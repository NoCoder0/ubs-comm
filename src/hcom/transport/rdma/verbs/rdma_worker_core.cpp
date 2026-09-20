/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 
 * ubs-hcom is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifdef RDMA_BUILD_ENABLED
#include <unistd.h>
#include <utility>

#include "hcom_utils.h"
#include "hcom_rdma_trace.h"
#include "net_common.h"
#include "rdma_worker.h"
#include "net_rdma_async_endpoint.h"

namespace ock {
namespace hcom {
std::string &WorkerTypeToString(RDMAWorkerType tp)
{
    static std::string workerTypeString[3] = {"sender", "receiver", "sender&receiver"};
    static std::string unknownWorkerType = "unknown worker type";
    if (tp != SENDER && tp != RECEIVER && tp != SENDER_RECEIVER) {
        return unknownWorkerType;
    }
    return workerTypeString[tp];
}

std::string &PollingModeToString(RDMAPollingMode m)
{
    static std::string workerModeString[2] = {"busy_polling", "cq_event_polling"};
    static std::string unknownWorkerMode = "unknown worker mode";
    if (m != BUSY_POLLING && m != EVENT_POLLING) {
        return unknownWorkerMode;
    }
    return workerModeString[m];
}

RDMAWorker::RDMAWorker(const std::string &name, RDMAContext *ctx, const RDMAWorkerOptions &options,
    const NetMemPoolFixedPtr &memPool, const NetMemPoolFixedPtr &sglMemPool)
    : mName(name),
      mRDMAContext(ctx),
      mOpCtxMemPool(memPool),
      mSglCtxMemPool(sglMemPool),
      mOptions(options),
      mProgressThreadStarted(false)
{
    if (mRDMAContext != nullptr) {
        mRDMAContext->IncreaseRef();
    }
    mThreadStop.store(false);
    mProgressCpuId = options.cpuId;
    mProgressBatchSize = options.pollingBatchSize;
    OBJ_GC_INCREASE(RDMAWorker);
}

RResult RDMAWorker::Initialize()
{
    if (mInited) {
        return RR_OK;
    }

    if (mRDMAContext == nullptr || mRDMAContext->mContext == nullptr) {
        NN_LOG_ERROR("RDMA Context is null, probably not initialized");
        return RR_PARAM_INVALID;
    }

    // create and init CQ
    auto tmpCQ = new (std::nothrow)
        RDMACq(DetailName(), mRDMAContext, mOptions.workerMode == EVENT_POLLING, reinterpret_cast<uintptr_t>(this));
    if (tmpCQ == nullptr) {
        NN_LOG_ERROR("Verbs Failed to new RDMACq in RDMAWorker " << DetailName() << ", probably out of memory");
        return RR_NEW_OBJECT_FAILED;
    }

    tmpCQ->SetCQCount(mOptions.completionQueueDepth);

    RResult result = RR_OK;
    if ((result = tmpCQ->Initialize()) != RR_OK) {
        NN_LOG_ERROR("Verbs Failed to initialize RDMACq in RDMAWorker " << DetailName() << ", result " << result);
        delete tmpCQ;
        return result;
    }

    if ((result = mOpCtxInfoPool.Initialize(mOpCtxMemPool)) != RR_OK) {
        NN_LOG_ERROR("Verbs Failed to initialize operation context info pool in RDMAWorker " << DetailName());
        delete tmpCQ;
        return result;
    }

    if ((result = mSglCtxInfoPool.Initialize(mSglCtxMemPool)) != RR_OK) {
        NN_LOG_ERROR("Verbs Failed to initialize sgl context info pool in RDMAWorker " << DetailName());
        delete tmpCQ;
        return result;
    }

    mRDMACq = tmpCQ;
    mRDMACq->IncreaseRef();
    mInited = true;

    return RR_OK;
}

RResult RDMAWorker::UnInitialize()
{
    if (!mInited) {
        return RR_OK;
    }

    if (mRDMACq != nullptr) {
        mRDMACq->DecreaseRef();
        mRDMACq = nullptr;
    }

    if (mRDMAContext != nullptr) {
        mRDMAContext->DecreaseRef();
        mRDMAContext = nullptr;
    }

    if (mOpCtxMemPool != nullptr) {
        mOpCtxMemPool.Set(nullptr);
    }

    mOpCtxInfoPool.UnInitialize();

    mInited = false;
    return RR_OK;
}

RResult RDMAWorker::ReInitializeCQ()
{
    if (!mInited) {
        return RR_OK;
    }

    if (mRDMACq != nullptr) {
        mRDMACq->DecreaseRef();
        mRDMACq = nullptr;
    }

    // create and init CQ
    auto tmpCQ = new (std::nothrow)
        RDMACq(DetailName(), mRDMAContext, mOptions.workerMode == EVENT_POLLING, reinterpret_cast<uintptr_t>(this));
    if (tmpCQ == nullptr) {
        NN_LOG_ERROR("Failed to new RDMACq in RDMAWorker " << DetailName() << ", probably out of memory");
        return RR_NEW_OBJECT_FAILED;
    }

    tmpCQ->SetCQCount(mOptions.completionQueueDepth);

    RResult result = RR_OK;
    if ((result = tmpCQ->Initialize()) != RR_OK) {
        delete tmpCQ;
        tmpCQ = nullptr;
        NN_LOG_ERROR("Failed to initialize RDMACq in RDMAWorker " << DetailName() << ", result " << result);
        return result;
    }

    mRDMACq = tmpCQ;
    mRDMACq->IncreaseRef();

    return RR_OK;
}

RResult RDMAWorker::Start()
{
    if (!mInited) {
        NN_LOG_ERROR("Failed to start RDMAWorker " << DetailName() << " as not initialized");
        return RR_WORKER_NOT_INITIALIZED;
    }

    if (mThreadStop.load()) {
        NN_LOG_ERROR("Failed to start RDMAWorker " << DetailName() << "worker thread not stop");
        return RR_WORKER_START_ERROR;
    }

    if (mOptions.dontStartWorkers) {
        NN_LOG_INFO("Do not start workers " << DetailName());
        return RR_OK;
    }

    if ((mOptions.workerType == RECEIVER || mOptions.workerType == SENDER_RECEIVER) && mNewRequestHandler == nullptr) {
        NN_LOG_ERROR("New request handler is not registered yet in RDMAWorker " << DetailName());
        return RR_WORKER_REQUEST_HANDLER_NOT_SET;
    }

    if ((mOptions.workerType == SENDER || mOptions.workerType == SENDER_RECEIVER) && mSendPostedHandler == nullptr) {
        NN_LOG_ERROR("Send request posted handler is not registered yet in RDMAWorker " << DetailName());
        return RR_WORKER_SEND_POSTED_HANDLER_NOT_SET;
    }

    if (mOneSideDoneHandler == nullptr) {
        NN_LOG_WARN("One side done handler is not registered yet in RDMAWorker " << DetailName());
    }

    mNeedStop = false;
    std::thread tmpThread(&RDMAWorker::RunInThread, this);
    mProgressThread = std::move(tmpThread);
    std::string threadName = "RDMAWkr" + mIndex.ToString();
    if (pthread_setname_np(mProgressThread.native_handle(), threadName.c_str()) != 0) {
        NN_LOG_WARN("Unable to set name of RDMAWorker progress thread");
    }

    if (mProgressCpuId != -1) {
        cpu_set_t cpuSet;
        CPU_ZERO(&cpuSet);
        CPU_SET(mProgressCpuId, &cpuSet);
        if (pthread_setaffinity_np(mProgressThread.native_handle(), sizeof(cpuSet), &cpuSet) != 0) {
            NN_LOG_WARN("Unable to bind RDMAWorker" << mIndex.ToString() << " << to cpu " << mProgressCpuId);
        }
    }

    while (!mProgressThreadStarted.load()) {
        usleep(NN_NO10);
    }
    mThreadStop.store(true);
    return RR_OK;
}

RResult RDMAWorker::Stop()
{
    if (!mThreadStop.load()) {
        return RR_OK;
    }
    mNeedStop = true;
    if (mProgressThread.native_handle()) {
        mProgressThread.join();
    }
    mThreadStop.store(false);
    return RR_OK;
}

#define BUSY_POLLING()                                                               \
    if (NN_UNLIKELY(mRDMACq->ProgressV(wc, pollCount) != RR_OK)) {                   \
        /* timeout return 0, count = 0, will invoke PROCESS_POLLING_RESULT() idle */ \
        /* do later */                                                               \
        continue;                                                                    \
    }

#define CQ_EVENT_POLLING()                                                           \
    if (NN_UNLIKELY(mRDMACq->EventProgressV(wc, pollCount, pollTimeOut) != RR_OK)) { \
        /* timeout need invoke idle */                                               \
        if (mIdleHandler != nullptr) {                                               \
            mIdleHandler(mIndex);                                                    \
        }                                                                            \
        /* do later */                                                               \
        continue;                                                                    \
    }

#define PROCESS_POLLING_RESULT(pollCount, contextInfo, lastBrokenQp)                                                   \
    do {                                                                                                               \
        for (int i = 0; i < (pollCount); i++) {                                                                        \
            UBSHcomRdmaTraceDispatchScope traceDispatch(wc[i].wr_id, wc[i].qp_num, wc[i].opcode, wc[i].status);          \
            (contextInfo) = reinterpret_cast<RDMAOpContextInfo *>(wc[i].wr_id);                                        \
            if ((contextInfo)->qpNum != wc[i].qp_num ||                                                                \
                (contextInfo)->opResultType == RDMAOpContextInfo::INVALID_MAGIC) {                                     \
                continue;                                                                                              \
            }                                                                                                          \
            (contextInfo)->opResultType = RDMAOpContextInfo::OpResult(wc[i]);                                          \
            if (NN_LIKELY(wc[i].status == IBV_WC_SUCCESS)) {                                                           \
                /* detach the context */                                                                               \
                (contextInfo)->qp->RemoveOpCtxInfo(contextInfo);                                                       \
            } else {                                                                                                   \
                if ((contextInfo)->opType == RDMAOpContextInfo::HB_WRITE) {                                            \
                    (lastBrokenQp) = (contextInfo)->qp;                                                                \
                    NN_LOG_INFO("HB poll cq receive wcStatus " << wc[i].status << ", maybe remote ep " <<              \
                        (contextInfo)->qp->UpId() << " closed");                                                       \
                } else if (((contextInfo)->qp->isStarted) && ((lastBrokenQp) != (contextInfo)->qp)) {                  \
                    (lastBrokenQp) = (contextInfo)->qp;                                                                \
                    NN_LOG_ERROR("Poll cq failed in RDMAWorker " << DetailName() << ", wcStatus " << wc[i].status <<   \
                        ", opType " << (contextInfo)->opType << ", ep id " << (contextInfo)->qp->UpId());              \
                } else if (((contextInfo)->qp->isStarted) && (lastErrorWcStatus != wc[i].status)) {                    \
                    lastErrorWcStatus = wc[i].status;                                                                  \
                    NN_LOG_ERROR("Poll cq failed in RDMAWorker " << DetailName() << ", wc Status " << wc[i].status <<  \
                        ", opType " << (contextInfo)->opType << ", ep id " << (contextInfo)->qp->UpId());              \
                }                                                                                                      \
            }                                                                                                          \
                                                                                                                       \
            auto asyncEp = reinterpret_cast<NetAsyncEndpoint *>(contextInfo->qp->UpContext());                         \
            if (asyncEp == nullptr) {                                                                                  \
                NN_LOG_ERROR("Poll cq asyncEp is null in RDMAWorker " << DetailName());                                \
                continue;                                                                                              \
            }                                                                                                          \
            if (wc[i].status == IBV_WC_SUCCESS) {                                                                      \
                asyncEp->UpdateTargetHbTime();                                                                         \
            }                                                                                                          \
            switch ((contextInfo)->opType) {                                                                           \
                case (RDMAOpContextInfo::OpType::SEND):                                                                \
                case (RDMAOpContextInfo::OpType::SEND_RAW):                                                            \
                case (RDMAOpContextInfo::OpType::SEND_RAW_NO_CP):                                                      \
                case (RDMAOpContextInfo::OpType::SEND_RAW_SGL):                                                        \
                case (RDMAOpContextInfo::OpType::SEND_SGL_INLINE):                                                     \
                    mSendPostedHandler(contextInfo);                                                                   \
                    break;                                                                                             \
                case (RDMAOpContextInfo::OpType::RECEIVE):                                                             \
                    /* NOTE, up context is store imm data */                                                           \
                    (contextInfo)->dataSize = wc[i].byte_len;                                                          \
                    *((int32_t *)(void *)&((contextInfo)->upCtx)) = wc[i].imm_data;                                    \
                    mNewRequestHandler(contextInfo);                                                                   \
                    break;                                                                                             \
                case (RDMAOpContextInfo::OpType::WRITE):                                                               \
                case (RDMAOpContextInfo::OpType::SGL_WRITE):                                                           \
                case (RDMAOpContextInfo::OpType::HB_WRITE):                                                            \
                case (RDMAOpContextInfo::OpType::READ):                                                                \
                case (RDMAOpContextInfo::OpType::SGL_READ):                                                            \
                    mOneSideDoneHandler(contextInfo);                                                                  \
                    break;                                                                                             \
                default:                                                                                               \
                    NN_LOG_ERROR("Poll cq invalid OpType " << (contextInfo)->opType);                                  \
                    break;                                                                                             \
            }                                                                                                          \
        }                                                                                                              \
                                                                                                                      \
        /* if there is no coming request, call up idle function */                                                     \
        if (mIdleHandler != nullptr && (pollCount) == 0) {                                                             \
            mIdleHandler(mIndex);                                                                                      \
        }                                                                                                              \
    } while (0)


void RDMAWorker::DoWithBusyPolling()
{
    // allocate wc vector
    auto *wc = static_cast<struct ibv_wc *>(calloc(mProgressBatchSize, sizeof(struct ibv_wc)));
    if (wc == nullptr) {
        NN_LOG_ERROR("Failed to allocate wc in RDMAWorker " << DetailName() << ", thread exiting");
        return;
    }

    int pollCount = 0;
    RDMAOpContextInfo *contextInfo = nullptr;

    RDMAQp *lastBrokenQp = nullptr;
    enum ibv_wc_status lastErrorWcStatus = IBV_WC_SUCCESS;

    while (!mNeedStop) {
        try {
            pollCount = mProgressBatchSize;
            BUSY_POLLING()
            /* 只在取到完成项时才打点：忙轮询每空转一圈都记一次会让该点涨到千万条（实测 3000 万条 /
               1.13s 累计 CPU），两条 clock_gettime 的累加会明显拖慢 worker 线程、污染测量。 */
            const bool hasCompletion = (pollCount > 0);
            uint64_t pollingBegin = 0;
            if (hasCompletion) {
                TRACE_V2_DELAY_BEGIN(RDMA_WORKER_EVENT_POLLING, &pollingBegin);
            }
            PROCESS_POLLING_RESULT(pollCount, contextInfo, lastBrokenQp);
            if (hasCompletion) {
                TRACE_V2_DELAY_END(RDMA_WORKER_EVENT_POLLING, pollingBegin, 0);
            }
        } catch (std::runtime_error &ex) {
            NN_LOG_WARN("Verbs Got runtime incorrect signal in RDMAWorker::RunInThread '" << ex.what() <<
                "', ignore and continue");
        } catch (...) {
            NN_LOG_WARN("Verbs Got unknown signal in RDMAWorker::RunInThread, ignore and continue");
        }
    }

    free(wc);
    wc = nullptr;
}

void RDMAWorker::DoWithCQEventPolling()
{
    // allocate wc vector
    auto *wc = static_cast<struct ibv_wc *>(calloc(mProgressBatchSize, sizeof(struct ibv_wc)));
    if (wc == nullptr) {
        NN_LOG_ERROR("Failed to allocate wc in RDMAWorker " << DetailName() << ", thread exiting");
        return;
    }

    int pollCount = 0;
    uint32_t pollTimeOut = 0;
    RDMAOpContextInfo *contextInfo = nullptr;

    RDMAQp *lastBrokenQp = nullptr;
    enum ibv_wc_status lastErrorWcStatus = IBV_WC_SUCCESS;

    while (!mNeedStop) {
        try {
            pollTimeOut = mOptions.eventPollingTimeout;
            pollCount = mProgressBatchSize;
            CQ_EVENT_POLLING()
            /* 同 DoWithBusyPolling：只在取到完成项时打点，避免空轮询把条数刷到千万级 */
            const bool hasCompletion = (pollCount > 0);
            uint64_t pollingBegin = 0;
            if (hasCompletion) {
                TRACE_V2_DELAY_BEGIN(RDMA_WORKER_EVENT_POLLING, &pollingBegin);
            }
            PROCESS_POLLING_RESULT(pollCount, contextInfo, lastBrokenQp);
            if (hasCompletion) {
                TRACE_V2_DELAY_END(RDMA_WORKER_EVENT_POLLING, pollingBegin, 0);
            }
        } catch (std::runtime_error &ex) {
            NN_LOG_WARN("Got runtime incorrect signal in RDMAWorker::RunInThread '" << ex.what() <<
                "', ignore and continue");
        } catch (...) {
            NN_LOG_WARN("Got unknown signal in RDMAWorker::RunInThread, ignore and continue");
        }
    }

    free(wc);
    wc = nullptr;
}

void RDMAWorker::RunInThread()
{
    if (mOptions.threadPriority != 0) {
        if (NN_UNLIKELY(setpriority(PRIO_PROCESS, 0, mOptions.threadPriority) != 0)) {
            char errBuf[NET_STR_ERROR_BUF_SIZE] = {0};
            NN_LOG_WARN("Unable to set worker thread priority in rdma worker " << mName << ", errno:" <<
                NetFunc::NN_GetStrError(errno, errBuf, NET_STR_ERROR_BUF_SIZE));
        }
    }

    mProgressThreadStarted.store(true);
    NN_LOG_INFO("RDMAWorker " << DetailName() << ", cpuId: " << mProgressCpuId << ", cq count: " <<
        ((mRDMACq != nullptr) ? mRDMACq->GetCQCount() : 0) << ", polling batch size: " << mProgressBatchSize <<
        ", more " << mOptions.ToString() << "] working thread started");

    if (mOptions.workerMode == BUSY_POLLING) {
        DoWithBusyPolling();
    } else if (mOptions.workerMode == EVENT_POLLING) {
        DoWithCQEventPolling();
    } else {
        NN_LOG_ERROR("Un-reachable");
    }

    NN_LOG_INFO("RDMAWorker " << DetailName() << " working thread exiting");
}

RResult RDMAWorker::Create(const std::string &name, RDMAContext *ctx, const RDMAWorkerOptions &options,
    NetMemPoolFixedPtr memPool, NetMemPoolFixedPtr sglMemPool, RDMAWorker *&outWorker)
{
    if (ctx == nullptr || name.empty()) {
        NN_LOG_ERROR("Create worker param invalid");
        return RR_PARAM_INVALID;
    }

    auto tmp = new (std::nothrow) RDMAWorker(name, ctx, options, std::move(memPool), std::move(sglMemPool));
    if (tmp == nullptr) {
        NN_LOG_ERROR("Failed to create RDMAWorker, probably out of memory");
        return RR_NEW_OBJECT_FAILED;
    }

    outWorker = tmp;
    return RR_OK;
}

RResult RDMAWorker::CreateQP(RDMAQp *&qp)
{
    if (NN_UNLIKELY(!mInited)) {
        NN_LOG_ERROR("Failed to create qp with RDMAWorker " << DetailName() << " as not initialized");
        return RR_WORKER_NOT_INITIALIZED;
    }

    QpOptions qpOptions(mOptions.qpSendQueueSize, mOptions.qpReceiveQueueSize, mOptions.qpMrSegSize,
        mOptions.qpMrSegCount);
    qp = new (std::nothrow) RDMAQp(DetailName(), RDMAQp::NewId(), mRDMAContext, mRDMACq, qpOptions);
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Failed to create qp with RDMAWorker " << DetailName() << ", probably out of memory");
        return RR_NEW_OBJECT_FAILED;
    }

    qp->UpContext1(reinterpret_cast<uintptr_t>(this));
    return RR_OK;
}
}
}
#endif
