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
#ifndef OCK_RDMA_WORKER_1234341456433_H
#define OCK_RDMA_WORKER_1234341456433_H
#ifdef RDMA_BUILD_ENABLED

#include <atomic>
#include <mutex>
#include <sys/resource.h>
#include <thread>
#include <utility>
#include <pthread.h>

#include "hcom.h"
#include "net_ctx_info_pool.h"
#include "net_mem_pool_fixed.h"
#include "rdma_verbs_wrapper_qp.h"

namespace ock {
namespace hcom {
using RDMANewReqHandler = std::function<int(RDMAOpContextInfo *)>;
using RDMAPostedHandler = std::function<int(RDMAOpContextInfo *)>;
using RDMAOneSideDoneHandler = std::function<int(RDMAOpContextInfo *)>;

// when there is no request from cq, call this
using RDMAIdleHandler = UBSHcomNetDriverIdleHandler;

using RDMASendSglInlineHeader = UBSHcomNetTransHeader;
using RDMASendReadWriteRequest = UBSHcomNetTransRequest;
using RDMASendSglRWRequest = UBSHcomNetTransSglRequest;

using RDMAOpContextInfoPool = OpContextInfoPool<RDMAOpContextInfo>;
using RDMASglContextInfoPool = OpContextInfoPool<RDMASglContextInfo>;

enum RDMAWorkerType : uint8_t {
    SENDER = 0,
    RECEIVER = 1,
    SENDER_RECEIVER = 2,
};

std::string &WorkerTypeToString(RDMAWorkerType tp);
std::string &PollingModeToString(RDMAPollingMode m);

using RDMAWorkerOptions = struct RDMAWorkerOptionsStruct {
    RDMAWorkerType workerType = RDMAWorkerType::RECEIVER;
    RDMAPollingMode workerMode = RDMAPollingMode::BUSY_POLLING;
    uint16_t completionQueueDepth = NN_NO2048;
    uint16_t maxPostSendCountPerQP = NN_NO64;
    uint16_t prePostReceiveSizePerQP = NN_NO64;
    uint16_t pollingBatchSize = NN_NO4;
    int16_t cpuId = -1;
    uint32_t qpSendQueueSize = NN_NO256;
    uint32_t qpReceiveQueueSize = NN_NO256;
    uint32_t qpMrSegSize = NN_NO1024;
    uint32_t qpMrSegCount = NN_NO64;
    uint32_t eventPollingTimeout = NN_NO500;
    bool dontStartWorkers = false;
    /* worker thread priority [-20,20], 20 is the lowest, -20 is the highest, 0 (default) means do not set priority */
    int threadPriority = 0;
    uint32_t qpBatchRePostSize = NN_NO1;

    std::string ToString() const
    {
        std::ostringstream oss;
        oss << "options type: " << WorkerTypeToString(workerType) << ", mode: " << PollingModeToString(workerMode) <<
            ", cq size: " << completionQueueDepth << ", max post send: " << maxPostSendCountPerQP <<
            ", pre-post receive size: " << prePostReceiveSizePerQP << ", poll batch size " << pollingBatchSize <<
            ", cpu id: " << cpuId << ", qp send queue: " << qpSendQueueSize << ", qp receive queue: " <<
            qpReceiveQueueSize << ", qp batch repost size: " << qpBatchRePostSize <<
            ", dontStartWorkers: " << dontStartWorkers;
        return oss.str();
    }

    void SetValue(const UBSHcomNetDriverOptions& opt)
    {
        workerType = RDMAWorkerType::SENDER_RECEIVER;
        completionQueueDepth = opt.completionQueueDepth;
        maxPostSendCountPerQP = opt.maxPostSendCountPerQP;
        prePostReceiveSizePerQP = opt.prePostReceiveSizePerQP;
        pollingBatchSize = opt.pollingBatchSize;
        if (opt.mode == NET_EVENT_POLLING) {
            workerMode = RDMAPollingMode::EVENT_POLLING;
        } else if (opt.mode == NET_BUSY_POLLING) {
            workerMode = RDMAPollingMode::BUSY_POLLING;
        }
        qpSendQueueSize = opt.qpSendQueueSize;
        qpReceiveQueueSize = opt.qpReceiveQueueSize;
        qpMrSegSize = opt.mrSendReceiveSegSize;
        qpMrSegCount = opt.prePostReceiveSizePerQP;
        eventPollingTimeout = opt.eventPollingTimeout;
        dontStartWorkers = opt.dontStartWorkers;
        threadPriority = opt.workerThreadPriority;
        qpBatchRePostSize = opt.qpBatchRePostSize;
    }
};

class RDMAWorker {
public:
    RDMAWorker(const std::string &name, RDMAContext *ctx, const RDMAWorkerOptions &options,
        const NetMemPoolFixedPtr &memPool, const NetMemPoolFixedPtr &sglMemPool);

    virtual ~RDMAWorker()
    {
        UnInitialize();
        OBJ_GC_DECREASE(RDMAWorker);
    }

    RResult Initialize();
    RResult UnInitialize();
    RResult ReInitializeCQ();

    RResult Start();
    RResult Stop();

    inline bool IsWorkStarted(uint32_t timeOutSecond = NN_NO8)
    {
        uint64_t count = static_cast<uint64_t>(timeOutSecond) * NN_NO1000000 / NN_NO100;
        while (--count > 0 && !mProgressThreadStarted.load()) {
            usleep(NN_NO100);
        }

        if (count > 0) {
            return true;
        } else {
            return false;
        }
    }

    inline const UBSHcomNetWorkerIndex &Index() const
    {
        return mIndex;
    }

    inline void SetIndex(const UBSHcomNetWorkerIndex &value)
    {
        mIndex = value;
    }

    RResult CreateQP(RDMAQp *&qp);

    RResult PostReceive(RDMAQp *qp, uintptr_t bufAddress, uint32_t bufSize, uint32_t localKey);
    RResult PostSend(RDMAQp *qp, const RDMASendReadWriteRequest &req, uint32_t immData = 0);
    RResult PostSendSglInline(
        RDMAQp *qp, const RDMASendSglInlineHeader &header, const RDMASendReadWriteRequest &req, uint32_t immData = 0);

    RResult PostSendSgl(RDMAQp *qp, const RDMASendSglRWRequest &req, const RDMASendReadWriteRequest &tlsReq,
        uint32_t immData = 0, bool isEncrypted = false);
    RResult PostRead(RDMAQp *qp, const RDMASendReadWriteRequest &req);
    RResult PostOneSideSgl(RDMAQp *qp, const RDMASendSglRWRequest &req, bool isRead = true);
    RResult PostWrite(RDMAQp *qp, const RDMASendReadWriteRequest &req,
        RDMAOpContextInfo::OpType type = RDMAOpContextInfo::WRITE);
    RResult CreateOneSideCtx(RDMASgeCtxInfo &sgeInfo, UBSHcomNetTransSgeIov *iov, uint32_t iovCount,
        uint32_t groupCount, const uint32_t *groupBegin, const uint32_t *groupLen,
        uint64_t (&ctxArr)[NET_SGE_MAX_IOV], bool isRead);
    RResult RePostReceive(RDMAOpContextInfo *ctx);
    RResult BatchRePostReceive(RDMAOpContextInfo *ctx);
    RResult PostSendRawNoCpy(RDMAQp *qp, const RDMASendReadWriteRequest &req, uint32_t immData);

    inline RDMAOpContextInfo *GetOpContextInfo()
    {
        return mOpCtxInfoPool.Get();
    }

    inline void ReturnOpContextInfo(RDMAOpContextInfo *&ctx)
    {
        if (NN_LIKELY(ctx != nullptr)) {
            if (NN_LIKELY(ctx->qp != nullptr)) {
                ctx->qp->DecreaseRef();
            }
            mOpCtxInfoPool.Return(ctx);
            ctx = nullptr;
        }
    }

    inline void RegisterNewRequestHandler(const RDMANewReqHandler &handler)
    {
        mNewRequestHandler = handler;
    }

    inline void ReturnSglContextInfo(RDMASglContextInfo *&ctx)
    {
        if (NN_LIKELY(ctx != nullptr)) {
            mSglCtxInfoPool.Return(ctx);
            ctx = nullptr;
        }
    }

    inline void RegisterPostedHandler(const RDMAPostedHandler &handler)
    {
        mSendPostedHandler = handler;
    }

    inline void RegisterIdleHandler(const RDMAIdleHandler &handler)
    {
        mIdleHandler = handler;
    }

    inline void RegisterOneSideDoneHandler(const RDMAOneSideDoneHandler &handler)
    {
        mOneSideDoneHandler = handler;
    }

    inline const std::string &Name() const
    {
        return mName;
    }

    inline uint8_t PortNum() const
    {
        return mRDMAContext->mPortNumber;
    }

    std::string DetailName() const
    {
        std::ostringstream oss;
        oss << "[name: " << mName << ", index: " << mIndex.ToString() << "]";
        return oss.str();
    }

    DEFINE_RDMA_REF_COUNT_FUNCTIONS
public:
    static RResult Create(const std::string &name, RDMAContext *ctx, const RDMAWorkerOptions &options,
        NetMemPoolFixedPtr memPool, NetMemPoolFixedPtr sglMemPool, RDMAWorker *&outWorker);

protected:
    void RunInThread();
    void DoWithBusyPolling();
    void DoWithCQEventPolling();

protected:
    std::string mName;
    UBSHcomNetWorkerIndex mIndex {};
    RDMAContext *mRDMAContext = nullptr;
    RDMACq *mRDMACq = nullptr;
    NetMemPoolFixedPtr mOpCtxMemPool = nullptr;
    NetMemPoolFixedPtr mSglCtxMemPool = nullptr;
    bool mInited = false;

    RDMAWorkerOptions mOptions {};

    // variable for thread
    std::thread mProgressThread;
    std::atomic_bool mProgressThreadStarted;
    std::atomic_bool mThreadStop;
    int16_t mProgressCpuId = -1;
    bool mNeedStop = false;

    RDMAOpContextInfoPool mOpCtxInfoPool;
    RDMASglContextInfoPool mSglCtxInfoPool;

    // request process related
    RDMANewReqHandler mNewRequestHandler = nullptr;

    // send request posted process related
    RDMAPostedHandler mSendPostedHandler = nullptr;

    // one side done  related
    RDMAOneSideDoneHandler mOneSideDoneHandler = nullptr;

    // no request will this
    RDMAIdleHandler mIdleHandler = nullptr;

    int mProgressBatchSize = NN_NO4;

    DEFINE_RDMA_REF_COUNT_VARIABLE;

    friend class RDMAQp;
};
}
}
#endif
#endif // OCK_RDMA_WORKER_1234341456433_H