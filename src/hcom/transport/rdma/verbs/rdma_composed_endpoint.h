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
#ifndef OCK_RDMA_COMPOSED_ENDPOINT_12342437333_H
#define OCK_RDMA_COMPOSED_ENDPOINT_12342437333_H
#ifdef RDMA_BUILD_ENABLED

#include "net_common.h"
#include "net_monotonic.h"
#include "rdma_common.h"
#include "rdma_verbs_wrapper_qp.h"
#include "rdma_worker.h"

namespace ock {
namespace hcom {
/* *********************************************************************************** */
class RDMAEndpoint {
public:
    RDMAEndpoint(const std::string &name, RDMAQp *qp) : mName(name), mQP(qp)
    {
        if (mQP != nullptr) {
            mQP->IncreaseRef();
        }
        OBJ_GC_INCREASE(RDMAEndpoint);
    }

    virtual ~RDMAEndpoint()
    {
        if (mQP != nullptr) {
            mQP->DecreaseRef();
            mQP = nullptr;
        }
        OBJ_GC_DECREASE(RDMAEndpoint);
    }

    virtual RResult Initialize() = 0;
    virtual void UnInitialize() = 0;

    /*
     * @brief, get the name of the ep
     */
    inline const std::string &Name() const
    {
        return mName;
    }

    /*
     * @brief Get qp exchange info
     *
     * @param info         [out] the exchange into
     *
     * @return 0 is successful
     */
    inline RResult GetExchangeInfo(RDMAQpExchangeInfo &info)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        return mQP->GetExchangeInfo(info);
    }

    /*
     * @brief Change the QP to RTR & RTS
     *
     * @param info         [in] the exchange from peer
     *
     * @return 0 is successful
     */
    inline RResult ChangeToReady(RDMAQpExchangeInfo &info)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_EP_NOT_INITIALIZED;
        }

        return mQP->ChangeToReady(info);
    }

    /*
     * @brief Get peer ip and port
     *
     * @return peer ip and port
     */
    inline const std::string &PeerIpAndPort()
    {
        if (NN_UNLIKELY(mQP != nullptr)) {
            return mQP->PeerIpAndPort();
        }
        return CONST_EMPTY_STRING;
    }

    /*
     * @brief Set peer ip and port
     *
     * @param value        [in] ip and port
     */
    inline void PeerIpAndPort(const std::string &value)
    {
        if (NN_UNLIKELY(mQP != nullptr)) {
            mQP->PeerIpAndPort(value);
        }
    }

    /*
     * @brief Get the qp object
     */
    inline RDMAQp *Qp() const
    {
        return mQP;
    }

    inline bool GetFreeBuffer(uintptr_t &item)
    {
        return mQP->GetFreeBuff(item);
    }

    inline bool GetFreeBufferN(uintptr_t *&items, uint32_t n)
    {
        return mQP->GetFreeBufferN(items, n);
    }

    inline bool ReturnBuffer(uintptr_t item)
    {
        return mQP->ReturnBuffer(item);
    }

    inline uint32_t GetLKey() const
    {
        return mQP->GetLKey();
    }

    DEFINE_RDMA_REF_COUNT_FUNCTIONS

protected:
    std::string mName;
    RDMAQp *mQP = nullptr;

    DEFINE_RDMA_REF_COUNT_VARIABLE;
};

/* *********************************************************************************** */
/*
 * @brief, both send cq and receive cq are in worker
 */
class RDMAAsyncEndPoint : public RDMAEndpoint {
public:
    static RResult Create(const std::string &name, RDMAWorker *worker, RDMAAsyncEndPoint *&ep);

public:
    RDMAAsyncEndPoint(const std::string &name, RDMAWorker *worker, RDMAQp *qp) : RDMAEndpoint(name, qp), mWorker(worker)
    {
        if (mWorker != nullptr) {
            mWorker->IncreaseRef();
        }

        OBJ_GC_INCREASE(RDMAAsyncEndPoint);
    }

    ~RDMAAsyncEndPoint() override
    {
        if (mWorker != nullptr) {
            mWorker->DecreaseRef();
            mWorker = nullptr;
        }

        OBJ_GC_DECREASE(RDMAAsyncEndPoint);
    }

    RResult Initialize() override
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_EP_NOT_INITIALIZED;
        }

        RResult result = RR_OK;
        // initialize QP
        if ((result = mQP->Initialize()) != RR_OK) {
            return result;
        }

        return result;
    }

    void UnInitialize() override {}

    RDMAAsyncEndPoint() = delete;
    RDMAAsyncEndPoint(const RDMAAsyncEndPoint &) = delete;
    RDMAAsyncEndPoint &operator = (const RDMAAsyncEndPoint &) = delete;
    RDMAAsyncEndPoint(RDMAAsyncEndPoint &&) = delete;
    RDMAAsyncEndPoint &operator = (RDMAAsyncEndPoint &&) = delete;

private:
    RDMAWorker *mWorker = nullptr;

    friend class NetDriverRDMAWithOob;
};

/* *********************************************************************************** */
/*
 * @brief, both send cq and receive cq in its
 */
class RDMASyncEndpoint : public RDMAEndpoint {
public:
    static RResult Create(const std::string &name, RDMAContext *ctx, RDMAPollingMode pollMode,
        uint32_t rdmaOpCtxPoolSize, const QpOptions &options, RDMASyncEndpoint *&ep);

public:
    RDMASyncEndpoint(const std::string &name, RDMAContext *ctx, RDMAPollingMode pollMode, RDMACq *cq, RDMAQp *qp,
        uint32_t rdmaOpCtxPoolSize)
        : RDMAEndpoint(name, qp), mContext(ctx), mPollingMode(pollMode), mCq(cq), mCtxPool(name, rdmaOpCtxPoolSize)
    {
        if (mContext != nullptr) {
            mContext->IncreaseRef();
        }

        if (mCq != nullptr) {
            mCq->IncreaseRef();
        }

        OBJ_GC_INCREASE(RDMASyncEndpoint);
    }

    ~RDMASyncEndpoint() override
    {
        if (mContext != nullptr) {
            mContext->DecreaseRef();
            mContext = nullptr;
        }

        if (mCq != nullptr) {
            mCq->DecreaseRef();
            mCq = nullptr;
        }

        OBJ_GC_DECREASE(RDMASyncEndpoint);
    }

    RResult Initialize() override
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_EP_NOT_INITIALIZED;
        }

        if (NN_UNLIKELY(mCq == nullptr)) {
            return RR_EP_NOT_INITIALIZED;
        }

        RResult result = RR_OK;
        // initialize cq
        if ((result = mCq->Initialize()) != RR_OK) {
            return result;
        }

        if ((result = mQP->Initialize()) != RR_OK) {
            return result;
        }

        if ((result = mCtxPool.Initialize()) != RR_OK) {
            return result;
        }

        return result;
    }

    void UnInitialize() override
    {
        if (mQP != nullptr) {
            mQP->UnInitialize();
        }

        if (mCq != nullptr) {
            mCq->UnInitialize();
        }
    }

    inline RResult PostReceive(uintptr_t bufAddress, uint32_t bufSize, uint32_t localKey)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            NN_LOG_ERROR("Failed to PostReceive with RDMASyncEndpoint " << mName << " as qp is null");
            return RR_PARAM_INVALID;
        }

        RDMAOpContextInfo *ctx = nullptr;
        if (NN_UNLIKELY(!mCtxPool.Dequeue(ctx))) {
            NN_LOG_ERROR("Failed to PostReceive with RDMASyncEndpoint " << mName << " as no ctx left");
            return RR_PARAM_INVALID;
        }

        ctx->qp = mQP;
        ctx->mrMemAddr = bufAddress;
        ctx->dataSize = bufSize;
        ctx->qpNum = mQP->QpNum();
        ctx->lKey = localKey;
        ctx->opType = RDMAOpContextInfo::RECEIVE;
        ctx->opResultType = RDMAOpContextInfo::SUCCESS;
        mQP->IncreaseRef();

        // attach context to qp firstly, because post could be finished very fast
        // if posted failed, need to remove
        mQP->AddOpCtxInfo(ctx);

        auto result = mQP->PostReceive(bufAddress, bufSize, localKey, reinterpret_cast<uint64_t>(ctx));
        if (NN_UNLIKELY(result != RR_OK)) {
            // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
            mQP->DecreaseRef();
            mQP->RemoveOpCtxInfo(ctx);
            mCtxPool.Enqueue(ctx);
        }

        // ctx could not be used if post successfully
        return result;
    }

    inline RResult RePostReceive(RDMAOpContextInfo *ctx)
    {
        if (NN_UNLIKELY(ctx == nullptr || ctx->qp == nullptr)) {
            NN_LOG_ERROR("Failed to RePostReceive with RDMASyncEndpoint " << mName << " as ctx or its qp is null");
            return RR_PARAM_INVALID;
        }

        auto result =
            ctx->qp->PostReceive(ctx->mrMemAddr, mQP->PostRegMrSize(), ctx->lKey, reinterpret_cast<uint64_t>(ctx));
        if (NN_UNLIKELY(result != RR_OK)) {
            // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
            ctx->qp->DecreaseRef();
            mQP->RemoveOpCtxInfo(ctx);
            mCtxPool.Enqueue(ctx);
        }

        // ctx could not be used if post successfully
        return result;
    }

    inline RResult PostSend(const RDMASendReadWriteRequest &req, uint32_t immData = 0)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            NN_LOG_ERROR("Failed to PostSend with RDMASyncEndpoint " << mName << " as qp is null");
            return RR_PARAM_INVALID;
        }

        static thread_local RDMAOpContextInfo ctx {};
        ctx.qp = mQP;
        ctx.mrMemAddr = req.lAddress;
        ctx.dataSize = req.size;
        ctx.qpNum = mQP->QpNum();
        // Prevent integer truncation, safely converts uint64_t to uint32_t
        if (NN_UNLIKELY(req.lKey > UINT32_MAX)) {
            NN_LOG_ERROR("Failed to PostSend with RDMASyncEndpoint as lKey is larger than uint32max, lkey" << req.lKey);
            return RR_PARAM_INVALID;
        }
        ctx.lKey = static_cast<uint32_t>(req.lKey);
        ctx.opType = RDMAOpContextInfo::SEND;
        ctx.opResultType = RDMAOpContextInfo::SUCCESS;
        ctx.upCtxSize = req.upCtxSize;
        if (req.upCtxSize > 0) {
            if (NN_UNLIKELY(memcpy_s(ctx.upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
                NN_LOG_ERROR("Failed to copy req to ctx");
                return RR_PARAM_INVALID;
            }
        }
        mQP->IncreaseRef();

        auto result = mQP->PostSend(req.lAddress, req.size, static_cast<uint32_t>(req.lKey),
            reinterpret_cast<uint64_t>(&ctx), immData);
        if (NN_UNLIKELY(result != RR_OK)) {
            // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
            mQP->DecreaseRef();
        }

        // ctx could not be used if post successfully
        return result;
    }

    RResult PostSendSgl(const RDMASendSglRWRequest &req, const RDMASendReadWriteRequest &tlsReq, uint32_t immData,
        bool isEncrypted = false)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            NN_LOG_ERROR("Failed to PostSendSgl with RDMAWorker " << mName << " as qp is null");
            return RR_PARAM_INVALID;
        }

        static thread_local RDMASglContextInfo sglCtx;
        sglCtx.qp = mQP;
        sglCtx.result = RR_OK;
        if (NN_UNLIKELY(memcpy_s(sglCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, req.iov,
            sizeof(UBSHcomNetTransSgeIov) * req.iovCount) != RR_OK)) {
            NN_LOG_ERROR("Failed to copy request to sglCtx");
            return RR_PARAM_INVALID;
        }
        sglCtx.iovCount = req.iovCount;
        sglCtx.upCtxSize = req.upCtxSize;
        if (req.upCtxSize > 0) {
            if (NN_UNLIKELY(memcpy_s(sglCtx.upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
                NN_LOG_ERROR("Failed to copy request to sglCtx");
                return RR_PARAM_INVALID;
            }
        }

        static thread_local RDMAOpContextInfo ctx;

        // if not encrypt reqTls lAddress\size\lKey is 0
        ctx.mrMemAddr = tlsReq.lAddress;
        ctx.dataSize = tlsReq.size;
        // Prevent integer truncation, safely converts uint64_t to uint32_t
        if (NN_UNLIKELY(tlsReq.lKey > UINT32_MAX)) {
            NN_LOG_ERROR("Failed to PostSendSgl with RDMASyncEp as lKey is larger than uint32max, lkey" << tlsReq.lKey);
            return RR_PARAM_INVALID;
        }
        ctx.lKey = static_cast<uint32_t>(tlsReq.lKey);
        ctx.qp = mQP;
        ctx.qpNum = mQP->QpNum();
        ctx.opType = RDMAOpContextInfo::SEND_RAW_SGL;
        ctx.opResultType = RDMAOpContextInfo::SUCCESS;
        ctx.upCtxSize = static_cast<uint16_t>(sizeof(RDMASgeCtxInfo));
        auto upCtx = reinterpret_cast<RDMASgeCtxInfo *>(&ctx.upCtx);
        upCtx->ctx = &sglCtx;
        mQP->IncreaseRef();

        RResult result = RR_OK;
        if (isEncrypted) {
            result =
                mQP->PostSend(tlsReq.lAddress, tlsReq.size, static_cast<uint32_t>(tlsReq.lKey),
                    reinterpret_cast<uint64_t>(&ctx), immData);
        } else {
            result = mQP->PostSendSgl(req.iov, req.iovCount, reinterpret_cast<uint64_t>(&ctx), immData);
        }

        if (NN_UNLIKELY(result != RR_OK)) {
            // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
            mQP->DecreaseRef();
        }

        return result;
    }

    inline RResult PostRead(const RDMASendReadWriteRequest &req)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            NN_LOG_ERROR("Failed to PostRead with RDMASyncEndpoint " << mName << " as qp is null");
            return RR_PARAM_INVALID;
        }

        static thread_local RDMAOpContextInfo ctx {};
        ctx.qp = mQP;
        ctx.mrMemAddr = req.lAddress;
        ctx.dataSize = req.size;
        ctx.qpNum = mQP->QpNum();
        ctx.lKey = req.lKey;
        ctx.opType = RDMAOpContextInfo::READ;
        ctx.opResultType = RDMAOpContextInfo::SUCCESS;
        ctx.upCtxSize = req.upCtxSize;
        if (req.upCtxSize > 0) {
            if (NN_UNLIKELY(memcpy_s(ctx.upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
                NN_LOG_ERROR("Failed to copy request to sglCtx");
                return RR_PARAM_INVALID;
            }
        }
        mQP->IncreaseRef();

        auto result =
            mQP->PostRead(req.lAddress, req.lKey, req.rAddress, req.rKey, req.size, reinterpret_cast<uint64_t>(&ctx));
        if (NN_UNLIKELY(result != RR_OK)) {
            // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
            mQP->DecreaseRef();
        }

        // ctx could not be used if post successfully
        return result;
    }

    inline RResult PostWrite(const RDMASendReadWriteRequest &req)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            NN_LOG_ERROR("Failed to PostWrite with RDMASyncEndpoint " << mName << " as qp is null");
            return RR_PARAM_INVALID;
        }

        static thread_local RDMAOpContextInfo ctx {};
        ctx.qp = mQP;
        ctx.mrMemAddr = req.lAddress;
        ctx.dataSize = req.size;
        ctx.qpNum = mQP->QpNum();
        ctx.lKey = req.lKey;
        ctx.opType = RDMAOpContextInfo::WRITE;
        ctx.opResultType = RDMAOpContextInfo::SUCCESS;
        ctx.upCtxSize = req.upCtxSize;
        if (req.upCtxSize > 0) {
            if (NN_UNLIKELY(memcpy_s(ctx.upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
                NN_LOG_ERROR("Failed to copy req to sglCtx");
                return RR_PARAM_INVALID;
            }
        }
        mQP->IncreaseRef();

        auto result =
            mQP->PostWrite(req.lAddress, req.lKey, req.rAddress, req.rKey, req.size, reinterpret_cast<uint64_t>(&ctx));
        if (NN_UNLIKELY(result != RR_OK)) {
            // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
            mQP->DecreaseRef();
        }

        // ctx could not be used if post successfully
        return result;
    }

    RResult PostOneSideSgl(const RDMASendSglRWRequest &req, bool isRead = true)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            NN_LOG_ERROR("Failed to oneSide operation with RDMAWorker " << mName << " as qp is null");
            return RR_PARAM_INVALID;
        }

        static thread_local RDMASglContextInfo sglCtx;
        sglCtx.result = RR_OK;
        sglCtx.qp = mQP;
        if (NN_UNLIKELY(memcpy_s(sglCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, req.iov,
            sizeof(UBSHcomNetTransSgeIov) * req.iovCount) != RR_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            return RR_PARAM_INVALID;
        }
        sglCtx.iovCount = req.iovCount;
        sglCtx.upCtxSize = req.upCtxSize;
        if (req.upCtxSize > 0) {
            if (NN_UNLIKELY(memcpy_s(sglCtx.upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
                NN_LOG_ERROR("Failed to copy req to sglCtx");
                return RR_PARAM_INVALID;
            }
        }
        sglCtx.refCount = 0;
        RDMASgeCtxInfo sgeInfo(&sglCtx);
        uint64_t ctxArr[NET_SGE_MAX_IOV];
        RResult result = CreateOneSideCtx(sgeInfo, req.iov, req.iovCount, ctxArr, isRead);
        if (result != RR_OK) {
            NN_LOG_ERROR("Failed to create one side ctx.");
            return result;
        }

        result = mQP->PostOneSideSgl(req.iov, req.iovCount, ctxArr, isRead);
        if (NN_UNLIKELY(result != RR_OK)) {
            for (int i = 0; i < req.iovCount; ++i) {
                mQP->DecreaseRef();
            }
        }

        return result;
    }

    RResult CreateOneSideCtx(RDMASgeCtxInfo &sgeInfo, UBSHcomNetTransSgeIov *iov, uint32_t iovCount,
        uint64_t (&ctxArr)[NET_SGE_MAX_IOV], bool isRead)
    {
        if (iov == nullptr || iovCount == NN_NO0 || iovCount > NET_SGE_MAX_IOV || ctxArr == nullptr) {
            NN_LOG_ERROR("Failed to create oneSide operation ctx because param invalid");
            return RR_PARAM_INVALID;
        }
        static thread_local RDMAOpContextInfo ctx[NET_SGE_MAX_IOV] = {};
        for (uint32_t i = 0; i < iovCount; ++i) {
            ctx[i].qp = mQP;
            ctx[i].mrMemAddr = iov[i].lAddress;
            ctx[i].dataSize = iov[i].size;
            ctx[i].qpNum = mQP->QpNum();
            ctx[i].lKey = iov[i].lKey;
            ctx[i].opType = isRead ? RDMAOpContextInfo::SGL_READ : RDMAOpContextInfo::SGL_WRITE;
            ctx[i].opResultType = RDMAOpContextInfo::SUCCESS;
            ctx[i].upCtxSize = static_cast<uint16_t>(sizeof(RDMASgeCtxInfo));
            auto upCtx = static_cast<RDMASgeCtxInfo *>((void *)&(ctx[i].upCtx));
            upCtx->ctx = sgeInfo.ctx;
            upCtx->idx = i;
            mQP->IncreaseRef();

            ctxArr[i] = reinterpret_cast<uint64_t>(&ctx[i]);
        }
        return RR_OK;
    }

    inline RResult PollingCompletion(RDMAOpContextInfo *&ctx, int32_t timeout, uint32_t &immData)
    {
        if (NN_UNLIKELY(mCq == nullptr)) {
            NN_LOG_ERROR("Failed to polling completion with RDMASyncEndpoint " << mName << " as cq is null");
            return RR_EP_NOT_INITIALIZED;
        }

        int32_t timeoutInMs = TimeSecToMs(timeout);
        ibv_wc wc {};
        int pollCount = 1;
        RResult result = RR_OK;
        if (mPollingMode == BUSY_POLLING) {
            auto start = NetMonotonic::TimeMs();
            int64_t pollTime = 0;
            do {
                pollCount = 1;
                result = mCq->ProgressV(&wc, pollCount);

                pollTime = (int64_t)(NetMonotonic::TimeMs() - start);
                if (pollCount == 0 && timeoutInMs >= 0 && pollTime > timeoutInMs) {
                    return RR_CQ_EVENT_GET_TIMOUT;
                }
            } while (result == RR_OK && pollCount == 0);
        } else if (mPollingMode == EVENT_POLLING) {
            result = mCq->EventProgressV(&wc, pollCount, timeoutInMs);
        }

        if (NN_UNLIKELY(result != RR_OK)) {
            return result;
        }

        auto *contextInfo = reinterpret_cast<RDMAOpContextInfo *>(wc.wr_id);
        if (contextInfo == nullptr) {
            NN_LOG_ERROR("Failed to polling completion with RDMASyncEndpoint " << mName << " as contextInfo is null");
            return RR_CQ_WC_WRONG;
        }
        contextInfo->dataSize = wc.byte_len;
        contextInfo->opResultType = RDMAOpContextInfo::OpResult(wc);
        ctx = contextInfo;
        if (NN_UNLIKELY(wc.status != IBV_WC_SUCCESS)) {
            NN_LOG_ERROR("Poll cq failed in RDMASyncEndpoint " << mName << ", wcStatus " << wc.status << ", opType " <<
                contextInfo->opType);
            return RR_CQ_WC_WRONG;
        }
        immData = wc.imm_data;

        return RR_OK;
    }

private:
    RDMAContext *mContext = nullptr;
    RDMAPollingMode mPollingMode = RDMAPollingMode::EVENT_POLLING;
    RDMACq *mCq = nullptr;
    NetObjPool<RDMAOpContextInfo> mCtxPool;
};
}
}

#endif
#endif // OCK_RDMA_COMPOSED_ENDPOINT_12342437333_H