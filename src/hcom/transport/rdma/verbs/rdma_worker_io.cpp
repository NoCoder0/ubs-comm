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
#include <cstdlib>

#include "hcom_utils.h"
#include "net_common.h"
#include "rdma_worker.h"
#include "net_rdma_async_endpoint.h"

namespace ock {
namespace hcom {

RResult RDMAWorker::PostReceive(RDMAQp *qp, uintptr_t bufAddress, uint32_t bufSize, uint32_t localKey)
{
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Failed to PostReceive with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto ctx = mOpCtxInfoPool.Get();
    if (NN_UNLIKELY(ctx == nullptr)) {
        NN_LOG_ERROR("Failed to PostReceive with RDMAWorker " << DetailName() << " as no ctx left");
        return RR_QP_CTX_FULL;
    }

    /* set to all 0 */
    bzero(ctx, sizeof(RDMAOpContextInfo));
    ctx->qp = qp;
    ctx->mrMemAddr = bufAddress;
    ctx->dataSize = bufSize;
    ctx->qpNum = qp->QpNum();
    ctx->lKey = localKey;
    ctx->opType = RDMAOpContextInfo::RECEIVE;
    ctx->opResultType = RDMAOpContextInfo::SUCCESS;
    qp->IncreaseRef();

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    qp->AddOpCtxInfo(ctx);

    auto res = qp->PostReceive(bufAddress, bufSize, localKey, reinterpret_cast<uint64_t>(ctx));
    if (NN_UNLIKELY(res != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        qp->DecreaseRef();
        qp->RemoveOpCtxInfo(ctx);
        mOpCtxInfoPool.Return(ctx);
    }

    // ctx could not be used if post successfully
    return res;
}

RResult RDMAWorker::RePostReceive(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(ctx == nullptr || ctx->qp == nullptr)) {
        NN_LOG_ERROR("Failed to RePostReceive with RDMAWorker " << DetailName() << " as ctx or its qp is null");
        return RR_PARAM_INVALID;
    }

    if (mOptions.qpBatchRePostSize > NN_NO1) {
        return BatchRePostReceive(ctx);
    }

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    ctx->qp->AddOpCtxInfo(ctx);

    auto result =
        ctx->qp->PostReceive(ctx->mrMemAddr, mOptions.qpMrSegSize, ctx->lKey, reinterpret_cast<uint64_t>(ctx));
    if (NN_UNLIKELY(result != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        ctx->qp->DecreaseRef();
        ctx->qp->RemoveOpCtxInfo(ctx);
        mOpCtxInfoPool.Return(ctx);
    }

    // ctx could not be used if post successfully
    return result;
}

RResult RDMAWorker::BatchRePostReceive(RDMAOpContextInfo *ctx)
{
    uint16_t num = ctx->qp->mDelayNum.load(std::memory_order_relaxed);
    uint16_t batchSize = mOptions.qpBatchRePostSize;

    if (num >= batchSize) {
        NN_LOG_WARN("Batch repostReceive failed delayNum " << num << " >= batchSize " << batchSize);
        return NN_ERROR;
    }

    ctx->qp->mDelayList[num] = ctx;
    uint16_t newNum = ctx->qp->mDelayNum.fetch_add(1, std::memory_order_release) + 1;
    if (newNum != batchSize) {
        return NN_OK;
    }
    // batch post receive
    auto result = ctx->qp->BatchPostReceive(ctx, batchSize, mOptions.qpMrSegSize);
    if (NN_UNLIKELY(result != RR_OK)) {
        // batch free context
        for (int i = 0; i < batchSize; ++i) {
            auto* delayCtx = ctx->qp->mDelayList[i];
            if (!delayCtx) {
                continue;
            }
            delayCtx->qp->DecreaseRef();
            delayCtx->qp->RemoveOpCtxInfo(delayCtx);
            ReturnOpContextInfo(delayCtx);
            ctx->qp->mDelayList[i] = nullptr;
        }
        ctx->qp->mDelayNum.store(0, std::memory_order_relaxed);
        return NN_ERROR;
    }
    ctx->qp->mDelayNum.store(0, std::memory_order_relaxed);
    return NN_OK;
}

RResult RDMAWorker::PostSend(RDMAQp *qp, const RDMASendReadWriteRequest &req, uint32_t immData)
{
    // Prevent integer truncation, safely converts uint64_t to uint32_t
    if (NN_UNLIKELY(req.lKey > UINT32_MAX)) {
        NN_LOG_ERROR("Failed to PostSend with RDMAWorker as lKey is larger than uint32max, lKey" << req.lKey);
        return RR_PARAM_INVALID;
    }

    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Verbs Failed to PostSend with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto ctx = mOpCtxInfoPool.Get();
    if (NN_UNLIKELY(ctx == nullptr)) {
        NN_LOG_ERROR("Verbs Failed to PostSend with RDMAWorker " << DetailName() << " as no reqInfo left");
        return RR_QP_CTX_FULL;
    }

    if (NN_UNLIKELY(!qp->GetPostSendWr())) {
        NN_LOG_ERROR("Verbs Failed to PostSend with RDMAWorker " << DetailName() << " as no post send wr left");
        mOpCtxInfoPool.Return(ctx);
        return RR_QP_POST_SEND_WR_FULL;
    }
    ctx->qp = qp;
    ctx->mrMemAddr = req.lAddress;
    ctx->dataSize = req.size;
    ctx->qpNum = qp->QpNum();
    ctx->lKey = static_cast<uint32_t>(req.lKey);
    ctx->opType = immData == 0 ? RDMAOpContextInfo::SEND : RDMAOpContextInfo::SEND_RAW;
    ctx->opResultType = RDMAOpContextInfo::SUCCESS;
    ctx->upCtxSize = req.upCtxSize;
    if (req.upCtxSize > 0 && NN_UNLIKELY(memcpy_s(ctx->upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
        NN_LOG_ERROR("Failed to copy req to ctx");
        qp->ReturnPostSendWr();
        mOpCtxInfoPool.Return(ctx);
        return RR_PARAM_INVALID;
    }
    qp->IncreaseRef();

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    qp->AddOpCtxInfo(ctx);

    auto result = qp->PostSend(req.lAddress, req.size, static_cast<uint32_t>(req.lKey),
        reinterpret_cast<uint64_t>(ctx), immData);
    if (NN_UNLIKELY(result != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        qp->ReturnPostSendWr();
        qp->DecreaseRef();
        qp->RemoveOpCtxInfo(ctx);
        mOpCtxInfoPool.Return(ctx);
    }

    // ctx could not be used if post successfully
    return result;
}

RResult RDMAWorker::PostSendRawNoCpy(RDMAQp *qp, const RDMASendReadWriteRequest &req, uint32_t immData)
{
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Verbs Failed to PostSend with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto ctx = mOpCtxInfoPool.Get();
    if (NN_UNLIKELY(ctx == nullptr)) {
        NN_LOG_ERROR("Verbs Failed to PostSend with RDMAWorker " << DetailName() << " as no reqInfo left");
        return RR_QP_CTX_FULL;
    }

    if (NN_UNLIKELY(!qp->GetPostSendWr())) {
        NN_LOG_ERROR("Verbs Failed to PostSend with RDMAWorker " << DetailName() << " as no post send wr left");
        mOpCtxInfoPool.Return(ctx);
        return RR_QP_POST_SEND_WR_FULL;
    }
    ctx->qp = qp;
    ctx->mrMemAddr = req.lAddress;
    ctx->dataSize = req.size;
    ctx->qpNum = qp->QpNum();
    ctx->lKey = static_cast<uint32_t>(req.lKey);
    ctx->opType = RDMAOpContextInfo::SEND_RAW_NO_CP;
    ctx->opResultType = RDMAOpContextInfo::SUCCESS;
    ctx->upCtxSize = req.upCtxSize;
    if (req.upCtxSize > 0 && NN_UNLIKELY(memcpy_s(ctx->upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
        NN_LOG_ERROR("Failed to copy req to ctx");
        qp->ReturnPostSendWr();
        mOpCtxInfoPool.Return(ctx);
        return RR_PARAM_INVALID;
    }
    qp->IncreaseRef();

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    qp->AddOpCtxInfo(ctx);

    auto result = qp->PostSend(req.lAddress, req.size, static_cast<uint32_t>(req.lKey),
                               reinterpret_cast<uint64_t>(ctx), immData);
    if (NN_UNLIKELY(result != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        qp->ReturnPostSendWr();
        qp->DecreaseRef();
        qp->RemoveOpCtxInfo(ctx);
        mOpCtxInfoPool.Return(ctx);
    }

    // ctx could not be used if post successfully
    return result;
}

RResult RDMAWorker::PostSendSglInline(
    RDMAQp *qp, const RDMASendSglInlineHeader &header, const RDMASendReadWriteRequest &req, uint32_t immData)
{
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("RDMA Failed to PostSendSgl with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto ctx = mOpCtxInfoPool.Get();
    if (NN_UNLIKELY(ctx == nullptr)) {
        NN_LOG_ERROR("RDMA Failed to PostSendSgl with RDMAWorker " << DetailName() << " as no reqInfo left");
        return RR_QP_CTX_FULL;
    }

    if (NN_UNLIKELY(!qp->GetPostSendWr())) {
        NN_LOG_ERROR("RDMA Failed to PostSendSgl with RDMAWorker " << DetailName() << " as no post send wr left");
        mOpCtxInfoPool.Return(ctx);
        return RR_QP_POST_SEND_WR_FULL;
    }
    ctx->qp = qp;
    ctx->mrMemAddr = req.lAddress;
    ctx->dataSize = req.size;
    ctx->qpNum = qp->QpNum();
    ctx->lKey = req.lKey;
    ctx->opType = RDMAOpContextInfo::SEND_SGL_INLINE;
    ctx->opResultType = RDMAOpContextInfo::SUCCESS;
    ctx->upCtxSize = req.upCtxSize;
    if (req.upCtxSize > 0 && NN_UNLIKELY(memcpy_s(ctx->upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
        NN_LOG_ERROR("Failed to copy request to ctx");
        qp->ReturnPostSendWr();
        mOpCtxInfoPool.Return(ctx);
        return RR_PARAM_INVALID;
    }
    qp->IncreaseRef();

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    qp->AddOpCtxInfo(ctx);

    UBSHcomNetTransDataIov netTransDataIov[NN_NO2];
    netTransDataIov[NN_NO0].address = reinterpret_cast<uintptr_t>(&header);
    netTransDataIov[NN_NO0].size = sizeof(RDMASendSglInlineHeader);
    netTransDataIov[NN_NO1].address = req.lAddress;
    netTransDataIov[NN_NO1].size = req.size;

    auto result = qp->PostSendSglInline(
        netTransDataIov, NN_NO2, reinterpret_cast<uint64_t>(ctx), immData);
    if (NN_UNLIKELY(result != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        qp->ReturnPostSendWr();
        qp->DecreaseRef();
        qp->RemoveOpCtxInfo(ctx);
        mOpCtxInfoPool.Return(ctx);
    }

    // ctx could not be used if post successfully
    return result;
}

RResult RDMAWorker::PostSendSgl(RDMAQp *qp, const RDMASendSglRWRequest &req, const RDMASendReadWriteRequest &tlsReq,
    uint32_t immData, bool isEncrypted)
{
    // Prevent integer truncation, safely converts uint64_t to uint32_t
    if (NN_UNLIKELY(tlsReq.lKey > UINT32_MAX)) {
        NN_LOG_ERROR("Failed to PostSendSgl with RDMAWorker as lKey is larger than uint32max, lKey" << tlsReq.lKey);
        return RR_PARAM_INVALID;
    }
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Failed to PostRead with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto sglCtx = mSglCtxInfoPool.Get();
    if (NN_UNLIKELY(sglCtx == nullptr)) {
        NN_LOG_ERROR("Failed to PostRead with RDMAWorker " << DetailName() << " as no ctx left");
        return RR_PARAM_INVALID;
    }

    sglCtx->qp = qp;
    sglCtx->result = RR_OK;
    if (NN_UNLIKELY(memcpy_s(sglCtx->iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, req.iov,
        sizeof(UBSHcomNetTransSgeIov) * req.iovCount) != RR_OK)) {
        NN_LOG_ERROR("Failed to copy request to sglCtx");
        mSglCtxInfoPool.Return(sglCtx);
        return RR_PARAM_INVALID;
    }
    sglCtx->iovCount = req.iovCount;
    sglCtx->upCtxSize = req.upCtxSize;
    if (req.upCtxSize > 0) {
        if (NN_UNLIKELY(memcpy_s(sglCtx->upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
            NN_LOG_ERROR("Failed to copy request to sglCtx");
            mSglCtxInfoPool.Return(sglCtx);
            return RR_PARAM_INVALID;
        }
    }

    auto ctx = mOpCtxInfoPool.Get();
    if (NN_UNLIKELY(ctx == nullptr)) {
        NN_LOG_ERROR("Failed to PostSend with RDMAWorker " << DetailName() << " as no reqInfo left");
        mSglCtxInfoPool.Return(sglCtx);
        return RR_QP_CTX_FULL;
    }

    if (NN_UNLIKELY(!qp->GetPostSendWr())) {
        NN_LOG_ERROR("Failed to PostSend with RDMAWorker " << DetailName() << " as no post send wr left");
        mOpCtxInfoPool.Return(ctx);
        mSglCtxInfoPool.Return(sglCtx);
        return RR_QP_POST_SEND_WR_FULL;
    }
    ctx->qp = qp;

    // if not encrypt reqTls lAddress\size\lKey is 0
    ctx->mrMemAddr = tlsReq.lAddress;
    ctx->dataSize = tlsReq.size;
    ctx->lKey = static_cast<uint32_t>(tlsReq.lKey);
    ctx->qpNum = qp->QpNum();
    ctx->opType = RDMAOpContextInfo::SEND_RAW_SGL;
    ctx->opResultType = RDMAOpContextInfo::SUCCESS;
    ctx->upCtxSize = static_cast<uint16_t>(sizeof(RDMASgeCtxInfo));
    auto upCtx = static_cast<RDMASgeCtxInfo *>((void *)&(ctx->upCtx));
    upCtx->ctx = sglCtx;
    qp->IncreaseRef();

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    qp->AddOpCtxInfo(ctx);

    RResult result = RR_OK;
    if (isEncrypted != 0) {
        result = qp->PostSend(tlsReq.lAddress, tlsReq.size, static_cast<uint32_t>(tlsReq.lKey),
            reinterpret_cast<uint64_t>(ctx), immData);
    } else {
        result = qp->PostSendSgl(req.iov, req.iovCount, reinterpret_cast<uint64_t>(ctx), immData);
    }

    if (NN_UNLIKELY(result != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        qp->ReturnPostSendWr();
        qp->RemoveOpCtxInfo(ctx);
        qp->DecreaseRef();
        mOpCtxInfoPool.Return(ctx);
        mSglCtxInfoPool.Return(sglCtx);
    }

    return result;
}

RResult RDMAWorker::PostRead(RDMAQp *qp, const RDMASendReadWriteRequest &req)
{
    // Prevent integer truncation, safely converts uint64_t to uint32_t
    if (NN_UNLIKELY(req.lKey > UINT32_MAX || req.rKey > UINT32_MAX)) {
        NN_LOG_ERROR("Failed to PostRead with RDMAWorker as Key is larger than uint32max, lKey" <<
            req.lKey << " rKey " << req.rKey);
        return RR_PARAM_INVALID;
    }
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Failed to PostRead with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto ctx = mOpCtxInfoPool.Get();
    if (NN_UNLIKELY(ctx == nullptr)) {
        NN_LOG_ERROR("Failed to PostRead with RDMAWorker " << DetailName() << " as no reqInfo left");
        return RR_QP_CTX_FULL;
    }

    if (NN_UNLIKELY(!qp->GetOneSideWr())) {
        NN_LOG_ERROR("Failed to PostSend with RDMAWorker " << DetailName() << " as no one side wr left");
        mOpCtxInfoPool.Return(ctx);
        return RR_QP_ONE_SIDE_WR_FULL;
    }
    ctx->mrMemAddr = req.lAddress;
    ctx->qp = qp;
    ctx->dataSize = req.size;
    ctx->qpNum = qp->QpNum();
    ctx->lKey = static_cast<uint32_t>(req.lKey);
    ctx->opType = RDMAOpContextInfo::READ;
    ctx->opResultType = RDMAOpContextInfo::SUCCESS;
    ctx->upCtxSize = req.upCtxSize;
    if (req.upCtxSize > 0) {
        if (NN_UNLIKELY(memcpy_s(ctx->upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            qp->ReturnOneSideWr();
            mOpCtxInfoPool.Return(ctx);
            return RR_PARAM_INVALID;
        }
    }
    qp->IncreaseRef();

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    qp->AddOpCtxInfo(ctx);

    auto result = qp->PostRead(req.lAddress, static_cast<uint32_t>(req.lKey), req.rAddress,
        static_cast<uint32_t>(req.rKey), req.size, reinterpret_cast<uint64_t>(ctx));
    if (NN_UNLIKELY(result != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        qp->ReturnOneSideWr();
        qp->DecreaseRef();
        qp->RemoveOpCtxInfo(ctx);
        mOpCtxInfoPool.Return(ctx);
    }

    // ctx could not be used if post successfully
    return result;
}

RResult RDMAWorker::PostOneSideSgl(RDMAQp *qp, const RDMASendSglRWRequest &req, bool isRead)
{
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Failed to oneSide operation with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto sglCtx = mSglCtxInfoPool.Get();
    if (NN_UNLIKELY(sglCtx == nullptr)) {
        NN_LOG_ERROR("Failed to oneSide operation with RDMAWorker " << DetailName() << " as no ctx left");
        return RR_PARAM_INVALID;
    }

    sglCtx->result = RR_OK;
    sglCtx->qp = qp;
    if (NN_UNLIKELY(memcpy_s(sglCtx->iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, req.iov,
        sizeof(UBSHcomNetTransSgeIov) * req.iovCount) != RR_OK)) {
        NN_LOG_ERROR("Failed to copy req to sglCtx");
        mSglCtxInfoPool.Return(sglCtx);
        return RR_PARAM_INVALID;
    }
    sglCtx->upCtxSize = req.upCtxSize;
    sglCtx->iovCount = req.iovCount;
    if (req.upCtxSize > 0) {
        if (NN_UNLIKELY(memcpy_s(sglCtx->upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            mSglCtxInfoPool.Return(sglCtx);
            return RR_PARAM_INVALID;
        }
    }
    sglCtx->refCount = 0;

    /* 分组：同 rkey 且远端地址首尾连续的 iov 合成一个 WR(多 SGE)，减少 WR/完成数。
       默认关闭(等同旧行为，每 iov 一个 WR)：
       HCOM_MSGE_MERGE=1 开启合并；HCOM_MSGE_MAX=N 限制单 WR 最多合并 N 个 iov(默认4)。 */
    static const bool kMsgeMerge = []() {
        const char *v = std::getenv("HCOM_MSGE_MERGE");
        return v != nullptr && *v != '\0' && *v != '0';
    }();
    static const uint32_t kMsgeMax = []() {
        const char *v = std::getenv("HCOM_MSGE_MAX");
        if (v == nullptr || *v == '\0' || *v == '0') {
            return static_cast<uint32_t>(NN_NO4);
        }
        uint32_t m = static_cast<uint32_t>(std::atoi(v));
        return m == 0 ? static_cast<uint32_t>(NN_NO4) : m;
    }();
    uint32_t groupBegin[NET_SGE_MAX_IOV] = {};
    uint32_t groupLen[NET_SGE_MAX_IOV] = {};
    uint32_t groupCount = 0;
    for (uint32_t i = 0; i < req.iovCount;) {
        uint32_t begin = i;
        if (!kMsgeMerge) {
            ++i;
        } else {
            uint64_t prevEnd = req.iov[i].rAddress + req.iov[i].size;
            ++i;
            while (i < req.iovCount && (i - begin) < kMsgeMax && req.iov[i].rKey == req.iov[begin].rKey &&
                req.iov[i].rAddress == prevEnd) {
                prevEnd = req.iov[i].rAddress + req.iov[i].size;
                ++i;
            }
        }
        groupBegin[groupCount] = begin;
        groupLen[groupCount] = i - begin;
        ++groupCount;
    }

    RDMASgeCtxInfo sgeInfo(sglCtx);
    uint64_t ctxArr[NET_SGE_MAX_IOV] = {};
    RResult result =
        CreateOneSideCtx(sgeInfo, req.iov, req.iovCount, groupCount, groupBegin, groupLen, ctxArr, isRead);
    if (result != RR_OK) {
        NN_LOG_ERROR("Failed to create one side ctx.");
        mSglCtxInfoPool.Return(sglCtx);
        return result;
    }

    result = qp->PostOneSideSglGrouped(req.iov, groupCount, groupBegin, groupLen, ctxArr, isRead);
    if (NN_UNLIKELY(result != RR_OK)) {
        for (uint32_t i = 0; i < groupCount; ++i) {
            qp->ReturnOneSideWr();
            qp->RemoveOpCtxInfo(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[i]));
            qp->DecreaseRef();
            mOpCtxInfoPool.Return(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[i]));
        }
        mSglCtxInfoPool.Return(sglCtx);
    }

    return result;
}

RResult RDMAWorker::CreateOneSideCtx(RDMASgeCtxInfo &sgeInfo, UBSHcomNetTransSgeIov *iov, uint32_t iovCount,
    uint32_t groupCount, const uint32_t *groupBegin, const uint32_t *groupLen,
    uint64_t (&ctxArr)[NET_SGE_MAX_IOV], bool isRead)
{
    if (iov == nullptr || iovCount == NN_NO0 || iovCount > NN_NO4 || groupCount == 0 || groupCount > NN_NO4 ||
        groupBegin == nullptr || groupLen == nullptr || ctxArr == nullptr) {
        NN_LOG_ERROR("Failed to create oneSide operation ctx because param invalid");
        return RR_PARAM_INVALID;
    }
    for (uint32_t g = 0; g < groupCount; ++g) {
        uint32_t begin = groupBegin[g];
        uint32_t num = groupLen[g];
        if (NN_UNLIKELY(num == 0 || begin + num > iovCount)) {
            NN_LOG_ERROR("Failed to create oneSide operation ctx because group invalid, group " << g);
            for (uint32_t j = 0; j < g; ++j) {
                sgeInfo.ctx->qp->ReturnOneSideWr();
                sgeInfo.ctx->qp->RemoveOpCtxInfo(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[j]));
                sgeInfo.ctx->qp->DecreaseRef();
                mOpCtxInfoPool.Return(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[j]));
            }
            return RR_PARAM_INVALID;
        }

        auto ctx = mOpCtxInfoPool.Get();
        if (NN_UNLIKELY(ctx == nullptr)) {
            NN_LOG_ERROR("Verbs failed to oneSide operation with RDMAWorker " << DetailName() << " as no ctx left");
            for (uint32_t j = 0; j < g; ++j) {
                sgeInfo.ctx->qp->ReturnOneSideWr();
                sgeInfo.ctx->qp->RemoveOpCtxInfo(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[j]));
                sgeInfo.ctx->qp->DecreaseRef();
                mOpCtxInfoPool.Return(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[j]));
            }
            return RR_QP_CTX_FULL;
        }

        if (NN_UNLIKELY(!sgeInfo.ctx->qp->GetOneSideWr())) {
            NN_LOG_ERROR("Verbs failed to oneSide operation with RDMAWorker " << DetailName() <<
                " as no one side wr left");
            mOpCtxInfoPool.Return(ctx);
            for (uint32_t j = 0; j < g; ++j) {
                sgeInfo.ctx->qp->ReturnOneSideWr();
                sgeInfo.ctx->qp->RemoveOpCtxInfo(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[j]));
                sgeInfo.ctx->qp->DecreaseRef();
                mOpCtxInfoPool.Return(reinterpret_cast<RDMAOpContextInfo *>(ctxArr[j]));
            }
            return RR_QP_ONE_SIDE_WR_FULL;
        }

        ctx->qp = sgeInfo.ctx->qp;
        ctx->mrMemAddr = iov[begin].lAddress;
        uint32_t groupBytes = 0;
        for (uint32_t k = 0; k < num; ++k) {
            groupBytes += static_cast<uint32_t>(iov[begin + k].size);
        }
        ctx->dataSize = groupBytes;
        ctx->qpNum = sgeInfo.ctx->qp->QpNum();
        ctx->lKey = static_cast<uint32_t>(iov[begin].lKey);
        ctx->opType = isRead ? RDMAOpContextInfo::SGL_READ : RDMAOpContextInfo::SGL_WRITE;
        ctx->opResultType = RDMAOpContextInfo::SUCCESS;
        ctx->upCtxSize = static_cast<uint16_t>(sizeof(RDMASgeCtxInfo));
        auto upCtx = static_cast<RDMASgeCtxInfo *>((void *)&(ctx->upCtx));
        upCtx->ctx = sgeInfo.ctx;
        upCtx->idx = static_cast<uint16_t>(begin);
        upCtx->count = static_cast<uint16_t>(num); /* 该 WR 覆盖 iov 数，完成时按此累加 refCount */

        sgeInfo.ctx->qp->IncreaseRef();
        sgeInfo.ctx->qp->AddOpCtxInfo(ctx);
        ctxArr[g] = reinterpret_cast<uint64_t>(ctx);
    }
    return RR_OK;
}

RResult RDMAWorker::PostWrite(RDMAQp *qp, const RDMASendReadWriteRequest &req, RDMAOpContextInfo::OpType type)
{
    // Prevent integer truncation, safely converts uint64_t to uint32_t
    if (NN_UNLIKELY(req.lKey > UINT32_MAX || req.rKey > UINT32_MAX)) {
        NN_LOG_ERROR("Failed to PostWrite with RDMAWorker as Key is larger than uint32max, lKey" <<
            req.lKey << " rKey " << req.rKey);
        return RR_PARAM_INVALID;
    }
    if (NN_UNLIKELY(qp == nullptr)) {
        NN_LOG_ERROR("Failed to PostWrite with RDMAWorker " << DetailName() << " as qp is null");
        return RR_PARAM_INVALID;
    }

    auto ctx = mOpCtxInfoPool.Get();
    if (NN_UNLIKELY(ctx == nullptr)) {
        NN_LOG_ERROR("Failed to PostWrite with RDMAWorker " << DetailName() << " as no ctx left");
        return RR_QP_CTX_FULL;
    }
    if (NN_UNLIKELY(!qp->GetOneSideWr())) {
        NN_LOG_ERROR("Failed to PostWrite with RDMAWorker " << DetailName() << " as no one side wr left");
        mOpCtxInfoPool.Return(ctx);
        return RR_QP_ONE_SIDE_WR_FULL;
    }
    ctx->qp = qp;
    ctx->mrMemAddr = req.lAddress;
    ctx->dataSize = req.size;
    ctx->qpNum = qp->QpNum();
    ctx->lKey = static_cast<uint32_t>(req.lKey);
    ctx->opType = type;
    ctx->upCtxSize = req.upCtxSize;
    ctx->opResultType = RDMAOpContextInfo::SUCCESS;
    if (req.upCtxSize > 0) {
        if (NN_UNLIKELY(memcpy_s(ctx->upCtx, NN_NO16, req.upCtxData, req.upCtxSize) != RR_OK)) {
            NN_LOG_ERROR("Failed to copy request to ctx");
            qp->ReturnOneSideWr();
            mOpCtxInfoPool.Return(ctx);
            return RR_PARAM_INVALID;
        }
    }
    qp->IncreaseRef();

    // attach context to qp firstly, because post could be finished very fast
    // if posted failed, need to remove
    qp->AddOpCtxInfo(ctx);

    auto result = qp->PostWrite(req.lAddress, static_cast<uint32_t>(req.lKey), req.rAddress,
        static_cast<uint32_t>(req.rKey), req.size, reinterpret_cast<uint64_t>(ctx));
    if (NN_UNLIKELY(result != RR_OK)) {
        // remove ctx from qp firstly, then return to pool because, ctx maybe deleted
        qp->ReturnOneSideWr();
        qp->DecreaseRef();
        qp->RemoveOpCtxInfo(ctx);
        mOpCtxInfoPool.Return(ctx);
    }

    // ctx could not be used if post successfully
    return result;
}
}
}
#endif