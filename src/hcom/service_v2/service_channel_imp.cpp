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
#include "service_channel_imp.h"

#include <cstdint>

#include "hcom_log.h"
#include "hcom_err.h"
#include "hcom_num_def.h"
#include "hcom_service_channel.h"
#include "net_param_validator.h"

namespace ock {
namespace hcom {

constexpr uint16_t RECON_DELAY_ERASE_TIME = 60;
constexpr uint16_t DEFAULT_DELAY_ERASE_TIME = 1;


SerResult HcomChannelImp::Initialize(std::vector<UBSHcomNetEndpointPtr> &ep, uintptr_t ctxMemPool,
    uintptr_t periodicMgr, uintptr_t pgTable, uint32_t ctxStoreCapacity)
{
    std::lock_guard<std::mutex> locker(mMgrMutex);
    if (!mChState.Compare(UBSHcomChannelState::CH_NEW)) {
        return SER_OK;
    }

    if (NN_UNLIKELY(ep.size() == 0) || NN_UNLIKELY(ep.size() > NN_NO64)) {
        NN_LOG_ERROR("Invalid ep vector, size is " << ep.size() << " should in [1-64].");
        return SER_INVALID_PARAM;
    }

    auto header = new (std::nothrow) SerTimerListHeader;
    if (header == nullptr) {
        NN_LOG_ERROR("Failed to create timer list header");
        return SER_NEW_OBJECT_FAILED;
    }
    mTimerList = reinterpret_cast<uintptr_t>(header);

    auto ctxMemPoolPtr = reinterpret_cast<NetMemPoolFixed *>(ctxMemPool);
    if (NN_UNLIKELY(ctxMemPoolPtr == nullptr)) {
        NN_LOG_ERROR("Invalid ctx store ptr " << ctxMemPool);
        ForceUnInitialize();
        return SER_INVALID_PARAM;
    }
    ctxMemPoolPtr->IncreaseRef();
    mCtxMemPool = ctxMemPool;

    HcomServiceCtxStore *ctxStore = new (std::nothrow) HcomServiceCtxStore(ctxStoreCapacity, ctxMemPoolPtr, mProtocol);
    if (NN_UNLIKELY(ctxStore == nullptr)) {
        NN_LOG_ERROR("Create ctx store failed");
        ForceUnInitialize();
        return SER_NEW_OBJECT_FAILED;
    }

    SerResult ret = ctxStore->Initialize();
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Init ctx store failed " << ret);
        delete ctxStore;
        ctxStore = nullptr;
        ForceUnInitialize();
        return SER_NEW_OBJECT_FAILED;
    }
    ctxStore->IncreaseRef();
    mCtxStore = ctxStore;

    auto periodicMgrPtr = reinterpret_cast<HcomPeriodicManager *>(periodicMgr);
    if (NN_UNLIKELY(periodicMgrPtr == nullptr)) {
        NN_LOG_ERROR("Invalid periodic mgr ptr " << periodicMgr);
        ForceUnInitialize();
        return SER_INVALID_PARAM;
    }
    periodicMgrPtr->IncreaseRef();
    mPeriodicMgr = periodicMgr;

    auto netPgTablePtr = reinterpret_cast<NetPgTable *>(pgTable);
    if (NN_UNLIKELY(netPgTablePtr == nullptr)) {
        NN_LOG_ERROR("Invalid pgTable ptr is null");
        ForceUnInitialize();
        return SER_INVALID_PARAM;
    }
    netPgTablePtr->IncreaseRef();
    mPgtable = pgTable;

    ret = InitializeEp(ep);
    if (NN_UNLIKELY(ret != SER_OK)) {
        ForceUnInitialize();
        return ret;
    }

    CheckAndUpdateThreshold();
    mChState.Set(UBSHcomChannelState::CH_ESTABLISHED);
    return SER_OK;
}

void HcomChannelImp::CheckAndUpdateThreshold()
{
    auto rndvThreshold = HcomEnv::RndvThreshold();
    // 环境变量 HCOM_ENABLE_SPLIT_SEND 仅能够为 0 或者 1, 其他情况都认定为 0.
    const long enabled = NetFunc::NN_GetLongEnv("HCOM_ENABLE_SPLIT_SEND", 0, 1, 0);
    if (!enabled) {
        if (!mEnableMrCache) {
            NN_LOG_WARN("Unable to set rndv threshold because mEnableMrCache is false, SplitSend threshold " <<
                mUserSplitSendThreshold << ", Rndv Threshold is: " << mRndvThreshold);
            return;
        }
        mRndvThreshold = rndvThreshold;
        NN_LOG_INFO("SplitSend (UBC only) enabled with threshold " << UINT32_MAX
                                                                        << ", Rndv Threshold is: " << mRndvThreshold);
        return;
    }

    if (rndvThreshold < NN_NO65536) {
        NN_LOG_WARN("The threshold of split send cannot be greater than the threshold of rndv! Split send threshold: "
                    << NN_NO65536 << " Rndv threshold: " << rndvThreshold);
        return;
    }

    mUserSplitSendThreshold = NN_NO65536 - sizeof(UBSHcomNetTransHeader) - sizeof(UBSHcomFragmentHeader);
    if (!mEnableMrCache) {
        NN_LOG_WARN("Unable to set rndv threshold because mEnableMrCache is false ");
    } else {
        mRndvThreshold = rndvThreshold;
    }
    NN_LOG_INFO("SplitSend (UBC only) enabled with threshold " << NN_NO65536 << ", Rndv Threshold is: " <<
        mRndvThreshold);
}

SerResult HcomChannelImp::InitializeEp(std::vector<UBSHcomNetEndpointPtr> &ep)
{
    if (ep.empty() || ep[0] == nullptr) {
        NN_LOG_WARN("try to initialize empty ep");
        return SER_OK;
    }

    mLocalIp = ep[0]->LocalIp();
    mEpInfo = new (std::nothrow) EpInfo;
    if (mEpInfo == nullptr) {
        NN_LOG_ERROR("Create ep info failed");
        return SER_NEW_OBJECT_FAILED;
    }

    mEpInfo->epSize = ep.size();
    for (int i = 0; i < mEpInfo->epSize; i++) {
        mEpInfo->epArr[i] = ep.at(i).Get();
        mEpInfo->epArr[i]->IncreaseRef();

        ServiceEpState state = SER_EP_ESTABLISHED;
        if (mOptions.selfPoll) {
            state = SER_EP_ESTABLISHED_UNOCCUPIED;
        }
        mEpInfo->epState[i].Set(state);
    }
    SetEpUpCtx();

    if (NN_UNLIKELY(!AllEpEstablished())) {
        UnSetEpUpCtx();
        NN_LOG_ERROR("Failed to check ep state, some of them are broken during connecting, channel id " << mOptions.id);
        return SER_EP_BROKEN_DURING_CONNECTING;
    }

    return SER_OK;
}

void HcomChannelImp::UnInitialize()
{
    std::lock_guard<std::mutex> locker(mMgrMutex);
    if (mChState.Compare(UBSHcomChannelState::CH_DESTROY)) {
        return;
    }

    if (NN_UNLIKELY(mEpInfo == nullptr)) {
        mChState.Set(CH_CLOSE);
        return;
    }

    for (uint16_t idx = 0; idx < mEpInfo->epSize; idx++) {
        if (mEpInfo->epArr[idx]->State().Compare(NEP_ESTABLISHED)) {
            mEpInfo->epArr[idx]->Close();
        }
    }

    mChState.Set(CH_CLOSE);
}

void HcomChannelImp::ForceUnInitialize()
{
    if (mOptions.rateLimit != 0) {
        auto rateLimit = reinterpret_cast<RateLimiter *>(mOptions.rateLimit);
        delete rateLimit;
        mOptions.rateLimit = 0;
    }

    if (NN_LIKELY(mCtxStore != nullptr)) {
        mCtxStore->DecreaseRef();
        mCtxStore = nullptr;
    }

    auto ctxMemPool = reinterpret_cast<NetMemPoolFixed *>(mCtxMemPool);
    if (NN_LIKELY(ctxMemPool != nullptr)) {
        ctxMemPool->DecreaseRef();
        mCtxMemPool = 0;
    }

    auto periodicMgrPtr = reinterpret_cast<HcomPeriodicManager *>(mPeriodicMgr);
    if (NN_LIKELY(periodicMgrPtr != nullptr)) {
        periodicMgrPtr->DecreaseRef();
        mPeriodicMgr = 0;
    }

    NetPgTable *pgTable = reinterpret_cast<NetPgTable *>(mPgtable);
    if (NN_LIKELY(pgTable != nullptr)) {
        pgTable->DecreaseRef();
        mPgtable = 0;
    }

    auto timeHeader = reinterpret_cast<SerTimerListHeader *>(mTimerList);
    if (NN_LIKELY(timeHeader != nullptr)) {
        delete timeHeader;
        mTimerList = 0;
    }

    if (mEpInfo != nullptr) {
        // unset up ctx first, avoid race condition for ep broken during connecting.
        UnSetEpUpCtx();
        for (uint16_t i = 0; i < mEpInfo->epSize; i++) {
            if (mEpInfo->epArr[i] != nullptr) {
                mEpInfo->epArr[i]->DecreaseRef();
            }
        }
        delete mEpInfo;
        mEpInfo = nullptr;
    }
    mChState.Set(UBSHcomChannelState::CH_DESTROY);
}

std::string HcomChannelImp::ToString()
{
    std::ostringstream oss;
    oss << "Connect channel id " << mOptions.id;

    if (mEpInfo == nullptr) {
        oss << " error, mEpInfo is nullptr";
        return oss.str();
    }

    oss << " with " << mEpInfo->epSize << " eps :[";
    for (uint16_t i = 0; i < mEpInfo->epSize; i++) {
        if (mEpInfo->epArr[i] == nullptr) {
            continue;
        }
        oss << mEpInfo->epArr[i]->Id();
        if (i != (mEpInfo->epSize - 1)) {
            oss << ", ";
        }
    }
    oss << "]";
    return oss.str();
}

constexpr uint32_t VALID_SEQ_NO = 0xFFFFFFFF; /* low 32 bit */
inline void MarkOpCodeBySeqNo(uint32_t &seqNo, uintptr_t rspCtx)
{
    HcomSeqNo netSeqNo(seqNo);
    netSeqNo.isResp = rspCtx == 0 ? 0 : 1;
    seqNo = netSeqNo.wholeSeq;
}

inline void MarkOpCodeBySeqNo(uint32_t &seqNo, uintptr_t rspCtx, bool originalSeqNo)
{
    if (rspCtx == 0) {
        HcomSeqNo netSeqNo(seqNo);
        netSeqNo.isResp = 0;
        seqNo = netSeqNo.wholeSeq;
    } else if (originalSeqNo) {
        seqNo = rspCtx & VALID_SEQ_NO;
    } else {
        HcomSeqNo netSeqNo(rspCtx & VALID_SEQ_NO);
        netSeqNo.isResp = 1;
        seqNo = netSeqNo.wholeSeq;
    }
}

inline SerResult HcomChannelImp::AcquireSelfPollEp(UBSHcomNetEndpoint *&ep, uint32_t &index, int16_t timeout,
    uint16_t dvrIdx)
{
    if (NN_UNLIKELY(!mChState.Compare(UBSHcomChannelState::CH_ESTABLISHED))) {
        NN_LOG_ERROR("Channel state is not established " << static_cast<int>(mChState.Get()));
        return SER_NOT_ESTABLISHED;
    }
    NN_ASSERT_LOG_RETURN(mEpInfo != nullptr, NN_ERROR)
    uint64_t startTimeSecond = NetMonotonic::TimeSec();
    uint64_t endTimeSecond = 0;
    if (timeout > 0) {
        endTimeSecond = startTimeSecond + timeout;
    } else {
        endTimeSecond = startTimeSecond + NN_NO8;
    }

    index = __sync_fetch_and_add(&mEpChoosingIdx[dvrIdx], 1) % (mEpInfo->epSize / mDriverNum) +
        dvrIdx * (mEpInfo->epSize / mDriverNum);
    uint32_t count = 0;
    while (!mEpInfo->epState[index].CAS(SER_EP_ESTABLISHED_UNOCCUPIED, SER_EP_ESTABLISHED_OCCUPIED)) {
        index = __sync_fetch_and_add(&mEpChoosingIdx[dvrIdx], 1) % (mEpInfo->epSize / mDriverNum) +
            dvrIdx * (mEpInfo->epSize / mDriverNum);
        if ((++count % (mEpInfo->epSize / mDriverNum)) == 0) {
            if (NN_UNLIKELY(!mChState.Compare(UBSHcomChannelState::CH_ESTABLISHED))) {
                NN_LOG_ERROR("Channel is not established " << static_cast<int>(mChState.Get()));
                return SER_NOT_ESTABLISHED;
            }
            if (NetMonotonic::TimeSec() > endTimeSecond) {
                NN_LOG_ERROR("Acquire self poll ep timeout for " << endTimeSecond - startTimeSecond <<
                    " seconds, maybe all endpoints broken / users too much / remote side not response");
                return SER_TIMEOUT;
            }
        }
    }

    ep = mEpInfo->epArr[index];
    if (NN_UNLIKELY(ep == nullptr)) {
        NN_LOG_ERROR("Channel Id " << mOptions.id << " ep invalid");
        return SER_NOT_ESTABLISHED;
    }
    return SER_OK;
}

inline void HcomChannelImp::ReleaseSelfPollEp(uint32_t index)
{
    if (NN_UNLIKELY(index >= mEpInfo->epSize)) {
        NN_LOG_ERROR("Invalid index to release self poll ep in channel "
                     << mOptions.id);
        return;
    }

    if (!mEpInfo->epState[index].CAS(SER_EP_ESTABLISHED_OCCUPIED,
                                     SER_EP_ESTABLISHED_UNOCCUPIED)) {
        NN_LOG_ERROR("Channel id " << mOptions.id
                                   << " failed to release self poll ep, state "
                                   << mEpInfo->epState[index].Get());
    }
}

inline SerResult HcomChannelImp::NextWorkerPollEp(UBSHcomNetEndpoint *&ep, uint16_t dvrIdx)
{
    if (NN_UNLIKELY(!mChState.Compare(UBSHcomChannelState::CH_ESTABLISHED))) {
        NN_LOG_ERROR("Channel state not established " << static_cast<uint16_t>(mChState.Get()));
        return SER_NOT_ESTABLISHED;
    }

    uint16_t tmpIndex = __sync_fetch_and_add(&mEpChoosingIdx[dvrIdx], 1) % (mEpInfo->epSize / mDriverNum) +
            dvrIdx * (mEpInfo->epSize / mDriverNum);
    uint16_t count = 0;

    while (mEpInfo->epState[tmpIndex].Compare(SER_EP_BROKEN) &&
           count < (mEpInfo->epSize / mDriverNum)) {
        tmpIndex = (tmpIndex + 1) % (mEpInfo->epSize / mDriverNum) + dvrIdx * (mEpInfo->epSize / mDriverNum);
        count++;
    }

    if (NN_UNLIKELY(count > mEpInfo->epSize)) {
        NN_LOG_ERROR("Channel Id " << mOptions.id << " all ep broken");
        return SER_NOT_ESTABLISHED;
    }

    ep = mEpInfo->epArr[tmpIndex];
    if (NN_UNLIKELY(ep == nullptr)) {
        NN_LOG_ERROR("Channel Id " << mOptions.id << " ep invalid");
        return SER_NOT_ESTABLISHED;
    }
    return SER_OK;
}

inline SerResult HcomChannelImp::ResponseWorkerPollEp(uintptr_t rspCtx, UBSHcomNetEndpoint *&ep)
{
    if (NN_UNLIKELY(!mChState.Compare(CH_ESTABLISHED))) {
        NN_LOG_ERROR("Channel state not established " << mChState.Get());
        return SER_NOT_ESTABLISHED;
    }

    uint32_t epIndex = rspCtx >> 32;
    if (NN_UNLIKELY(epIndex >= mEpInfo->epSize)) {
        NN_LOG_ERROR("Invalid ep index " << epIndex << " over ep size " << mEpInfo->epSize);
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mEpInfo->epState[epIndex].Compare(SER_EP_BROKEN))) {
        NN_LOG_ERROR("Ep broken of channel id "
                     << mOptions.id << " , select response ep fail");
        return SER_NOT_ESTABLISHED;
    }

    ep = mEpInfo->epArr[epIndex];
    if (NN_UNLIKELY(ep == nullptr)) {
        NN_LOG_ERROR("Channel Id " << mOptions.id << " ep invalid");
        return SER_NOT_ESTABLISHED;
    }
    return SER_OK;
}

SerResult HcomChannelImp::PrepareTimerContext(const Callback *cb, int16_t timeout, TimerCtx &context)
{
    auto timerPtr = mCtxStore->GetCtxObj<HcomServiceTimer>();
    if (NN_UNLIKELY(timerPtr == nullptr)) {
        NN_LOG_ERROR("Failed to get context object from memory pool.");
        return SER_NEW_OBJECT_FAILED;
    }

    context.timer = new (timerPtr)HcomServiceTimer(this, mCtxStore,
        timeout, reinterpret_cast<uintptr_t>(cb), HcomAsyncCBType::CBS_IO);
    NResult ret = mCtxStore->PutAndGetSeqNo(context.timer, context.seqNo);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Failed to generate seqNo by context store pool.");
        mCtxStore->Return(timerPtr);
        return SER_NEW_OBJECT_FAILED;
    }

    context.timer->IncreaseRef();
    // timer seqNo is invalid, here need update by EmplaceContext() build seqNo.
    context.timer->SeqNo(context.seqNo);

    HcomPeriodicManagerPtr periodicMgrPtr = reinterpret_cast<HcomPeriodicManager *>(mPeriodicMgr);
    ret = periodicMgrPtr->AddTimer(context.timer);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Failed to add timer in for timeout control.");
        context.timer->EraseSeqNo();
        mCtxStore->Return(timerPtr);
        return ret;
    }
    context.timer->IncreaseRef();
    return SER_OK;
}

void HcomChannelImp::DestroyTimerContext(TimerCtx &context)
{
    // 主动清理 TimerContext，当且仅当发送失败时才会被调用。此时仅标记它为 finished，由于它已经被放
    // 入了超时队列当中，后面由超时线程自动将其删除、回收。如果很不巧，在发生超时时此线程未被调度到，
    // 那么定时器会被标记为超时，清理完全由超时线程处理。
    //
    // `DeleteCallBack()` 必须要被保护起来，否则可能会发生超时线程先被调度到，之后运行定时器关联的
    // callback 的同时将 callback 删除的极限情况。这时就可能会出现运行时错误了。
    if (NN_LIKELY(context.timer->EraseSeqNoWithRet())) {
        context.timer->DeleteCallBack();
        context.timer->MarkFinished();
        context.timer->DecreaseRef();
    }
}

int32_t HcomChannelImp::Send(const UBSHcomRequest &req, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::Send" << ", channel id = " << mOptions.id <<
                 ", status = " << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::CALLED));
    VALIDATE_PARAM_RET(Request, req);
    SerResult result = SER_OK;
    uint64_t timestamp = mOptions.twoSideTimeout < 0 ? UINT64_MAX : mOptions.twoSideTimeout + NetMonotonic::TimeSec();
    do {
        result = FlowControl(req.size, mOptions.twoSideTimeout, timestamp);
        if (NN_UNLIKELY(SER_OK != result)) {
            return result;
        }

        NetTrace::TraceBegin(CHANNEL_SEND);
        result = SendInner(req, done);
        NetTrace::TraceEnd(CHANNEL_SEND, result);
        if (NN_LIKELY(result == SER_OK)) {
            return SER_OK;
        } else if (result == SER_NEW_OBJECT_FAILED) { // do later::add retry result code
            usleep(100UL);
            continue;
        } else {
            break;
        }
    } while (NetMonotonic::TimeSec() < timestamp);

    NN_LOG_WARN("Failed to Send, result code: " << result);
    return result;
}

SerResult HcomChannelImp::SendInner(const UBSHcomRequest &req, const Callback *done)
{
    if (done == nullptr) {
        return SyncSendInner(req);
    }
    return AsyncSendInner(req, done);
}

static void SyncSendCbForWorkerPoll(UBSHcomServiceContext &context, HcomServiceSelfSyncParam *syncParam)
{
    if (NN_UNLIKELY(syncParam == nullptr)) {
        NN_LOG_ERROR("Failed to call SyncCallback syncParam is null");
        return;
    }
    if (NN_UNLIKELY(context.Result() != SER_OK)) {
        NN_LOG_ERROR("Channel sync send inner callback failed " << context.Result());
    }
    syncParam->Result(context.Result());
    syncParam->Signal();
}

SerResult HcomChannelImp::SyncSendInner(const UBSHcomRequest &req)
{
    if (mOptions.selfPoll) {
        return SyncSendWithSelfPoll(req);
    }

    UBSHcomNetEndpoint *ep = nullptr;
    SerResult result = NextWorkerPollEp(ep);
    if (NN_UNLIKELY(SER_OK != result)) {
        return result;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size, true);
    if (fragmentNum > 1) {
        return SyncSendSplitWithWorkerPoll(ep, req, fragmentNum);
    }

    HcomServiceSelfSyncParam syncParam {};
    Callback *callback = UBSHcomNewCallback(SyncSendCbForWorkerPoll, std::placeholders::_1, &syncParam);
    if (NN_UNLIKELY(callback == nullptr)) {
        NN_LOG_ERROR("Sync send callback is nullptr");
        return SER_NEW_OBJECT_FAILED;
    }

    TimerCtx timerContext {};
    result = PrepareTimerContext(callback, mOptions.twoSideTimeout, timerContext);
    if (result != SER_OK) {
        delete callback;
        return result;
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, sizeof(SerTransContext));
    SetServiceTransCtx(transReq.upCtxData, timerContext.seqNo);
    uint32_t userSeqNo = timerContext.seqNo;
    MarkOpCodeBySeqNo(userSeqNo, NN_NO0, mRespOriginalSeqNo);
    UBSHcomNetTransOpInfo transOp(userSeqNo, mOptions.twoSideTimeout);
    if (NN_LIKELY(transReq.size >= mRndvThreshold)) {
        result = RndvInner(ep, req, transOp, false);
    } else {
        NN_LOG_DEBUG("[Request Send] ------ channel id=" << mOptions.id << ", ep id=" << ep->Id() << ", seqNo=" <<
                     transOp.seqNo << ", status=" << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        result = ep->PostSend(req.opcode, transReq, transOp);
    }
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync send failed " << result << " ep id " << ep->Id());
        DestroyTimerContext(timerContext);
        return result;
    }

    syncParam.Wait();
    return syncParam.Result();
}

SerResult HcomChannelImp::SyncSendSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req,
    uint32_t fragmentNum)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    HcomServiceSelfSyncParam syncParam{};
    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;
        extHeader.offset = segOffset;

        Callback *newCallback = UBSHcomNewCallback(
            [segIndex, fragmentNum, &syncParam](UBSHcomServiceContext &context) {
                if (NN_UNLIKELY(context.Result() != SER_OK)) {
                    syncParam.Result(context.Result());
                    NN_LOG_ERROR("Channel sync send inner callback failed " << context.Result() << " when sending ["
                                                                            << (segIndex + 1) << "/" << fragmentNum
                                                                            << "]");
                }

                if (segIndex == fragmentNum - 1) {
                    syncParam.Signal();
                }
            },
            std::placeholders::_1);

        if (NN_UNLIKELY(!newCallback)) {
            NN_LOG_ERROR("Sync send malloc callback failed");
            return SER_NEW_OBJECT_FAILED;
        }

        TimerCtx timerContext{};
        SerResult result = PrepareTimerContext(newCallback, mOptions.twoSideTimeout, timerContext);
        if (result != SER_OK) {
            delete newCallback;
            return result;
        }

        UBSHcomNetTransRequest transReq(reinterpret_cast<void *>(segAddr), segSize, sizeof(SerTransContext));
        SetServiceTransCtx(transReq.upCtxData, timerContext.seqNo);
        uint32_t userSeqNo = timerContext.seqNo;
        MarkOpCodeBySeqNo(userSeqNo, NN_NO0, mRespOriginalSeqNo);
        UBSHcomNetTransOpInfo transOp(userSeqNo, mOptions.twoSideTimeout);
        NN_LOG_DEBUG("SyncSendSplitWithWorkerPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin; ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << ", status="
                     << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM)
                     << " req.opcode: " << req.opcode);
        result = ep->PostSend(req.opcode, transReq, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
            sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync send failed " << result << " ep id " << ep->Id());
            DestroyTimerContext(timerContext);
            return result;
        }

        NN_LOG_DEBUG("SyncSendSplitWithWorkerPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");
    }

    syncParam.Wait();
    return syncParam.Result();
}

auto HcomChannelImp::SpliceMessage(const UBSHcomNetRequestContext &ctx, bool isResp)
            -> std::tuple<SpliceMessageResultType, SerResult, std::string>
{
    const uintptr_t msgAddr = reinterpret_cast<uintptr_t>(ctx.Message()->Data());
    const uint32_t msgSize = ctx.Message()->DataLen();
    if (msgSize < sizeof(UBSHcomFragmentHeader)) {
        NN_LOG_ERROR("SpliceMessage: message size is invalid, actual: " << msgSize << ", wanted at least "
                                                                        << sizeof(UBSHcomFragmentHeader));
        return std::make_tuple(SpliceMessageResultType::ERROR, SER_SPLIT_INVALID_MSG, "");
    }

    // 需要拼包情况下必须包含 UBSHcomFragmentHeader 头部，此时的内存布局为：
    //     | UBSHcomFragmentHeader | payload |
    const UBSHcomFragmentHeader *serviceHeader = reinterpret_cast<UBSHcomFragmentHeader *>(msgAddr);
    const void *payload = reinterpret_cast<void *>(msgAddr + sizeof(UBSHcomFragmentHeader));
    const uint64_t payloadLen = msgSize - sizeof(UBSHcomFragmentHeader);
    const UBSHcomFragmentMessageId msgId = serviceHeader->msgId;
    const uint32_t totalLength = serviceHeader->totalLength;
    const uint32_t offset = serviceHeader->offset;

    NN_LOG_DEBUG("SpliceMessage: msgId " << msgId << ", totalLength " << totalLength
                                             << ", offset " << offset << ", size " << payloadLen);

    // 避免因数据在网络中被篡改而造成高内存占用
    if (totalLength >= SERVICE_MAX_TOTAL_LENGTH) {
        NN_LOG_ERROR("SpliceMessage: totalLength (" << totalLength << ") is larger than the maximum ("
                                                    << SERVICE_MAX_TOTAL_LENGTH << ")");
        return std::make_tuple(SpliceMessageResultType::ERROR, SER_SPLIT_INVALID_MSG, "");
    }

    std::shared_ptr<std::pair<uint32_t, std::string>> incompleteMsg;
    auto iter = mMsgReceived.end();

    if (offset == 0) {
        // 如果在短时间内 msgId 出现重复，且之前的消息还未超时仍旧存在，那么就会
        // 失败。需要修正一下 msgId 的生成算法。
        bool isInserted = false;
        {
            std::lock_guard<std::mutex> lock(mMsgReceivedMutex);
            std::tie(iter, isInserted) = mMsgReceived.emplace(msgId,
                std::make_shared<std::pair<uint32_t, std::string>>());
            if (NN_LIKELY(isInserted)) {
                incompleteMsg = iter->second;
            } else {
                NN_LOG_WARN("SpliceMessage: duplicate id " << msgId << ", nothing to do.");
            }
        }

        if (isInserted) {
            // 为防止分片无限堆积，如果在有限时间内无法完成拼包则将分片全部丢弃。
            Callback *cb = UBSHcomNewCallback(
                [iter](UBSHcomServiceContext &context, NetRef<HcomChannelImp> ch) {
                    // 超时由单独的超时线程处理，可能会并发地进行 iter 删除（此处）与对 iter->second
                    // 的复制（Worker 线程接收到另一个分片）。为了避免 Worker 线程访问无效内存，使用
                    // std::shared_ptr 增加引用计数延长接收 buffer 的生命周期。
                    NN_LOG_WARN("SpliceMessage: Timed-out. message can't be spliced in time.");
                    std::lock_guard<std::mutex> lock(ch->mMsgReceivedMutex);
                    ch->mMsgReceived.erase(iter);
                },
                std::placeholders::_1, NetRef<HcomChannelImp>{this});
            if (!cb) {
                NN_LOG_ERROR("SpliceMessage malloc callback failed");
                return std::make_tuple(SpliceMessageResultType::ERROR, SER_NEW_OBJECT_FAILED, "");
            }

            // 由于默认 NetServiceOpInfo.timeout 初始化为 -1, 用户在创建 OpInfo 时可能会忘记修改，最终会导致定
            // 时器永不超时，与预期不符；同时 NetServiceOpInfo 的另一个构造函数的 timeout 参数默认值为 0, 只要
            // 定时器线程被 OS 调度并处理定时器就会立即超时。这两种情况都会导致此处创建的定时器不起作用。
            if (ctx.Header().timeout <= 0) {
                NN_LOG_WARN("SpliceMessage: the timer will not work correctly! Check NetServiceOpInfo.timeout field, "
                            "current value: "
                            << ctx.Header().timeout);
            }

            TimerCtx context{};
            auto result = PrepareTimerContext(cb, ctx.Header().timeout, context);
            if (result != SER_OK) {
                NN_LOG_ERROR("Prepare timer context failed when creating timer for SpliceMessage");
                delete cb;
                return std::make_tuple(SpliceMessageResultType::ERROR, result, "");
            }

            // 在拼包完成后，通过 seqNo 索引到对应定时器
            incompleteMsg->first = context.seqNo;
            // 首包，分配足够大的内存
            incompleteMsg->second.resize(totalLength);
        }
    } else {
        std::lock_guard<std::mutex> lock(mMsgReceivedMutex);

        iter = mMsgReceived.find(msgId);
        if (NN_LIKELY(iter != mMsgReceived.end())) {
            incompleteMsg = iter->second;
        } else {
            NN_LOG_WARN("SpliceMessage: the first fragment is lost/timed-out? msgId " << msgId);
        }
    }

    if (!incompleteMsg) {
        return std::make_tuple(SpliceMessageResultType::ERROR, SER_ERROR, "");
    }

    auto *pmsg = &incompleteMsg->second;

    // 极小概率出现 msg2 的首包丢失，同时又正好 msgId 相同：
    //     | msg1 first | last |
    //     | msg2 first |  ...  | last |
    if (NN_UNLIKELY(offset > pmsg->size())) {
        NN_LOG_ERROR("SpliceMessage: the fragment is from another msg.");
        return std::make_tuple(SpliceMessageResultType::ERROR, SER_SPLIT_INVALID_MSG, "");
    }

    if (NN_UNLIKELY(memcpy_s(reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(pmsg->data()) + offset),
                             pmsg->size() - offset, payload, payloadLen) != EOK)) {
        NN_LOG_ERROR("SpliceMessage: the payload is too large.");
        return std::make_tuple(SpliceMessageResultType::ERROR, SER_SPLIT_INVALID_MSG, "");
    }

    // 最后一个包，拼包结束. 如果 totalLength 在网络传输中被修改，可能永远无法取
    // 等，依赖超时机制将这种异常 Msg 清除。
    if (offset + payloadLen == totalLength) {
        NN_LOG_DEBUG("SpliceMessage: complete! id " << msgId);

        // 由 std::shared_ptr 保证，pmsg 一定有效
        std::string msg = std::move(*pmsg);

        HcomServiceTimer* timer = nullptr;
        if (NN_UNLIKELY(mCtxStore->GetSeqNoAndRemove(incompleteMsg->first, timer) == SER_OK)) {
            timer->MarkFinished();
            timer->DeleteCallBack();
            timer->DecreaseRef();

            std::lock_guard<std::mutex> lock(mMsgReceivedMutex);
            mMsgReceived.erase(iter);
        }

        return std::make_tuple(SpliceMessageResultType::OK, SER_OK, std::move(msg));
    }
    return std::make_tuple(SpliceMessageResultType::INDETERMINATE, SER_OK, "");
}

SerResult HcomChannelImp::AsyncSendSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req,
    uint32_t fragmentNum, const Callback *done)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;

        extHeader.offset = segOffset;

        UBSHcomNetTransRequest transReq(reinterpret_cast<void *>(segAddr), segSize, sizeof(SerTransContext));

        // 用户回调函数 done 只在最后被调用一次。由于每次都创建了一个新的
        // callback，需要在 PostSend 失败时将 callback 删除。
        Callback *callback = UBSHcomNewCallback(
            [segIndex, fragmentNum, done](UBSHcomServiceContext &context) {
                NN_LOG_DEBUG("Run CB [" << (segIndex + 1) << "/" << fragmentNum << "], result " << context.Result());
                if (segIndex == fragmentNum - 1) {
                    const_cast<Callback *>(done)->Run(context);
                }
            },
            std::placeholders::_1);
        if (!callback) {
            NN_LOG_ERROR("Async send malloc callback failed");
            delete done;
            return SER_NEW_OBJECT_FAILED;
        }

        TimerCtx context{};
        auto result = PrepareTimerContext(callback, mOptions.twoSideTimeout, context);
        if (result != SER_OK) {
            NN_LOG_ERROR("Prepare timer context failed when sending [" << (segIndex + 1) << "/" << fragmentNum << "]");
            delete callback;
            delete done;
            return result;
        }

        SetServiceTransCtx(transReq.upCtxData, context.seqNo);
        uint32_t newSeqNo = context.seqNo;
        MarkOpCodeBySeqNo(newSeqNo, 0);

        UBSHcomNetTransOpInfo transOp(newSeqNo, mOptions.twoSideTimeout);
        NN_LOG_DEBUG("AsyncSendSplitWithWorkerPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin; ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << ", status="
                     << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        result = ep->PostSend(req.opcode, transReq, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
            sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("AsyncSendSplitWithWorkerPoll Send fragment [" << (segIndex + 1) << "/" << fragmentNum <<
                         "] failed");

            DestroyTimerContext(context);
            delete done;
            return result;
        }
        NN_LOG_DEBUG("AsyncSendSplitWithWorkerPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");
    }

    return SER_OK;
}

SerResult HcomChannelImp::AsyncSendInner(const UBSHcomRequest &req, const Callback *done)
{
    if (mOptions.selfPoll) {
        NN_LOG_ERROR("Failed to invoke async send with self poll, not support");
        delete done;
        return SER_INVALID_PARAM;
    }

    UBSHcomNetEndpoint *ep = nullptr;
    SerResult result = NextWorkerPollEp(ep);
    if (NN_UNLIKELY(SER_OK != result)) {
        delete done;
        return result;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size, true);
    if (fragmentNum > 1) {
        return AsyncSendSplitWithWorkerPoll(ep, req, fragmentNum, done);
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, sizeof(SerTransContext));
    uint32_t newSeqNo = 0;
    TimerCtx context {};
    result = PrepareTimerContext(const_cast<Callback *>(done), mOptions.twoSideTimeout, context);
    if (result != SER_OK) {
        delete done;
        return result;
    }
    SetServiceTransCtx(transReq.upCtxData, context.seqNo);

    // if rspCtx is valid, seqNo is changed now by mark
    newSeqNo = context.seqNo;
    MarkOpCodeBySeqNo(newSeqNo, 0);
    UBSHcomNetTransOpInfo transOp(newSeqNo, mOptions.twoSideTimeout);
    if (NN_LIKELY(transReq.size >= mRndvThreshold)) {
        result = RndvInner(ep, req, transOp, false);
    } else {
        NN_LOG_DEBUG("[Request Send] ------ channel id=" << mOptions.id << ", ep id=" << ep->Id() << ", seqNo=" <<
                     transOp.seqNo << ", status=" << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        result = ep->PostSend(req.opcode, transReq, transOp);
    }
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel async send failed " << result << " ep id " << ep->Id());
        DestroyTimerContext(context);
        return result;
    }
    return result;
}

SerResult HcomChannelImp::SyncSendSplitWithSelfPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req,
    uint32_t fragmentNum, uint32_t index)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;
        extHeader.offset = segOffset;

        UBSHcomNetTransRequest transReq(reinterpret_cast<void *>(segAddr), segSize, 0);
        UBSHcomNetTransOpInfo transOp(SelfPollNextSeqNo(), mOptions.twoSideTimeout);
        NN_LOG_DEBUG("SyncSendSplitWithSelfPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin; ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << ", status="
                     << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        auto result = ep->PostSend(req.opcode, transReq, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
                                   sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel SyncSendSplitWithSelfPoll failed " << result << " ep id " << ep->Id() << ", ["
                                                                     << (segIndex + 1) << "/" << fragmentNum << "]");
            ReleaseSelfPollEp(index);
            return result;
        }
        NN_LOG_DEBUG("SyncSendSplitWithSelfPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");

        int32_t timeout = (mOptions.twoSideTimeout == 0 ? -1 : static_cast<int32_t>(mOptions.twoSideTimeout));
        result = ep->WaitCompletion(timeout);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync send split wait complete failed " << result << " ep id " << ep->Id());
            ReleaseSelfPollEp(index);
            return result;
        }
    }

    ReleaseSelfPollEp(index);
    NN_LOG_DEBUG("[Request Send] ------  ep id=" << ep->Id() << ", multiple seq no, status="
                                                 << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::SUCCESS));
    return SER_OK;
}

SerResult HcomChannelImp::SyncSendWithSelfPoll(const UBSHcomRequest &req)
{
    UBSHcomNetEndpoint *ep = nullptr;
    uint32_t index = 0;
    auto result = AcquireSelfPollEp(ep, index, mOptions.twoSideTimeout);
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync send acquire ep failed " << result << " channel id " << mOptions.id);
        return result;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size);
    if (fragmentNum > 1) {
        return SyncSendSplitWithSelfPoll(ep, req, fragmentNum, index);
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, 0);
    UBSHcomNetTransOpInfo transOp(SelfPollNextSeqNo(), mOptions.twoSideTimeout);
    NN_LOG_DEBUG("[Request Send] ------ channel id=" << mOptions.id << ", ep id=" << ep->Id() << ", seqNo=" <<
                 transOp.seqNo << ", status=" << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
    result = ep->PostSend(req.opcode, transReq, transOp);
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync send failed " << result << " ep id " << ep->Id());
        ReleaseSelfPollEp(index);
        return result;
    }

    /* timeout = 0 will poll cq empty in self polling */
    int32_t timeout = (mOptions.twoSideTimeout == 0 ? -1 : static_cast<int32_t>(mOptions.twoSideTimeout));
    result = ep->WaitCompletion(timeout);
    ReleaseSelfPollEp(index);
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync send wait complete failed " << result << " ep id " << ep->Id());
        return result;
    }

    return SER_OK;
}

int32_t HcomChannelImp::Call(const UBSHcomRequest &req, UBSHcomResponse &rsp, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::Call" << ", channel id = " << mOptions.id <<
                 ", status = " << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::CALLED));
    VALIDATE_PARAM(Request, req);
    SerResult result = SER_OK;
    uint64_t timestamp = mOptions.twoSideTimeout < 0 ? UINT64_MAX : mOptions.twoSideTimeout + NetMonotonic::TimeSec();
    do {
        result = FlowControl(req.size, mOptions.twoSideTimeout, timestamp);
        if (NN_UNLIKELY(result != SER_OK)) {
            return result;
        }
        result = CallInner(req, rsp, done);
        if (NN_LIKELY(result == SER_OK)) {
            return SER_OK;
        } else if (result == SER_NEW_OBJECT_FAILED) {
            usleep(100UL);
            continue;
        } else {
            break;
        }
    } while (NetMonotonic::TimeSec() < timestamp);

    NN_LOG_ERROR("Failed to sync call " << result);
    return result;
}

SerResult HcomChannelImp::CallInner(const UBSHcomRequest &req, UBSHcomResponse &rsp, const Callback *done)
{
    if (done == nullptr) {
        return SyncCallInner(req, rsp);
    }
    return AsyncCallInner(req, done);
}

NResult HcomChannelImp::SendFds(int fds[], uint32_t len)
{
    NN_ASSERT_LOG_RETURN(mEpInfo != nullptr, SER_ERROR)
    NN_ASSERT_LOG_RETURN(mEpInfo->epArr[0] != nullptr, SER_ERROR)
    return mEpInfo->epArr[0]->SendFds(fds, len);
}

NResult HcomChannelImp::ReceiveFds(int fds[], uint32_t len, int32_t timeoutSec)
{
    NN_ASSERT_LOG_RETURN(mEpInfo != nullptr, SER_ERROR)
    NN_ASSERT_LOG_RETURN(mEpInfo->epArr[0] != nullptr, SER_ERROR)
    return mEpInfo->epArr[0]->ReceiveFds(fds, len, timeoutSec);
}

static void SyncCallCbForWorkerPoll(UBSHcomServiceContext &context, UBSHcomResponse *rsp,
    HcomServiceSelfSyncParam *syncParam)
{
    if (NN_UNLIKELY(rsp == nullptr || syncParam == nullptr)) {
        NN_LOG_ERROR("Failed to call SyncCallback as rspOpInfo, rsp or syncParam is null");
        return;
    }
    HcomServiceMessage message(context.MessageData(), context.MessageDataLen());
    syncParam->Result(SER_OK);

    do {
        rsp->errorCode = context.ErrorCode();
        if (NN_UNLIKELY(context.Result() != SER_OK)) {
            NN_LOG_ERROR("Sync call result " << context.Result() << " error");
            syncParam->Result(context.Result());
            break;
        }

        if (rsp->address != nullptr) {
            if (NN_UNLIKELY(message.size > rsp->size)) {
                NN_LOG_ERROR("Sync call check user prepare size " << rsp->size << " less than receive size " <<
                    message.size);
                syncParam->Result(SER_RSP_SIZE_TOO_SMALL);
                break;
            }
            if (NN_UNLIKELY(memcpy_s(rsp->address, rsp->size, message.data, message.size) != SER_OK)) {
                NN_LOG_ERROR("Sync call failed to copy data");
                syncParam->Result(SER_INVALID_PARAM);
                break;
            }
        } else {
            rsp->address = malloc(message.size);
            if (rsp->address == nullptr) {
                NN_LOG_ERROR("Sync call malloc data size " << message.size << " failed");
                syncParam->Result(SER_NEW_MESSAGE_DATA_FAILED);
                break;
            }
            if (NN_UNLIKELY(memcpy_s(rsp->address, message.size, message.data, message.size) != SER_OK)) {
                free(rsp->address);
                rsp->address = nullptr;
                NN_LOG_ERROR("Sync call failed to copy data");
                syncParam->Result(SER_INVALID_PARAM);
                break;
            }
        }
        rsp->size = message.size;
    } while (false);

    syncParam->Signal();
}

SerResult HcomChannelImp::SyncCallInner(const UBSHcomRequest &req, UBSHcomResponse &rsp, uint32_t timeOut)
{
    if (mOptions.selfPoll) {
        return SyncCallWithSelfPoll(req, rsp);
    }

    UBSHcomNetEndpoint *ep = nullptr;
    auto result = NextWorkerPollEp(ep);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size, true);
    if (fragmentNum > 1) {
        return SyncCallSplitWithWorkerPoll(ep, req, fragmentNum, rsp);
    }

    /* worker poll mode */
    HcomServiceSelfSyncParam syncParam {};
    Callback *newCallback = UBSHcomNewCallback(SyncCallCbForWorkerPoll, std::placeholders::_1, &rsp, &syncParam);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("Sync call malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }

    TimerCtx context {};
    result = PrepareTimerContext(newCallback, timeOut == 0 ? mOptions.twoSideTimeout : timeOut, context);
    if (result != SER_OK) {
        delete newCallback;
        return result;
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, sizeof(SerTransContext));
    SetServiceTransCtx(transReq.upCtxData, context.seqNo, false);

    MarkOpCodeBySeqNo(context.seqNo, 0);
    UBSHcomNetTransOpInfo transOp(context.seqNo, mOptions.twoSideTimeout);
    if (NN_LIKELY(transReq.size >= mRndvThreshold)) {
        result = RndvInner(ep, req, transOp, true);
    } else {
        result = ep->PostSend(req.opcode, transReq, transOp);
    }
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync call send failed " << result << " ep id " << ep->Id());
        DestroyTimerContext(context);
        return result;
    }

    syncParam.Wait();
    return syncParam.Result();
}

SerResult HcomChannelImp::SyncCallSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req,
    uint32_t fragmentNum, UBSHcomResponse &rsp)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    HcomServiceSelfSyncParam syncParam{};
    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;
        extHeader.offset = segOffset;

        Callback *newCallback = UBSHcomNewCallback(SyncCallCbForWorkerPoll, std::placeholders::_1, &rsp, &syncParam);
        if (NN_UNLIKELY(newCallback == nullptr)) {
            NN_LOG_ERROR("Sync call split malloc callback failed");
            return SER_NEW_OBJECT_FAILED;
        }

        Callback *cb = UBSHcomNewCallback(
            [segIndex, fragmentNum, newCallback](UBSHcomServiceContext &context) {
                NN_LOG_DEBUG("Run CB [" << (segIndex + 1) << "/" << fragmentNum << "], result " << context.Result());
                if (segIndex == fragmentNum - 1) {
                    const_cast<Callback *>(newCallback)->Run(context);
                }
            },
                std::placeholders::_1);
        if (!cb) {
            NN_LOG_ERROR("Sync call split malloc callback failed");
            delete newCallback;
            return SER_NEW_OBJECT_FAILED;
        }

        TimerCtx context{};
        auto result = PrepareTimerContext(cb, mOptions.twoSideTimeout, context);
        if (result != SER_OK) {
            NN_LOG_ERROR("Prepare timer context failed when sending [" << (segIndex + 1) << "/" << fragmentNum << "]");
            delete cb;
            delete newCallback;
            return result;
        }

        UBSHcomNetTransRequest transReq(reinterpret_cast<void *>(segAddr), segSize, sizeof(SerTransContext));
        SetServiceTransCtx(transReq.upCtxData, context.seqNo, segIndex != fragmentNum - 1);

        uint32_t newSeqNo = context.seqNo;
        MarkOpCodeBySeqNo(newSeqNo, 0);
        UBSHcomNetTransOpInfo transOp(newSeqNo, mOptions.twoSideTimeout);
        NN_LOG_DEBUG("SyncCallSplitWithWorkerPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin;ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << " ,opCode = " << req.opcode
                     << ", status=" << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        result = ep->PostSend(req.opcode, transReq, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
            sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("SyncCallSplitWithWorkerPoll Send fragment [" << (segIndex + 1) << "/" << fragmentNum <<
                         "] failed");
            DestroyTimerContext(context);
            delete newCallback;
            return result;
        }
        NN_LOG_DEBUG("SyncCallSplitWithWorkerPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");
    }

    syncParam.Wait();
    return syncParam.Result();
}

SerResult HcomChannelImp::RndvInner(UBSHcomNetEndpoint *ep, const UBSHcomRequest &req,
    UBSHcomNetTransOpInfo &transOp, bool isCall)
{
    SerResult result = SER_OK;
    PgTable *pgTable = reinterpret_cast<PgTable *>(mPgtable);
    // pgTable 根据地址查询start addr和end addr
    PgtAddress add = reinterpret_cast<PgtAddress>(req.address);
    PgtAddress reqEndAdd = reinterpret_cast<PgtAddress>(req.address) + req.size - NN_NO1;

    PgtRegion *pgtRegion = pgTable->Lookup(add);
    if (pgtRegion == nullptr || !(pgtRegion->start <= add && reqEndAdd < pgtRegion->end)) {
        NN_LOG_WARN("Unable to lookUp address in pgTable or req address is out of range, so not use rndv send ");
        UBSHcomNetTransRequest transReq(req.address, req.size, sizeof(SerTransContext));
        SetServiceTransCtx(transReq.upCtxData, transOp.seqNo, !isCall);
        result = ep->PostSend(req.opcode, transReq, transOp);
    } else {
        UBSHcomRequest newReq{};
        newReq.address = req.address;
        newReq.size = req.size;
        newReq.opcode = req.opcode;
        // 根据起始地址查找lKey
        newReq.key = pgtRegion->key;

        HcomServiceRndvMessage rndvMessage(mConnectTimestamp.GetRemoteTimestamp(mOptions.twoSideTimeout), newReq);
        UBSHcomNetTransRequest transReq(const_cast<void *>(reinterpret_cast<const void *>(&rndvMessage)),
            sizeof(HcomServiceRndvMessage), sizeof(SerTransContext));
        // RNDV请求 对端必须reply 不区分send和Call
        SetServiceTransCtx(transReq.upCtxData, transOp.seqNo, false);
        result = ep->PostSend(ServiceV2PrivateOpcode::RNDV_CALL_OP_V2, transReq, transOp);
    }
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync call Rndv send failed " << result << " ep id " << ep->Id());
    }
    return result;
}

static SerResult SyncCallCbForSelfPoll(UBSHcomNetResponseContext &ctx, UBSHcomResponse &rsp)
{
    void *data = ctx.Message()->Data();
    uint32_t dataLength = ctx.Message()->DataLen();

    UBSHcomNetTransHeader header = ctx.Header();
    rsp.errorCode = header.errorCode;

    if (rsp.address != nullptr) {
        if (dataLength <= rsp.size) {
            if (NN_UNLIKELY(memcpy_s(rsp.address, rsp.size, data, dataLength) != SER_OK)) {
                NN_LOG_ERROR("Failed to copy data");
                return SER_INVALID_PARAM;
            }
        } else {
            NN_LOG_ERROR("Sync call self poll check user prepare size " << rsp.size << " less than receive size " <<
                dataLength);
            return SER_RSP_SIZE_TOO_SMALL;
        }
    } else {
        rsp.address = malloc(dataLength);
        if (rsp.address == nullptr) {
            NN_LOG_ERROR("Sync call self poll malloc data size " << dataLength << " failed");
            return SER_NEW_MESSAGE_DATA_FAILED;
        }
        if (NN_UNLIKELY(memcpy_s(rsp.address, dataLength, data, dataLength) != SER_OK)) {
            free(rsp.address);
            rsp.address = nullptr;
            NN_LOG_ERROR("Failed to sync callback by copy data err");
            return SER_INVALID_PARAM;
        }
    }
    rsp.size = dataLength;
    return SER_OK;
}

SerResult HcomChannelImp::SyncCallWithSelfPoll(const UBSHcomRequest &req, UBSHcomResponse &rsp)
{
    UBSHcomNetEndpoint *ep = nullptr;
    uint32_t index = 0;
    auto ret = AcquireSelfPollEp(ep, index, mOptions.twoSideTimeout);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Channel sync call acquire ep failed " << ret << " channel id " << mOptions.id);
        return ret;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size);
    if (fragmentNum > 1) {
        ret = SyncCallSplitWithSelfPoll(ep, req, fragmentNum, index, rsp);
        ReleaseSelfPollEp(index);
        return ret;
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, 0);
    UBSHcomNetTransOpInfo transOp(SelfPollNextSeqNo(), mOptions.twoSideTimeout);
    ret = ep->PostSend(req.opcode, transReq, transOp);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Channel sync call failed " << ret << " ep id " << ep->Id());
        ReleaseSelfPollEp(index);
        return ret;
    }

    /* timeout = 0 will poll cq empty in self polling */
    int32_t timeout = (mOptions.twoSideTimeout == 0 ? -1 : static_cast<int32_t>(mOptions.twoSideTimeout));
    ret = ep->WaitCompletion(timeout);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Channel sync call wait complete failed " << ret << " ep id " << ep->Id());
        ReleaseSelfPollEp(index);
        return ret;
    }

    UBSHcomNetResponseContext ctx;
    ret = ep->Receive(timeout, ctx);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Channel sync call receive failed " << ret << " ep id " << ep->Id());
        ReleaseSelfPollEp(index);
        return ret;
    }

    ret = SyncCallCbForSelfPoll(ctx, rsp);
    ReleaseSelfPollEp(index);
    if (NN_UNLIKELY(ret != SER_OK)) {
        return ret;
    }

    return SER_OK;
}

static SerResult SyncCallbackWithSelfPoll(void *data, uint32_t dataLen, const UBSHcomNetTransHeader &header,
    UBSHcomResponse &rsp)
{
    rsp.errorCode = header.errorCode;
    if (rsp.address != nullptr) {
        if (dataLen <= rsp.size) {
            if (NN_UNLIKELY(memcpy_s(rsp.address, rsp.size, data, dataLen) != SER_OK)) {
                NN_LOG_ERROR("Failed to copy data");
                return SER_INVALID_PARAM;
            }
        } else {
            NN_LOG_ERROR("Sync call self poll check user prepare size " << rsp.size << " less than receive size " <<
                dataLen);
            return SER_RSP_SIZE_TOO_SMALL;
        }
    } else {
        rsp.address = malloc(dataLen);
        if (rsp.address == nullptr) {
            NN_LOG_ERROR("Sync call self poll malloc data size " << dataLen << " failed");
            return SER_NEW_MESSAGE_DATA_FAILED;
        }
        if (NN_UNLIKELY(memcpy_s(rsp.address, dataLen, data, dataLen) != SER_OK)) {
            free(rsp.address);
            rsp.address = nullptr;
            NN_LOG_ERROR("Failed to sync callback by copy data err");
            return SER_INVALID_PARAM;
        }
    }
    rsp.size = dataLen;
    return SER_OK;
}

SerResult HcomChannelImp::SyncCallSplitWithSelfPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req,
    uint32_t fragmentNum, uint32_t index, UBSHcomResponse &rsp)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    const int32_t timeout = (mOptions.twoSideTimeout == 0 ? -1 : static_cast<int32_t>(mOptions.twoSideTimeout));
    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;
        extHeader.offset = segOffset;

        UBSHcomNetTransRequest msg(reinterpret_cast<void *>(segAddr), segSize, 0);
        UBSHcomNetTransOpInfo transOp(SelfPollNextSeqNo(), mOptions.twoSideTimeout);
        NN_LOG_DEBUG("SyncCallSplitWithSelfPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin;ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << ", opCode = " << req.opcode
                     << ", status=" << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        auto result = ep->PostSend(req.opcode, msg, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
            sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel SyncCallSplitWithSelfPoll failed " << result << " ep id " << ep->Id() << ", ["
                                                                     << (segIndex + 1) << "/" << fragmentNum << "]");
            return result;
        }
        NN_LOG_DEBUG("SyncCallSplitWithSelfPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");

        result = ep->WaitCompletion(timeout);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync call split wait complete failed " << result << " ep id " << ep->Id());
            return result;
        }
    }

    // 同步方式拼包
    std::string acc;
    void *data;
    uint32_t dataLen;
    UBSHcomNetResponseContext ctx;
    auto result = SyncSpliceMessage(ctx, ep, timeout, acc, data, dataLen);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    // 对端回复的每一个小包，它们的 Header() 都是相同的.
    result = SyncCallbackWithSelfPoll(data, dataLen, ctx.Header(), rsp);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

SerResult HcomChannelImp::AsyncCallInner(const UBSHcomRequest &req, const Callback *done)
{
    if (mOptions.selfPoll) {
        NN_LOG_ERROR("Failed to invoke async call with self poll, not support");
        delete done;
        return SER_INVALID_PARAM;
    }

    UBSHcomNetEndpoint *ep = nullptr;
    auto result = NextWorkerPollEp(ep);
    if (NN_UNLIKELY(result != SER_OK)) {
        delete done;
        return result;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size, true);
    if (fragmentNum > 1) {
        return AsyncCallSplitWithWorkerPoll(ep, req, fragmentNum, done);
    }

    TimerCtx context {};
    result = PrepareTimerContext(const_cast<Callback *>(done), mOptions.twoSideTimeout, context);
    if (result != SER_OK) {
        delete done;
        return result;
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, sizeof(SerTransContext));
    SetServiceTransCtx(transReq.upCtxData, context.seqNo, false);

    MarkOpCodeBySeqNo(context.seqNo, 0);
    UBSHcomNetTransOpInfo transOp(context.seqNo, mOptions.twoSideTimeout);
    if (NN_LIKELY(transReq.size >= mRndvThreshold)) {
        result = RndvInner(ep, req, transOp, true);
    } else {
        result = ep->PostSend(req.opcode, transReq, transOp);
    }

    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel async call send failed " << result << " ep id " << ep->Id());
        DestroyTimerContext(context);
        return result;
    }
    return SER_OK;
}

SerResult HcomChannelImp::AsyncCallSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req,
    uint32_t fragmentNum, const Callback *done)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;
        extHeader.offset = segOffset;

        Callback *cb = UBSHcomNewCallback(
            [segIndex, fragmentNum, done](UBSHcomServiceContext &context) {
                NN_LOG_DEBUG("Run CB [" << (segIndex + 1) << "/" << fragmentNum << "], result "
                                        << context.Result());
                if (segIndex == fragmentNum - 1) {
                    const_cast<Callback *>(done)->Run(context);
                }
            },
            std::placeholders::_1);
        if (!cb) {
            NN_LOG_ERROR("AsyncCallInner malloc callback failed");
            delete done;
            return SER_NEW_OBJECT_FAILED;
        }

        TimerCtx context{};
        auto result = PrepareTimerContext(cb, mOptions.twoSideTimeout, context);
        if (result != SER_OK) {
            NN_LOG_ERROR("Prepare timer context failed when sending [" << (segIndex + 1) << "/" << fragmentNum << "]");
            delete cb;
            delete done;
            return result;
        }

        UBSHcomNetTransRequest transReq(reinterpret_cast<void *>(segAddr), segSize, sizeof(SerTransContext));
        SetServiceTransCtx(transReq.upCtxData, context.seqNo, segIndex != fragmentNum - 1);

        uint32_t newSeqNo = context.seqNo;
        MarkOpCodeBySeqNo(newSeqNo, 0);
        UBSHcomNetTransOpInfo transOp(newSeqNo, mOptions.twoSideTimeout);
        NN_LOG_DEBUG("AsyncCallSplitWithWorkerPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin;ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << " ,opCode = " << req.opcode
                     << ", status=" << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        result = ep->PostSend(req.opcode, transReq, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
            sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("AsyncCallSplitWithWorkerPoll Send fragment [" << (segIndex + 1) << "/" << fragmentNum <<
                         "] failed");
            DestroyTimerContext(context);
            delete done;
            return result;
        }
        NN_LOG_DEBUG("AsyncCallSplitWithWorkerPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");
    }

    return SER_OK;
}

int32_t HcomChannelImp::Reply(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::Reply" << ", channel id = " << mOptions.id <<
                 ", status = " << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::CALLED));
    VALIDATE_PARAM(Reply, ctx, req, mOptions.selfPoll);
    SerResult ret = SER_OK;
    uint64_t timestamp = mOptions.twoSideTimeout < 0 ? UINT64_MAX : mOptions.twoSideTimeout + NetMonotonic::TimeSec();
    do {
        ret = FlowControl(req.size, mOptions.twoSideTimeout, timestamp);
        if (NN_UNLIKELY(ret != SER_OK)) {
            return ret;
        }
        ret = ReplyInner(ctx, req, done);
        if (NN_LIKELY(ret == SER_OK)) {
            return SER_OK;
        } else if (ret == SER_NEW_OBJECT_FAILED) { // do later::add retry result code
            usleep(100UL);
            continue;
        } else {
            break;
        }
    } while (NetMonotonic::TimeSec() < timestamp);
    NN_LOG_WARN("Failed to reply, ret code: " << ret);
    return ret;
}

SerResult HcomChannelImp::ReplyInner(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req, const Callback *done)
{
    if (done == nullptr) {
        return SyncReplyInner(ctx, req);
    }
    return AsyncReplyInner(ctx, req, done);
}

SerResult HcomChannelImp::SyncReplyInner(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req)
{
    SerResult res = SER_OK;
    UBSHcomNetEndpoint *ep = nullptr;
    res = ResponseWorkerPollEp(ctx.rspCtx, ep);
    if (NN_UNLIKELY(res != SER_OK)) {
        NN_LOG_ERROR("Failed to select ep " << res);
        return res;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size);
    if (fragmentNum > 1) {
        return SyncReplySplitWithWorkerPoll(ctx, ep, req, fragmentNum);
    }

    HcomServiceSelfSyncParam syncParam {};
    Callback *newCallback = UBSHcomNewCallback(
        [&syncParam](UBSHcomServiceContext &context) {
            if (NN_UNLIKELY(context.Result() != SER_OK)) {
                NN_LOG_WARN("Channel sync reply inner callback failed " << context.Result());
            }
            syncParam.Result(context.Result());
            syncParam.Signal();
        },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("Sync send callback is nullptr");
        return SER_NEW_OBJECT_FAILED;
    }

    TimerCtx context {};
    auto result = PrepareTimerContext(newCallback, mOptions.twoSideTimeout, context);
    if (result != SER_OK) {
        delete newCallback;
        return result;
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, sizeof(SerTransContext));
    SetServiceTransCtx(transReq.upCtxData, context.seqNo);

    uint32_t userSeqNo = context.seqNo;
    MarkOpCodeBySeqNo(userSeqNo, ctx.rspCtx, mRespOriginalSeqNo);
    UBSHcomNetTransOpInfo transOp(userSeqNo, mOptions.twoSideTimeout, ctx.errorCode, 0);
    result = ep->PostSend(req.opcode, transReq, transOp);
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync send failed " << result << " ep id " << ep->Id());
        DestroyTimerContext(context);
        return result;
    }

    syncParam.Wait();
    return syncParam.Result();
}

SerResult HcomChannelImp::SyncReplySplitWithWorkerPoll(const UBSHcomReplyContext &ctx, UBSHcomNetEndpoint *&ep,
    const UBSHcomRequest &req, uint32_t fragmentNum)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    HcomServiceSelfSyncParam syncParam{};
    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;
        extHeader.offset = segOffset;

        Callback *newCallback = UBSHcomNewCallback(
            [segIndex, fragmentNum, &syncParam](UBSHcomServiceContext &context) {
                if (NN_UNLIKELY(context.Result() != SER_OK)) {
                    syncParam.Result(context.Result());
                    NN_LOG_ERROR("Channel sync reply inner callback failed " << context.Result() << " when sending ["
                                                                             << (segIndex + 1) << "/" << fragmentNum
                                                                             << "]");
                }

                if (segIndex == fragmentNum - 1) {
                    syncParam.Signal();
                }
            },
            std::placeholders::_1);

        if (NN_UNLIKELY(!newCallback)) {
            NN_LOG_ERROR("Sync reply malloc callback failed");
            return SER_NEW_OBJECT_FAILED;
        }

        TimerCtx context{};
        SerResult result = PrepareTimerContext(newCallback, mOptions.twoSideTimeout, context);
        if (result != SER_OK) {
            delete newCallback;
            return result;
        }

        UBSHcomNetTransRequest transReq(reinterpret_cast<void *>(segAddr), segSize, sizeof(SerTransContext));
        SetServiceTransCtx(transReq.upCtxData, context.seqNo);
        uint32_t userSeqNo = context.seqNo;
        MarkOpCodeBySeqNo(userSeqNo, ctx.rspCtx, mRespOriginalSeqNo);
        UBSHcomNetTransOpInfo transOp(userSeqNo, mOptions.twoSideTimeout, ctx.errorCode, 0);
        NN_LOG_DEBUG("SyncReplySplitWithWorkerPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin; ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << ", status="
                     << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM)
                     << " req.opcode: " << req.opcode);
        result = ep->PostSend(req.opcode, transReq, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
            sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync reply failed " << result << " ep id " << ep->Id());
            DestroyTimerContext(context);
            return result;
        }

        NN_LOG_DEBUG("SyncReplySplitWithWorkerPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");
    }

    syncParam.Wait();
    return syncParam.Result();
}

SerResult HcomChannelImp::AsyncReplyInner(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req,
    const Callback *done)
{
    SerResult res = SER_OK;
    UBSHcomNetEndpoint *ep = nullptr;
    res = ResponseWorkerPollEp(ctx.rspCtx, ep);
    if (NN_UNLIKELY(res != SER_OK)) {
        NN_LOG_ERROR("Failed to select ep " << res);
        delete done;
        return res;
    }

    const uint32_t fragmentNum = EstimateFragmentNum(req.size);
    if (fragmentNum > 1) {
        return AsyncReplySplitWithWorkerPoll(ctx, ep, req, fragmentNum, done);
    }

    UBSHcomNetTransRequest transReq(req.address, req.size, sizeof(SerTransContext));
    uint32_t newSeqNo = 0;
    SetServiceTransCtx(transReq.upCtxData, const_cast<Callback *>(done));
    MarkOpCodeBySeqNo(newSeqNo, ctx.rspCtx, mRespOriginalSeqNo);
    UBSHcomNetTransOpInfo transOp(newSeqNo, mOptions.twoSideTimeout, ctx.errorCode, 0);
    return ep->PostSend(req.opcode, transReq, transOp);
}

SerResult HcomChannelImp::AsyncReplySplitWithWorkerPoll(const UBSHcomReplyContext &ctx, UBSHcomNetEndpoint *&ep,
    const UBSHcomRequest &req, uint32_t fragmentNum, const Callback *done)
{
    UBSHcomFragmentHeader extHeader;
    extHeader.msgId = {ep->Id(), ep->NextSeq()};
    extHeader.totalLength = req.size;
    extHeader.offset = 0;

    for (uint32_t segIndex = 0; segIndex < fragmentNum; ++segIndex) {
        const uint32_t segOffset = segIndex * mUserSplitSendThreshold;
        const uint64_t segSize = std::min(mUserSplitSendThreshold, req.size - segOffset);
        const uintptr_t segAddr = reinterpret_cast<uintptr_t>(req.address) + segOffset;
        extHeader.offset = segOffset;

        Callback *cb = UBSHcomNewCallback(
            [segIndex, fragmentNum, done](UBSHcomServiceContext &context) {
                NN_LOG_DEBUG("Run CB [" << (segIndex + 1) << "/" << fragmentNum << "], result " << context.Result());
                if (segIndex == fragmentNum - 1) {
                    const_cast<Callback *>(done)->Run(context);
                }
            },
            std::placeholders::_1);
        if (!cb) {
            NN_LOG_ERROR("Async send malloc callback failed");
            delete done;
            return SER_NEW_OBJECT_FAILED;
        }

        TimerCtx context{};
        auto result = PrepareTimerContext(cb, mOptions.twoSideTimeout, context);
        if (result != SER_OK) {
            NN_LOG_ERROR("Prepare timer context failed when sending [" << (segIndex + 1) << "/" << fragmentNum << "]");
            delete cb;
            delete done;
            return result;
        }

        UBSHcomNetTransRequest transReq(reinterpret_cast<void *>(segAddr), segSize, sizeof(SerTransContext));
        SetServiceTransCtx(transReq.upCtxData, context.seqNo);
        uint32_t newSeqNo = 0;
        MarkOpCodeBySeqNo(newSeqNo, ctx.rspCtx, mRespOriginalSeqNo);
        UBSHcomNetTransOpInfo transOp(newSeqNo, mOptions.twoSideTimeout, ctx.errorCode, 0);
        NN_LOG_DEBUG("AsyncReplySplitWithWorkerPoll fragment ["
                     << (segIndex + 1) << "/" << fragmentNum << "] begin; ep id=" << ep->Id()
                     << ", seqNo=" << transOp.seqNo << ", status="
                     << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::IN_HCOM));
        result = ep->PostSend(req.opcode, transReq, transOp, UBSHcomExtHeaderType::FRAGMENT, &extHeader,
            sizeof(extHeader));
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("AsyncReplySplitWithWorkerPoll Send fragment [" << (segIndex + 1) << "/" << fragmentNum <<
                         "] failed");

            DestroyTimerContext(context);
            delete done;
            return result;
        }
        NN_LOG_DEBUG("AsyncReplySplitWithWorkerPoll fragment [" << (segIndex + 1) << "/" << fragmentNum << "] end");
    }

    return SER_OK;
}

SerResult HcomChannelImp::OneSideSyncWithSelfPoll(const UBSHcomOneSideRequest &request, bool isWrite)
{
    SerResult result = SER_OK;
    uint32_t size = request.size;
    uint32_t offset = 0;
    uint32_t remain = request.size;
    uint16_t multiNum = (mOptions.enableMultiRail && request.size > mOptions.multiRailThresh) ? mDriverNum : 1;
    if (mOptions.enableMultiRail && request.size > mOptions.multiRailThresh) {
        NN_LOG_INFO("Multirail not supported in oneside sync with self poll, using single rail.");
    }
    for (uint32_t i = 0; i < multiNum; i++) {
        UBSHcomNetEndpoint *ep = nullptr;
        uint32_t index = 0;
        result = AcquireSelfPollEp(ep, index, mOptions.oneSideTimeout, i);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync read acquire ep failed " << result << " channel id " << mOptions.id <<
                " in rail " << i);
            return result;
        }

        CalculateOffsetAndSize(request, ep, remain, offset, size);
        UBSHcomNetTransRequest req(request.lAddress + offset, request.rAddress + offset,
            request.lKey.keys[ep->GetDevIndex()], request.rKey.keys[ep->GetPeerDevIndex()], size, 0);
        req.srcSeg = reinterpret_cast<void *>(request.lKey.tokens[ep->GetDevIndex()]);
        req.dstSeg = reinterpret_cast<void *>(request.rKey.tokens[ep->GetDevIndex()]);
        if (isWrite) {
            result = ep->PostWrite(req);
        } else {
            result = ep->PostRead(req);
        }
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync read failed " << result << " ep id " << ep->Id() << " in rail " << i);
            ReleaseSelfPollEp(index);
            return result;
        }
        /*  The PostRead operation uses a thread-local variable to record the RDMA context for the current thread.
            Thus, the next PostRead operation must be performed after executing WaitCompletion. */
        result = ep->WaitCompletion(mOptions.oneSideTimeout == 0 ? -1 : mOptions.oneSideTimeout);
        ReleaseSelfPollEp(index);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync read wait complete failed " << result << " ep id " << ep->Id());
            return result;
        }
    }
    return SER_OK;
}

SerResult HcomChannelImp::PrepareCallback(HcomServiceSelfSyncParam& syncParam, TimerCtx &syncContext)
{
    Callback *newCallback = UBSHcomNewCallback([&syncParam](UBSHcomServiceContext &context) {
            if (NN_UNLIKELY(context.Result() != SER_OK)) {
                NN_LOG_ERROR("Prepare callback failed " << context.Result());
            }
            syncParam.Result(context.Result());
            syncParam.Signal();
        },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("Sync read callback is nullptr");
        return SER_NEW_OBJECT_FAILED;
    }

    SerResult result = PrepareTimerContext(newCallback, mOptions.oneSideTimeout, syncContext);
    if (result != SER_OK) {
        delete newCallback;
        return result;
    }
    return SER_OK;
}


SerResult HcomChannelImp::OneSideSyncWithWorkerPoll(const UBSHcomOneSideRequest &request, bool isWrite)
{
    SerResult ret = SER_OK;
    uint32_t size = request.size;
    uint32_t offset = 0;
    uint32_t remain = request.size;
    uint16_t multiNum = (mOptions.enableMultiRail && request.size > mOptions.multiRailThresh) ? mDriverNum : 1;
    std::vector<HcomServiceSelfSyncParam> paramVec(multiNum, HcomServiceSelfSyncParam());
    uint32_t idx = 0;
    NN_LOG_DEBUG("Multirail enabled: " << (multiNum != 1) << ", rail num: " << multiNum);
    do {
        UBSHcomNetEndpoint *ep = nullptr;
        auto result = NextWorkerPollEp(ep, idx);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("NextWorkerPollEp failed, result:" << result <<", idx: "<< idx);
            ret = result;
            break;
        }
        TimerCtx syncContext {};
        result = PrepareCallback(paramVec[idx], syncContext);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("PrepareCallback failed, result:" << result << ", idx:" << idx);
            ret = result;
            break;
        }

        CalculateOffsetAndSize(request, ep, remain, offset, size);
        UBSHcomNetTransRequest req(request.lAddress + offset, request.rAddress + offset,
            request.lKey.keys[ep->GetDevIndex()], request.rKey.keys[ep->GetPeerDevIndex()], size,
            sizeof(SerTransContext));
        req.srcSeg = reinterpret_cast<void *>(request.lKey.tokens[ep->GetDevIndex()]);
        req.dstSeg = reinterpret_cast<void *>(request.rKey.tokens[ep->GetDevIndex()]);
        SetServiceTransCtx(req.upCtxData, syncContext.seqNo);

        if (isWrite) {
            result = ep->PostWrite(req);
        } else {
            result = ep->PostRead(req);
        }
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel sync oneside failed " << result << " ep id " << ep->Id() << " in rail " << idx);
            DestroyTimerContext(syncContext);
            NN_LOG_ERROR("ep Post failed: " << result << ", idx:" << idx);
            ret = result;
            break;
        }
        ++idx;
    } while (idx < multiNum);

    SerResult cbRet = SER_OK;
    for (uint32_t i = 0; i < idx; i++) {
        paramVec[i].Wait();
        if (NN_UNLIKELY((paramVec[i]).Result() != NN_OK)) {
            cbRet = (paramVec[i]).Result();
        }
    }

    // if ret is not ok, can not return before sem_wait because callback need paramVec, it can not free
    if (cbRet != SER_OK || ret != SER_OK) {
        NN_LOG_ERROR("callback or multi error, cbRet:" << cbRet << ",ret:" << ret);
        return cbRet != SER_OK ? cbRet : ret;
    }
    return SER_OK;
}

Callback *HcomChannelImp::GetAsyncCB(uint16_t multiNum, const Callback *done)
{
    if (multiNum > NN_NO1) {
        Callback *newCallback = new (std::nothrow) AsyncClosureCallback(const_cast<Callback *>(done), multiNum);
        if (newCallback == nullptr) {
            NN_LOG_ERROR("Failed to create new callback");
            return nullptr;
        }
        return newCallback;
    } else {
        return const_cast<Callback *>(done);
    }
}

void HcomChannelImp::ProcessRemainCallback(Callback *cb, uint32_t remainNums)
{
    if (NN_UNLIKELY(cb == nullptr)) {
        return;
    }

    UBSHcomServiceContext context{};
    context.mCh.Set(nullptr);
    context.mResult = SER_ERROR;
    context.mEpIdxInCh = 0;
    context.mSeqNo = 0;
    context.mDataType = UBSHcomServiceContext::INVALID_DATA;
    context.mDataLen = 0;
    context.mData = nullptr;
    context.mOpType = UBSHcomRequestContext::NN_INVALID_OP_TYPE;
    context.mOpCode = NN_NO1024;

    for (uint32_t i = 0; i < remainNums; i++) {
        cb->Run(context);
    }
}

SerResult HcomChannelImp::OneSideAsyncWithWorkerPoll(const UBSHcomOneSideRequest &request, const Callback *done,
    bool isWrite)
{
    uint32_t size = request.size;
    uint32_t offset = 0;
    uint32_t remain = request.size;
    uint16_t multiNum = (mOptions.enableMultiRail && request.size > mOptions.multiRailThresh) ? mDriverNum : 1;

    Callback *cb = GetAsyncCB(multiNum, done);
    if (NN_UNLIKELY(cb == nullptr)) {
        NN_LOG_ERROR("Get OneSideCB failed ");
        return SER_NEW_OBJECT_FAILED;
    }

    NN_LOG_DEBUG("Multirail enabled: " << (multiNum != 1) << ", rail num: " << multiNum);
    for (uint32_t i = 0; i < multiNum; i++) {
        UBSHcomNetEndpoint *ep = nullptr;
        auto result = NextWorkerPollEp(ep, i);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Get Ep failed " << result);
            ProcessRemainCallback(cb, multiNum - i);
            return result;
        }

        TimerCtx readContext {};
        result = PrepareTimerContext(cb, mOptions.oneSideTimeout, readContext);
        if (result != SER_OK) {
            NN_LOG_ERROR("PrepareTimerContext failed " << result << " in rail " << i);
            ProcessRemainCallback(cb, multiNum - i);
            return result;
        }

        CalculateOffsetAndSize(request, ep, remain, offset, size);
        UBSHcomNetTransRequest req(request.lAddress + offset, request.rAddress + offset,
            request.lKey.keys[ep->GetDevIndex()], request.rKey.keys[ep->GetPeerDevIndex()], size,
            sizeof(SerTransContext));
        req.srcSeg = reinterpret_cast<void *>(request.lKey.tokens[ep->GetDevIndex()]);
        req.dstSeg = reinterpret_cast<void *>(request.rKey.tokens[ep->GetDevIndex()]);
        SetServiceTransCtx(req.upCtxData, readContext.seqNo);

        if (isWrite) {
            result = ep->PostWrite(req);
        } else {
            result = ep->PostRead(req);
        }
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel async read failed " << result << " ep id " << ep->Id() << " in rail " << i);
            DestroyTimerContext(readContext);
            return result;
        }
    }
    return SER_OK;
}

SerResult HcomChannelImp::OneSideInner(const UBSHcomOneSideRequest &request, const Callback *done, bool isWrite)
{
    if (mOptions.selfPoll) {
        if (done == nullptr) {
            return OneSideSyncWithSelfPoll(request, isWrite);
        } else {
            NN_LOG_ERROR("Failed to invoke async one side op with self poll, not supported");
            return SER_INVALID_PARAM;
        }
    } else {
        if (done == nullptr) {
            return OneSideSyncWithWorkerPoll(request, isWrite);
        } else {
            return OneSideAsyncWithWorkerPoll(request, done, isWrite);
        }
    }
    return SER_INVALID_PARAM;
}

int32_t HcomChannelImp::Put(const UBSHcomOneSideRequest &req, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::Put" << ", channel id = " << mOptions.id <<
                 ", status = " << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::CALLED));
    VALIDATE_PARAM(OneSideRequest, req);
    SerResult ret = SER_OK;
    uint64_t timestamp = mOptions.oneSideTimeout < 0 ? UINT64_MAX : mOptions.oneSideTimeout + NetMonotonic::TimeSec();
    do {
        ret = FlowControl(req.size, mOptions.oneSideTimeout, timestamp);
        if (NN_UNLIKELY(ret != SER_OK)) {
            return ret;
        }

        NetTrace::TraceBegin(CHANNEL_WRITE);
        ret = OneSideInner(req, done, true);
        NetTrace::TraceEnd(CHANNEL_WRITE, ret);
        if (NN_LIKELY(ret == SER_OK)) {
            return SER_OK;
        } else if (ret == SER_NEW_OBJECT_FAILED) { // do later::add retry result code
            usleep(100UL);
            continue;
        } else {
            break;
        }
    } while (NetMonotonic::TimeSec() < timestamp);

    NN_LOG_ERROR("Failed to write " << ret);
    return ret;
}

int32_t HcomChannelImp::Get(const UBSHcomOneSideRequest &req, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::Get" << ", channel id = " << mOptions.id <<
                 ", status = " << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::CALLED));
    VALIDATE_PARAM(OneSideRequest, req);
    SerResult ret = SER_OK;
    uint64_t timestamp = mOptions.oneSideTimeout < 0 ? UINT64_MAX : mOptions.oneSideTimeout + NetMonotonic::TimeSec();
    do {
        ret = FlowControl(req.size, mOptions.oneSideTimeout, timestamp);
        if (NN_UNLIKELY(ret != SER_OK)) {
            return ret;
        }

        NetTrace::TraceBegin(CHANNEL_READ);
        ret = OneSideInner(req, done, false);
        NetTrace::TraceEnd(CHANNEL_READ, ret);
        if (NN_LIKELY(ret == SER_OK)) {
            return SER_OK;
        } else if (ret == SER_NEW_OBJECT_FAILED) { // do later::add retry result code
            usleep(100UL);
            continue;
        } else {
            break;
        }
    } while (NetMonotonic::TimeSec() < timestamp);

    NN_LOG_ERROR("Failed to read " << ret);
    return ret;
}

inline void DestroyCallback(const Callback *cb)
{
    if (cb != nullptr) {
        delete cb;
    }
}

int32_t HcomChannelImp::Recv(const UBSHcomServiceContext &context, uintptr_t address, uint32_t size,
    const Callback *done)
{
    HcomServiceRndvMessage *rndvMessage = static_cast<HcomServiceRndvMessage *>(context.mData);
    if (rndvMessage == nullptr || rndvMessage->request.size != size) {
        NN_LOG_ERROR(" Fail to get Request data or Request size " << size << " and processing size " <<
            (rndvMessage == nullptr ? 0 : rndvMessage->request.size) << " mismatch");
        DestroyCallback(done);
        return SER_ERROR;
    }

    if (rndvMessage->IsTimeout()) {
        NN_LOG_ERROR(" Fail to recv request data due to timeout");
        DestroyCallback(done);
        return SER_TIMEOUT;
    }

    // 在pgTable上查询address 是否被注册
    PgTable *pgTable = reinterpret_cast<PgTable *>(mPgtable);
    uintptr_t endAddr = address + size - NN_NO1;
    PgtRegion *pgtRegion = pgTable->Lookup(address);
    if (pgtRegion == nullptr || !(pgtRegion->start <= address && pgtRegion->end > endAddr)) {
        NN_LOG_ERROR(" Fail to lookUp address in pgTable or req address is out of range");
        DestroyCallback(done);
        return SER_ERROR;
    }

    UBSHcomOneSideRequest oneSideRequest{};
    oneSideRequest.lAddress = address;
    oneSideRequest.lKey.keys[0] = pgtRegion->key;
    oneSideRequest.lKey.tokens[0] = pgtRegion->token;
    oneSideRequest.rAddress = reinterpret_cast<uintptr_t>(rndvMessage->request.address);
    oneSideRequest.rKey.keys[0] = rndvMessage->request.key;
    oneSideRequest.size = size;
    SerResult ret = Get(oneSideRequest, done);
    if (ret != SER_OK) {
        NN_LOG_ERROR("Fail to rndv read data " << ret);
        return ret;
    }
    return SER_OK;
}

SerResult HcomChannelImp::OneSideSglSyncWithSelfPoll(const UBSHcomOneSideSglRequest &request, bool isWrite,
    uint16_t railIdx)
{
    UBSHcomNetEndpoint *ep = nullptr;
    uint32_t index = 0;
    auto result = AcquireSelfPollEp(ep, index, mOptions.oneSideTimeout, ResolveRailIdx(railIdx));
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync oneside sgl acquire ep failed " << result << " channel id " << mOptions.id);
        return result;
    }

    const uint8_t devIdx = ep->GetDevIndex();
    const uint8_t peerDevIdx = ep->GetPeerDevIndex();
    UBSHcomNetTransSgeIov iovArray[NET_SGE_MAX_IOV];
    for (uint32_t i = 0; i < request.iovCount; i++) {
        iovArray[i] = UBSHcomNetTransSgeIov(request.iov[i].lAddress, request.iov[i].rAddress,
            request.iov[i].lKey.keys[devIdx], request.iov[i].rKey.keys[peerDevIdx], request.iov[i].size);
        iovArray[i].srcSeg = reinterpret_cast<void *>(request.iov[i].lKey.tokens[devIdx]);
        iovArray[i].dstSeg = reinterpret_cast<void *>(request.iov[i].rKey.tokens[devIdx]);
    }
    UBSHcomNetTransSglRequest sglReq(iovArray, request.iovCount, 0);
    if (isWrite) {
        result = ep->PostWrite(sglReq);
    } else {
        result = ep->PostRead(sglReq);
    }

    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync oneside sgl failed " << result << " ep id " << ep->Id());
        ReleaseSelfPollEp(index);
        return result;
    }

    /* timeout = 0 will poll cq empty in self polling */
    int32_t timeout = (mOptions.oneSideTimeout == 0 ? -1 : static_cast<int32_t>(mOptions.oneSideTimeout));
    result = ep->WaitCompletion(timeout);
    ReleaseSelfPollEp(index);
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync oneside sgl wait complete failed " << result << " ep id " << ep->Id());
    }
    return result;
}

SerResult HcomChannelImp::OneSideSglSyncWithWorkerPoll(const UBSHcomOneSideSglRequest &request, bool isWrite,
    uint16_t railIdx)
{
    UBSHcomNetEndpoint *ep = nullptr;
    auto result = NextWorkerPollEp(ep, ResolveRailIdx(railIdx));
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Get Ep failed " << result << " in rail " << ResolveRailIdx(railIdx));
        return result;
    }
    
    HcomServiceSelfSyncParam syncParam {};
    Callback *newCallback = UBSHcomNewCallback([&syncParam](UBSHcomServiceContext &context) {
            if (NN_UNLIKELY(context.Result() != SER_OK)) {
                NN_LOG_ERROR("Prepare callback failed " << context.Result());
            }
            syncParam.Result(context.Result());
            syncParam.Signal();
        },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("Sync oneside sgl callback is nullptr");
        return SER_NEW_OBJECT_FAILED;
    }

    TimerCtx readContext {};
    result = PrepareTimerContext(newCallback, mOptions.oneSideTimeout, readContext);
    if (result != SER_OK) {
        NN_LOG_ERROR("PrepareTimerContext failed " << result);
        DestroyCallback(newCallback);
        return result;
    }

    const uint8_t devIdx = ep->GetDevIndex();
    const uint8_t peerDevIdx = ep->GetPeerDevIndex();
    UBSHcomNetTransSgeIov iovArray[NET_SGE_MAX_IOV];
    for (uint32_t i = 0; i < request.iovCount; i++) {
        iovArray[i] = UBSHcomNetTransSgeIov(request.iov[i].lAddress, request.iov[i].rAddress,
            request.iov[i].lKey.keys[devIdx], request.iov[i].rKey.keys[peerDevIdx], request.iov[i].size);
        iovArray[i].srcSeg = reinterpret_cast<void *>(request.iov[i].lKey.tokens[devIdx]);
        iovArray[i].dstSeg = reinterpret_cast<void *>(request.iov[i].rKey.tokens[devIdx]);
    }
    UBSHcomNetTransSglRequest sglReq(iovArray, request.iovCount, sizeof(SerTransContext));
    SetServiceTransCtx(sglReq.upCtxData, readContext.seqNo);

    if (isWrite) {
        result = ep->PostWrite(sglReq);
    } else {
        result = ep->PostRead(sglReq);
    }
    if (NN_UNLIKELY(result != SER_OK)) {
        NN_LOG_ERROR("Channel sync oneside sgl failed " << result << " ep id " << ep->Id());
        DestroyTimerContext(readContext);
        return result;
    }
    
    syncParam.Wait();
    return syncParam.Result();
}

SerResult HcomChannelImp::OneSideSglAsyncWithWorkerPoll(const UBSHcomOneSideSglRequest &request, const Callback *done,
    bool isWrite, uint16_t railIdx)
{
    /* railIdx 指定时：整批 SGL 只走指定的那条 rail（上层可据此把不同数据区间钉到不同网卡）；
       未指定(SGL_AUTO_RAIL)时：按 MultiRail 策略把本批 iov 连续切分到多条 rail，
       每个 rail 用自己的设备 key 提交一个独立的 SGL 请求。 */
    uint64_t totalSize = 0;
    for (uint32_t i = 0; i < request.iovCount; i++) {
        totalSize += request.iov[i].size;
    }
    uint16_t railNum = NN_NO1;
    if (railIdx == SGL_AUTO_RAIL && mOptions.enableMultiRail && mDriverNum > 1 &&
        totalSize > mOptions.multiRailThresh) {
        railNum = mDriverNum;
    }
    if (railNum > request.iovCount) {
        railNum = request.iovCount;
    }

    Callback *cb = GetAsyncCB(railNum, done);
    if (NN_UNLIKELY(railNum > NN_NO1 && cb == nullptr)) {
        NN_LOG_ERROR("Get OneSideSglCB failed ");
        return SER_NEW_OBJECT_FAILED;
    }

    for (uint16_t rail = 0; rail < railNum; ++rail) {
        UBSHcomNetEndpoint *ep = nullptr;
        const uint16_t railSel = (railIdx == SGL_AUTO_RAIL) ? rail : ResolveRailIdx(railIdx);
        auto result = NextWorkerPollEp(ep, railSel);
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Get Ep failed " << result << " in rail " << railSel);
            ProcessRemainCallback(cb, railNum - rail);
            return result;
        }

        TimerCtx readContext {};
        result = PrepareTimerContext(cb, mOptions.oneSideTimeout, readContext);
        if (result != SER_OK) {
            NN_LOG_ERROR("PrepareTimerContext failed " << result << " in rail " << railSel);
            ProcessRemainCallback(cb, railNum - rail);
            return result;
        }

        const uint8_t devIdx = ep->GetDevIndex();
        const uint8_t peerDevIdx = ep->GetPeerDevIndex();
        /* 连续区间切分：rail r 负责 iov 的 [begin, end) 段，便于每张卡拿到连续地址 */
        const uint32_t base = request.iovCount / railNum;
        const uint32_t rem = request.iovCount % railNum;
        const uint32_t begin = rail * base + (rail < rem ? rail : rem);
        const uint32_t end = begin + base + (rail < rem ? 1 : 0);
        UBSHcomNetTransSgeIov iovArray[NET_SGE_MAX_IOV];
        uint16_t iovCnt = 0;
        for (uint32_t i = begin; i < end; ++i) {
            iovArray[iovCnt] = UBSHcomNetTransSgeIov(request.iov[i].lAddress, request.iov[i].rAddress,
                request.iov[i].lKey.keys[devIdx], request.iov[i].rKey.keys[peerDevIdx], request.iov[i].size);
            iovArray[iovCnt].srcSeg = reinterpret_cast<void *>(request.iov[i].lKey.tokens[devIdx]);
            iovArray[iovCnt].dstSeg = reinterpret_cast<void *>(request.iov[i].rKey.tokens[devIdx]);
            iovCnt++;
        }
        UBSHcomNetTransSglRequest sglReq(iovArray, iovCnt, sizeof(SerTransContext));
        SetServiceTransCtx(sglReq.upCtxData, readContext.seqNo);
        if (isWrite) {
            result = ep->PostWrite(sglReq);
        } else {
            result = ep->PostRead(sglReq);
        }
        if (NN_UNLIKELY(result != SER_OK)) {
            NN_LOG_ERROR("Channel async oneside sgl failed " << result << " ep id " << ep->Id() << " in rail "
                                                             << railSel);
            DestroyTimerContext(readContext);
            return result;
        }
    }

    NN_LOG_DEBUG("Multirail sgl: auto(" << (railIdx == SGL_AUTO_RAIL) << "), rail num: " << railNum << ", iov count: "
                                        << request.iovCount);
    return SER_OK;
}

SerResult HcomChannelImp::OneSideSglInner(const UBSHcomOneSideSglRequest &request, const Callback *done, bool isWrite,
    uint16_t railIdx)
{
    if (mOptions.selfPoll) {
        if (done == nullptr) {
            return OneSideSglSyncWithSelfPoll(request, isWrite, railIdx);
        } else {
            NN_LOG_ERROR("Failed to invoke async one side sgl op with self poll, not supported");
            return SER_INVALID_PARAM;
        }
    } else {
        if (done == nullptr) {
            /* worker poll 的同步 SGL 未做多 rail 扇出，固定走 rail 0（指定 rail 时按指定值走） */
            if (mOptions.enableMultiRail && railIdx == SGL_AUTO_RAIL) {
                NN_LOG_DEBUG("Multirail not supported in sync oneside sgl, using single rail.");
            }
            return OneSideSglSyncWithWorkerPoll(request, isWrite, railIdx);
        } else {
            return OneSideSglAsyncWithWorkerPoll(request, done, isWrite, railIdx);
        }
    }
    return SER_INVALID_PARAM;
}

int32_t HcomChannelImp::PutV(const UBSHcomOneSideSglRequest &req, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::PutV" << ", channel id = " << mOptions.id <<
                 ", status = " << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::CALLED));
    return SendSgl(req, done, true, SGL_AUTO_RAIL);
}

int32_t HcomChannelImp::GetV(const UBSHcomOneSideSglRequest &req, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::GetV" << ", channel id = " << mOptions.id <<
                 ", status = " << UBSHcomRequestStatusToString(UBSHcomNetRequestStatus::CALLED));
    return SendSgl(req, done, false, SGL_AUTO_RAIL);
}

int32_t HcomChannelImp::PutVOnRail(const UBSHcomOneSideSglRequest &req, uint16_t railIdx, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::PutVOnRail" << ", channel id = " << mOptions.id <<
                 ", rail: " << railIdx);
    return SendSgl(req, done, true, railIdx);
}

int32_t HcomChannelImp::GetVOnRail(const UBSHcomOneSideSglRequest &req, uint16_t railIdx, const Callback *done)
{
    NN_LOG_DEBUG("[Request Send] ------ API = HcomChannelImp::GetVOnRail" << ", channel id = " << mOptions.id <<
                 ", rail: " << railIdx);
    return SendSgl(req, done, false, railIdx);
}

int32_t HcomChannelImp::SendSgl(const UBSHcomOneSideSglRequest &req, const Callback *done, bool isWrite,
    uint16_t railIdx)
{
    VALIDATE_PARAM(OneSideSglRequest, req);
    SerResult ret = SER_OK;
    uint64_t timestamp = mOptions.oneSideTimeout < 0 ? UINT64_MAX : mOptions.oneSideTimeout + NetMonotonic::TimeSec();
    do {
        ret = FlowControl(req.Size(), mOptions.oneSideTimeout, timestamp);
        if (NN_UNLIKELY(ret != SER_OK)) {
            return ret;
        }

        if (isWrite) {
            NetTrace::TraceBegin(CHANNEL_WRITE);
            ret = OneSideSglInner(req, done, true, railIdx);
            NetTrace::TraceEnd(CHANNEL_WRITE, ret);
        } else {
            NetTrace::TraceBegin(CHANNEL_READ);
            ret = OneSideSglInner(req, done, false, railIdx);
            NetTrace::TraceEnd(CHANNEL_READ, ret);
        }
        if (NN_LIKELY(ret == SER_OK)) {
            return SER_OK;
        } else if (ret == SER_NEW_OBJECT_FAILED) { // do later::add retry result code
            usleep(100UL);
            continue;
        } else {
            break;
        }
    } while (NetMonotonic::TimeSec() < timestamp);

    NN_LOG_ERROR("Failed to " << (isWrite ? "writev " : "readv ") << ret);
    return ret;
}

SerResult HcomChannelImp::FlowControl(uint64_t size, int16_t timeout, uint64_t timestamp)
{
    if (mOptions.rateLimit == 0) {
        return SER_OK;
    }

    auto rateLimiter = reinterpret_cast<RateLimiter *>(mOptions.rateLimit);
    uint64_t timeoutSecond = timeout > 0 ? timestamp : NetMonotonic::TimeSec() + NN_NO10;
    while (true) {
        while (rateLimiter->AcquireQuota(size)) {
            uint64_t newByte = rateLimiter->windowPassedByte + size;
            uint64_t oldByte = rateLimiter->windowPassedByte;
            if (__sync_bool_compare_and_swap(&rateLimiter->windowPassedByte, oldByte, newByte)) {
                NN_LOG_TRACE_INFO("Success passed flow control size " << size << ", tid " << pthread_self());
                return SER_OK;
            }
        }

        if (NN_UNLIKELY(rateLimiter->InvalidateSize(size))) {
            NN_LOG_ERROR("Failed to flow control by user size " << size << " over configure thresholdByte " <<
                rateLimiter->thresholdByte);
            return SER_INVALID_PARAM;
        }

        NN_LOG_TRACE_INFO("Wait start flow control size " << size << ", tid " << pthread_self());
        rateLimiter->WaitUntilNextWindow();
        NN_LOG_TRACE_INFO("Wait finish flow control size " << size << ", tid " << pthread_self());
        rateLimiter->BuildNextWindow();

        if (NN_UNLIKELY(NetMonotonic::TimeSec() > timeoutSecond)) {
            NN_LOG_ERROR("Flow control timeout, channel id " << mOptions.id << " size " << size);
            return SER_TIMEOUT;
        }
    }

    return SER_OK;
}

int32_t HcomChannelImp::SetFlowControlConfig(const UBSHcomFlowCtrlOptions &opt)
{
    std::lock_guard<std::mutex> locker(mMgrMutex);
    if (!mChState.Compare(UBSHcomChannelState::CH_ESTABLISHED)) {
        NN_LOG_ERROR("Config flow control failed, as channel state invalid " << static_cast<uint16_t>(mChState.Get()));
        return SER_NOT_ESTABLISHED;
    }

    auto rateLimit = reinterpret_cast<RateLimiter *>(mOptions.rateLimit);
    if (mOptions.rateLimit == 0) {
        rateLimit = new (std::nothrow) RateLimiter;
        if (NN_UNLIKELY(rateLimit == nullptr)) {
            NN_LOG_ERROR("Failed to create rate limiter");
            return SER_INVALID_PARAM;
        }

        rateLimit->level = opt.flowCtrlLevel;
        rateLimit->intervalTimeMs = opt.intervalTimeMs;
        rateLimit->thresholdByte = opt.thresholdByte;
        rateLimit->windowEndTimeMs = NetMonotonic::TimeMs() + rateLimit->intervalTimeMs;
        mOptions.rateLimit = reinterpret_cast<uintptr_t>(rateLimit);
        return SER_OK;
    }

    /* require:support repeat config */
    rateLimit->level = opt.flowCtrlLevel;
    rateLimit->intervalTimeMs = opt.intervalTimeMs;
    rateLimit->thresholdByte = opt.thresholdByte;

    return SER_OK;
}

void HcomChannelImp::SetChannelTimeOut(int16_t oneSideTimeout, int16_t twoSideTimeout)
{
    if (oneSideTimeout < -1 || twoSideTimeout < -1) {
        NN_LOG_WARN("Timeout range must be greater than or equal to -1, default value is -1");
        return;
    }
    mOptions.oneSideTimeout = oneSideTimeout;
    mOptions.twoSideTimeout = twoSideTimeout;
}

void HcomChannelImp::SetEpUpCtx()
{
    for (uint16_t i = 0; i < mEpInfo->epSize; i++) {
        Ep2ChanUpCtx ctx(1, reinterpret_cast<uint64_t>(this), i);
        mEpInfo->epArr[i]->UpCtx(ctx.wholeUpCtx);
    }
}

void HcomChannelImp::UnSetEpUpCtx()
{
    for (uint16_t i = 0; i < mEpInfo->epSize; i++) {
        mEpInfo->epArr[i]->UpCtx(0);
    }
}

bool HcomChannelImp::AllEpEstablished()
{
    for (uint16_t i = 0; i < mEpInfo->epSize; i++) {
        if (mEpInfo->epState[i].Compare(SER_EP_BROKEN) ||
            mEpInfo->epArr[i]->State().Compare(NEP_BROKEN)) {
            return false;
        }
    }

    return true;
}

void HcomChannelImp::SetUuid(const std::string &uuid)
{
    mUuid = uuid;
}

void HcomChannelImp::SetPayload(const std::string &payload)
{
    mPayload = payload;
}

void HcomChannelImp::SetBrokenInfo(UBSHcomChannelBrokenPolicy policy, const UBSHcomServiceChannelBrokenHandler &broken)
{
    mOptions.brokenPolicy = policy;
    mOptions.brokenHandler = broken;
}

void HcomChannelImp::SetEpBroken(uint32_t index)
{
    if (mEpInfo == nullptr || index >= mEpInfo->epSize) {
        return;
    }
    mEpInfo->epState[index].Set(SER_EP_BROKEN);
}

void HcomChannelImp::SetChannelState(UBSHcomChannelState state)
{
    mChState.Set(state);
}

bool HcomChannelImp::AllEpBroken()
{
    for (uint16_t i = 0; i < mEpInfo->epSize; i++) {
        if (!mEpInfo->epState[i].Compare(SER_EP_BROKEN) || !mEpInfo->epArr[i]->State().Compare(NEP_BROKEN)) {
            return false;
        }
    }
    return true;
}

bool HcomChannelImp::NeedProcessBroken()
{
    bool process = false;
    if (NN_UNLIKELY(!mBrokenProcessed.compare_exchange_strong(process, true))) {
        return false;
    }
    return true;
}

void HcomChannelImp::ProcessIoInBroken()
{
    auto header = reinterpret_cast<SerTimerListHeader *>(mTimerList);
    std::vector<HcomServiceTimer *> remainCtx;

    header->GetTimerCtx(remainCtx);
    if (!remainCtx.empty()) {
        NN_LOG_INFO("Channel id " << mOptions.id << " process io broken, size " << remainCtx.size());
        PROCESS_IO(remainCtx);
    }

    /* try again to handle new add io during process */
    header->GetTimerCtx(remainCtx);
    if (!remainCtx.empty()) {
        NN_LOG_INFO("Channel id " << mOptions.id << " process io broken, size " << remainCtx.size());
        PROCESS_IO(remainCtx);
    }
}

void HcomChannelImp::InvokeChannelBrokenCb(UBSHcomChannelPtr &channel)
{
    if (mOptions.brokenHandler == nullptr) {
        NN_LOG_WARN("Empty ChannelBrokenCb");
        return;
    }
    mOptions.brokenHandler(channel);
}

uint64_t HcomChannelImp::GetId()
{
    return mOptions.id;
}
std::string HcomChannelImp::GetUuid()
{
    return mUuid;
}
uintptr_t HcomChannelImp::GetTimerList()
{
    return mTimerList;
}
uint32_t HcomChannelImp::GetLocalIp()
{
    return mLocalIp;
}
std::string HcomChannelImp::GetPeerConnectPayload()
{
    return mPayload;
}
uint16_t HcomChannelImp::GetDelayEraseTime()
{
    if (mOptions.brokenPolicy == UBSHcomChannelBrokenPolicy::RECONNECT) {
        return RECON_DELAY_ERASE_TIME;
    } else {
        return DEFAULT_DELAY_ERASE_TIME;
    }
}
HcomServiceCtxStore *HcomChannelImp::GetCtxStore()
{
    return mCtxStore;
}
UBSHcomChannelCallBackType HcomChannelImp::GetCallBackType()
{
    return mOptions.cbType;
}

SerResult HcomChannelImp::GetRemoteUdsIdInfo(UBSHcomNetUdsIdInfo &idInfo)
{
    NN_ASSERT_LOG_RETURN(mEpInfo != nullptr, SER_ERROR)
    NN_ASSERT_LOG_RETURN(mEpInfo->epArr[0] != nullptr, SER_ERROR)
    return mEpInfo->epArr[0]->GetRemoteUdsIdInfo(idInfo);
}

int32_t HcomChannelImp::SetTwoSideThreshold(const UBSHcomTwoSideThreshold &threshold)
{
    if (threshold.splitThreshold == UINT32_MAX) {
        mUserSplitSendThreshold = UINT32_MAX;
        // 如果mEnableMrCache为false且设置rndv阈值生效的情况(splitThreshold不涉及)，给用户返回报错，让用户先将mEnableMrCache设置为true
        if ((!mEnableMrCache) && (threshold.rndvThreshold != UINT32_MAX)) {
            NN_LOG_ERROR("Fail to set Threshold, because need set enableMrCache true first ");
            return SER_INVALID_PARAM;
        }
        mRndvThreshold = threshold.rndvThreshold;
        NN_LOG_INFO("SplitSend (UBC only) enabled with threshold " << mUserSplitSendThreshold <<
                    ", Rndv Threshold is: " << mRndvThreshold);
        return SER_OK;
    }

    if (threshold.splitThreshold < NN_NO128) {
        NN_LOG_ERROR("The split threshold (" << threshold.splitThreshold <<
            ") is less than 128, SplitSend may not work properly");
        return SER_INVALID_PARAM;
    }

    if (threshold.splitThreshold > mMaxSendRecvDataSize) {
        NN_LOG_ERROR("The split threshold (" << threshold.splitThreshold << ") is larger than SegSize (" <<
            mMaxSendRecvDataSize << "), SplitSend will fail to post request");
        return SER_INVALID_PARAM;
    }

    if (threshold.splitThreshold > threshold.rndvThreshold) {
        NN_LOG_ERROR("The threshold of split send cannot be greater than the threshold of rndv! Split send threshold: "
                     << threshold.splitThreshold << " Rndv threshold: " << threshold.rndvThreshold);
        return SER_INVALID_PARAM;
    }

    // 如果mEnableMrCache为false且设置rndv阈值生效的情况(splitThreshold不涉及)，给用户返回报错，让用户先将mEnableMrCache设置为true
    if ((!mEnableMrCache) && (threshold.rndvThreshold != UINT32_MAX)) {
        NN_LOG_ERROR("Fail to set Threshold, because need set enableMrCache true first ");
        return SER_INVALID_PARAM;
    }

    // 拆包阈值只有在小于rndv阈值时才有效
    if (threshold.splitThreshold < threshold.rndvThreshold) {
        mUserSplitSendThreshold =
        threshold.splitThreshold - sizeof(UBSHcomNetTransHeader) - sizeof(UBSHcomFragmentHeader);
    }

    mRndvThreshold = threshold.rndvThreshold;

    NN_LOG_INFO("SplitSend (UBC only) enabled with threshold " << threshold.splitThreshold <<
        ", Rndv Threshold is: " << mRndvThreshold);
    return SER_OK;
}

void HcomChannelImp::SetUpCtx(uint64_t ctx)
{
    mUpCtx = ctx;
}

uint64_t HcomChannelImp::GetUpCtx()
{
    return mUpCtx;
}
}
}
