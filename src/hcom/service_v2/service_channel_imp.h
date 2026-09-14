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
#ifndef HCOM_SERVICE_V2_HCOM_CHANNEL_IMP_H_
#define HCOM_SERVICE_V2_HCOM_CHANNEL_IMP_H_

#include <cstdint>
#include <mutex>
#include <pthread.h>
#include "hcom_def.h"
#include "hcom_service_def.h"
#include "hcom_service_channel.h"
#include "hcom_obj_statistics.h"
#include "service_imp.h"
#include "service_common.h"
#include "service_callback.h"
#include "hcom_env.h"

namespace ock {
namespace hcom {

struct HcomChannelImpOptions {
    uint64_t id = 0;
    uintptr_t rateLimit = 0;
    UBSHcomServiceChannelBrokenHandler brokenHandler = nullptr;
    uint32_t multiRailThresh = 8192;
    int16_t oneSideTimeout = 30;
    int16_t twoSideTimeout = 30;
    UBSHcomChannelCallBackType cbType = UBSHcomChannelCallBackType::CHANNEL_FUNC_CB;
    UBSHcomChannelBrokenPolicy brokenPolicy = UBSHcomChannelBrokenPolicy::BROKEN_ALL;
    bool enableMultiRail = false;
    bool selfPoll = false;
};

enum ServiceEpState : uint16_t {
    SER_EP_ESTABLISHED = 0,
    SER_EP_BROKEN = 1,
    SER_EP_ESTABLISHED_OCCUPIED = 2,
    SER_EP_ESTABLISHED_UNOCCUPIED = 3,
};

struct EpInfo {
    UBSHcomNetAtomicState<ServiceEpState> epState[CHANNEL_EP_MAX_NUM]{}; /* state of eps */
    UBSHcomNetEndpoint *epArr[CHANNEL_EP_MAX_NUM]{}; /* endpoints for data transfer */
    uint16_t epSize = 0;
    EpInfo() = default;
};

#define PROCESS_IO(remainCtx)                               \
    do {                                                    \
        UBSHcomServiceContext brokenCtx{};                     \
        HcomServiceGlobalObject::BuildBrokenCtx(brokenCtx); \
        for (auto ctx : (remainCtx)) {                      \
            if (ctx->EraseSeqNoWithRet()) {                 \
                ctx->TimeoutDump();                         \
                ctx->MarkFinished();                        \
                brokenCtx.mCh = ctx->mChannel;              \
                ctx->RunCallBack(brokenCtx);                \
                brokenCtx.mCh.Set(nullptr);                 \
                ctx->DecreaseRef();                         \
            }                                               \
            /* decrease linked list ref */                  \
            ctx->DecreaseRef();                             \
        }                                                   \
    } while (0)

struct TimerCtx {
    uint32_t seqNo = 0;
    HcomServiceTimer *timer = nullptr;

    TimerCtx() = default;
};

class HcomChannelImp : public UBSHcomChannel {
public:
    // 由于UBSHcomChannel是纯虚基类，UBSE、libvirt在ut中继承并实现了stub子类，如果基类有api增减，需要通知下游，否则影响下游门禁
    int32_t Send(const UBSHcomRequest &req, const Callback *done = nullptr) override;
    int32_t Call(const UBSHcomRequest &req, UBSHcomResponse &rsp, const Callback *done = nullptr) override;
    int32_t Reply(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req, const Callback *done = nullptr) override;
    int32_t Put(const UBSHcomOneSideRequest &req, const Callback *done = nullptr) override;
    int32_t Get(const UBSHcomOneSideRequest &req, const Callback *done = nullptr) override;
    int32_t PutV(const UBSHcomOneSideSglRequest &req, const Callback *done = nullptr) override;
    int32_t GetV(const UBSHcomOneSideSglRequest &req, const Callback *done = nullptr) override;
    int32_t PutVOnRail(const UBSHcomOneSideSglRequest &req, uint16_t railIdx, const Callback *done = nullptr) override;
    int32_t GetVOnRail(const UBSHcomOneSideSglRequest &req, uint16_t railIdx, const Callback *done = nullptr) override;
    int32_t SendFds(int fds[], uint32_t len) override;
    int32_t ReceiveFds(int fds[], uint32_t len, int32_t timeoutSec) override;
    int32_t Recv(const UBSHcomServiceContext &context, uintptr_t address, uint32_t size,
        const Callback *done = nullptr) override;

    int32_t SetFlowControlConfig(const UBSHcomFlowCtrlOptions &opt) override;
    void SetChannelTimeOut(int16_t oneSideTimeout, int16_t twoSideTimeout) override;
    int32_t GetRemoteUdsIdInfo(UBSHcomNetUdsIdInfo &idInfo) override;
    int32_t SetTwoSideThreshold(const UBSHcomTwoSideThreshold &threshold) override;
    void SetUpCtx(uint64_t ctx) override;
    uint64_t GetUpCtx() override;

    inline void SetTraceId(const std::string &traceId) override
    {
        SetTraceIdInner(traceId);
    }

protected:
    /// 当发送端发送大包时，一个消息会被分为多个 fragment 发送，接收端在识别后需要将 fragment 拼接。
    /// 当返回 SpliceMessageResultType::ERROR 时，同时返回的 SerResult 是实际的错误码，
    /// std::string 无效；当返回 SpliceMessageResultType::OK 时，同时返回的 SerResult 必
    /// 定为 SER_OK，同时 std::string 为拼完后的完整消息；当返回
    /// SpliceMessageResultType::INDETERMINATE 时，同时返回的 SerResult 必定为 SER_OK，
    /// std::string 无效。
    auto SpliceMessage(const UBSHcomNetRequestContext &ctx, bool isResp)
            -> std::tuple<SpliceMessageResultType, SerResult, std::string> override;

    std::mutex mMsgReceivedMutex;
    std::map<UBSHcomFragmentMessageId, std::shared_ptr<std::pair<uint32_t, std::string>>> mMsgReceived;

private:
    HcomChannelImp(uint64_t id, bool selfPoll, InnerConnectOptions &opt,
                   UBSHcomServiceProtocol protocol = UBSHcomServiceProtocol::UNKNOWN,
                   uint32_t maxSendRecvDataSize = 1024)
        : mProtocol(protocol), mMaxSendRecvDataSize(maxSendRecvDataSize)
    {
        mOptions.id = id;
        mOptions.selfPoll = selfPoll;
        mOptions.cbType = opt.cbType;
        if (opt.mode == UBSHcomClientPollingMode::SELF_POLL_BUSY) {
            mRespOriginalSeqNo = true;
        }
        mChState.Set(UBSHcomChannelState::CH_NEW);
        OBJ_GC_INCREASE(HcomChannelImp);
    }

    ~HcomChannelImp() override
    {
        UnInitialize();
        ForceUnInitialize();
        OBJ_GC_DECREASE(HcomChannelImp);
    }

    SerResult Initialize(std::vector<UBSHcomNetEndpointPtr> &ep, uintptr_t ctxMemPool, uintptr_t periodicMgr,
        uintptr_t pgTable, uint32_t ctxStoreCapacity = NN_NO2097152) override;
    void UnInitialize() override;
    void ForceUnInitialize();
    std::string ToString() override;

    SerResult InitializeEp(std::vector<UBSHcomNetEndpointPtr> &ep);
    SerResult SendInner(const UBSHcomRequest &req, const Callback *done);
    SerResult SyncSendInner(const UBSHcomRequest &req);
    SerResult AsyncSendInner(const UBSHcomRequest &req, const Callback *done);
    SerResult SyncSendWithSelfPoll(const UBSHcomRequest &req);
    SerResult CallInner(const UBSHcomRequest &req, UBSHcomResponse &rsp, const Callback *done);
    SerResult SyncCallInner(const UBSHcomRequest &req, UBSHcomResponse &rsp, uint32_t timeOut = NN_NO0);
    SerResult RndvInner(UBSHcomNetEndpoint *ep, const UBSHcomRequest &req, UBSHcomNetTransOpInfo &transOp, bool isCall);
    SerResult AsyncCallInner(const UBSHcomRequest &req, const Callback *done);
    SerResult ReplyInner(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req, const Callback *done);
    SerResult SyncReplyInner(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req);
    SerResult AsyncReplyInner(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req, const Callback *done);
    SerResult SyncCallWithSelfPoll(const UBSHcomRequest &req, UBSHcomResponse &rsp);
    SerResult FlowControl(uint64_t size, int16_t timeout, uint64_t timestamp);
    SerResult SyncSendSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req, uint32_t fragmentNum);
    SerResult SyncSendSplitWithSelfPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req, uint32_t fragmentNum,
                                        uint32_t index);
    SerResult AsyncSendSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req, uint32_t fragmentNum,
                                           const Callback *done);
    SerResult AsyncReplySplitWithWorkerPoll(const UBSHcomReplyContext &ctx, UBSHcomNetEndpoint *&ep,
                                            const UBSHcomRequest &req, uint32_t fragmentNum, const Callback *done);
    SerResult SyncReplySplitWithWorkerPoll(const UBSHcomReplyContext &ctx, UBSHcomNetEndpoint *&ep,
                                           const UBSHcomRequest &req, uint32_t fragmentNum);

    SerResult SyncCallSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req, uint32_t fragmentNum,
                                          UBSHcomResponse &rsp);
    SerResult AsyncCallSplitWithWorkerPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req, uint32_t fragmentNum,
                                           const Callback *done);
    SerResult SyncCallSplitWithSelfPoll(UBSHcomNetEndpoint *&ep, const UBSHcomRequest &req, uint32_t fragmentNum,
                                        uint32_t index, UBSHcomResponse &rsp);

    void SetUuid(const std::string &uuid) override;
    void SetPayload(const std::string &payload) override;
    void SetBrokenInfo(UBSHcomChannelBrokenPolicy policy, const UBSHcomServiceChannelBrokenHandler &broken) override;
    void SetEpBroken(uint32_t index) override;
    void SetChannelState(UBSHcomChannelState state) override;
    void SetEpUpCtx();
    bool AllEpEstablished();
    void UnSetEpUpCtx();
    inline void SetMultiRail(bool multiRail, uint32_t threshold) override
    {
        mOptions.enableMultiRail = multiRail;
        mOptions.multiRailThresh = threshold;
    }
    inline void SetDriverNum(uint16_t driverNum) override
    {
        mDriverNum = driverNum;
    }
    inline void SetTotalBandWidth(uint32_t bandWidth) override
    {
        mTotalBandWidth = bandWidth;
    }

    inline void SetEnableMrCache(bool enableMrCache) override
    {
        mEnableMrCache = enableMrCache;
    }

    bool AllEpBroken() override;
    bool NeedProcessBroken() override;
    void ProcessIoInBroken() override;
    void InvokeChannelBrokenCb(UBSHcomChannelPtr &channel) override;

    uint64_t GetId() override;
    std::string GetUuid() override;
    uintptr_t GetTimerList() override;
    uint32_t GetLocalIp() override;
    std::string GetPeerConnectPayload() override;
    uint16_t GetDelayEraseTime() override;
    HcomServiceCtxStore *GetCtxStore() override;
    UBSHcomChannelCallBackType GetCallBackType() override;

    SerResult AcquireSelfPollEp(UBSHcomNetEndpoint *&ep, uint32_t &index, int16_t timeout, uint16_t dvrIdx = 0);
    void ReleaseSelfPollEp(uint32_t index);
    SerResult NextWorkerPollEp(UBSHcomNetEndpoint *&ep, uint16_t dvrIdx = 0);
    SerResult ResponseWorkerPollEp(uintptr_t rspCtx, UBSHcomNetEndpoint *&ep);

    SerResult PrepareTimerContext(const Callback *cb, int16_t timeout, TimerCtx &context);
    void DestroyTimerContext(TimerCtx &context);

    Callback *GetAsyncCB(uint16_t multiNum, const Callback *done);
    SerResult OneSideInner(const UBSHcomOneSideRequest &request, const Callback *done, bool isWrite);
    SerResult OneSideSyncWithSelfPoll(const UBSHcomOneSideRequest &request, bool isWrite);
    SerResult OneSideSyncWithWorkerPoll(const UBSHcomOneSideRequest &request, bool isWrite);
    SerResult OneSideAsyncWithWorkerPoll(const UBSHcomOneSideRequest &request, const Callback *done, bool isWrite);

    SerResult OneSideSglInner(const UBSHcomOneSideSglRequest &request, const Callback *done, bool isWrite,
        uint16_t railIdx = SGL_AUTO_RAIL);
    SerResult OneSideSglSyncWithSelfPoll(const UBSHcomOneSideSglRequest &request, bool isWrite,
        uint16_t railIdx = SGL_AUTO_RAIL);
    SerResult OneSideSglSyncWithWorkerPoll(const UBSHcomOneSideSglRequest &request, bool isWrite,
        uint16_t railIdx = SGL_AUTO_RAIL);
    SerResult OneSideSglAsyncWithWorkerPoll(const UBSHcomOneSideSglRequest &req, const Callback *done, bool isWrite,
        uint16_t railIdx = SGL_AUTO_RAIL);
    int32_t SendSgl(const UBSHcomOneSideSglRequest &req, const Callback *done, bool isWrite, uint16_t railIdx);
    /* railIdx 超出实际 driver 数时回落到 rail 0（SGL_AUTO_RAIL 也走这里） */
    inline uint16_t ResolveRailIdx(uint16_t railIdx) const
    {
        return (railIdx < mDriverNum) ? railIdx : 0;
    }
    static constexpr uint16_t SGL_AUTO_RAIL = UINT16_MAX; /* 未指定 rail：按库内 MultiRail 策略自动扇出 */
    SerResult PrepareCallback(HcomServiceSelfSyncParam& syncParam, TimerCtx &syncContext);
    inline void CalculateOffsetAndSize(const UBSHcomOneSideRequest &request, UBSHcomNetEndpoint *ep,
        uint32_t &remain, uint32_t &offset, uint32_t &size)
    {
        if (mOptions.enableMultiRail && mDriverNum > 1 && request.size > mOptions.multiRailThresh) {
            offset = request.size - remain;
            uint32_t transferSize =
                static_cast<uint32_t>(ceilf(request.size * (ep->GetBandWidth() / static_cast<float>(mTotalBandWidth))));
            size = (transferSize > remain) ? remain : transferSize;
            remain -= size;
        }
    }

    inline uint32_t SelfPollNextSeqNo()
    {
        /* reserve 1 bit for mark send/rsp */
        uint32_t tmpSeqNo = __sync_fetch_and_add(&mSelfPollSeqNo, 1);
        /* In order to make sure the netSeqNo.wholeSeq is not zero, and since only the lower 24 bits will be assigned to
        netSeqNo.realSeq, tmpSeqNo need to be ensured that lower 24 bits are not zero. */
        if (NN_UNLIKELY((tmpSeqNo & 0x00FFFFFF) == 0)) {
            tmpSeqNo = __sync_fetch_and_add(&mSelfPollSeqNo, 1);
        }

        /* sell poll just set realSeq */
        HcomSeqNo netSeqNo(0);
        netSeqNo.realSeq = tmpSeqNo;
        return netSeqNo.wholeSeq;
    }

    void ProcessRemainCallback(Callback *cb, uint32_t remainNums);

    /// 估算 fragment 个数，如果为单个 fragment 则不拆包，service 层无额外头部。否则
    /// 添加 UBSHcomFragmentHeader 头部以指示共被分成多少块 fragment、总大小为多少。
    /// 如果满足以下任意条件，则始终使用一个 fragment 来发送：
    /// 1、split send 特性未启用；
    /// 2、protocol 非 UBC；
    /// 3、同时设置了rndv阈值，并且发送的数据size大于等于rndv阈值；
    /// 调用前应当保证 size 不为 0.
    /// \see SplitSendInner
    inline uint32_t EstimateFragmentNum(uint32_t size, bool withRndv = false)
    {
        if (mUserSplitSendThreshold == UINT32_MAX || (withRndv && size >= mRndvThreshold)) {
            return 1;
        }

        return (mProtocol != UBSHcomServiceProtocol::UBC && mProtocol != UBSHcomServiceProtocol::TCP) ?
                       1 :
                       (static_cast<uint64_t>(size) + mUserSplitSendThreshold - 1) / mUserSplitSendThreshold;
    }

    void CheckAndUpdateThreshold();

private:
    HcomChannelImpOptions mOptions;
    EpInfo *mEpInfo = nullptr;
    HcomServiceCtxStore *mCtxStore = nullptr;
    uintptr_t mCtxMemPool = 0;
    uintptr_t mPeriodicMgr = 0; /* timeout periodic manager */
    uintptr_t mPgtable = 0;
    uint32_t mRndvThreshold = UINT32_MAX;
    uint32_t mSelfPollSeqNo = 1;    /* for self polling simplified usage */
    bool mRespOriginalSeqNo = false;

    uintptr_t mTimerList = 0;
    uint32_t mLocalIp = 0;
    uint16_t mDriverNum = 1;
    uint32_t mTotalBandWidth = 0;
    uint16_t mEpChoosingIdx[4] = {0};   /* index for choosing to which ep to transfer */
    std::string mUuid;
    std::atomic_bool mBrokenProcessed{false};
    std::mutex mMgrMutex;
    UBSHcomNetAtomicState<UBSHcomChannelState> mChState;       // channel state
    std::string mPayload;
    HcomConnectTimestamp mConnectTimestamp {};

    UBSHcomServiceProtocol mProtocol = UBSHcomServiceProtocol::UNKNOWN;
    uint32_t mMaxSendRecvDataSize = 1024;
    bool mEnableMrCache = false;        //  mr into pgTable for management
    uint64_t mUpCtx; // store user ctx
    friend class HcomServiceImp;
};

}
}
#endif // HCOM_SERVICE_V2_HCOM_CHANNEL_IMP_H_