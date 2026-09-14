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
#ifndef HCOM_API_HCOM_CHANNEL_H_
#define HCOM_API_HCOM_CHANNEL_H_

#include <cstdint>
#include <memory>
#include "hcom.h"
#include "hcom_def.h"
#include "hcom_service_def.h"
#include "hcom_split.h"

namespace ock {
namespace hcom {
class UBSHcomServiceContext;
class UBSHcomChannel;
class HcomServiceCtxStore;

using UBSHcomEndpointPtr = NetRef<UBSHcomNetEndpoint>;
using UBSHcomChannelPtr = NetRef<UBSHcomChannel>;
using UBSHcomServiceChannelBrokenHandler = std::function<void(const UBSHcomChannelPtr &)>;

enum UBSHcomChannelState : uint16_t {
    CH_NEW,
    CH_ESTABLISHED,
    CH_CLOSE,
    CH_DESTROY,
};

class Callback {
public:
    Callback() = default;
    virtual ~Callback() = default;
    virtual void Run(UBSHcomServiceContext &context) = 0;
    virtual void SetTime(uint64_t time) = 0;
    virtual uint64_t GetTime() = 0;
};

/**
 * @brief 内部使用，请使用NewCallback生成回调用
 *
 * @param ClosureFunction
 */
template <typename ClosureFunction> class InnerClosureCallback : public Callback {
public:
    explicit InnerClosureCallback(ClosureFunction &&function, bool deleteSelf)
        : mFunction(std::move(function)), mDeleteSelf(deleteSelf) {}

    ~InnerClosureCallback() override = default;

    void Run(UBSHcomServiceContext &context) override
    {
        bool doDeleteSelf = false;
        if (mDeleteSelf) {
            mDeleteSelf = false;
            doDeleteSelf = true;
        }
        mFunction(context);
        if (doDeleteSelf) {
            delete this;
        }
    }

private:
    uint64_t GetTime() override
    {
        return mStartTime;
    }

    void SetTime(uint64_t time) override
    {
        mStartTime = time;
    }

private:
    ClosureFunction mFunction = nullptr;
    bool mDeleteSelf = true;
    uint64_t mStartTime = 0;
};

/**
 * @brief Generate a self-deleting Callback object.
 *
 * @param Args
 * @param args
 * @return Callback*
 * @note At present, asynchronous operation is not a hot spot. In order to simplify
 * coding, std::bind is used to implement closure. If the cost of std::bind
 * is found to be high, then optimize it.
 */
template <typename... Args> Callback *UBSHcomNewCallback(Args... args)
{
    auto closure = std::bind(args...);
    return new (std::nothrow) InnerClosureCallback<decltype(closure)>(std::move(closure), true);
}

class UBSHcomChannel {
public:
    /**
     * @brief 发送双边消息，不需要回复
     *
     * @param req 发送双边消息请求
     * @param done nullptr：同步发送；非nullptr：异步发送，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t Send(const UBSHcomRequest &req, const Callback *done) = 0;
    int32_t Send(const UBSHcomRequest &req);

    /**
     * @brief 发送双边消息，需要回复
     *
     * @param req 发送双边消息请求
     * @param rsp 出参，发送双边消息请求后对端回复
     * @param done nullptr：同步发送；非nullptr：异步发送，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t Call(const UBSHcomRequest &req, UBSHcomResponse &rsp, const Callback *done) = 0;
    int32_t Call(const UBSHcomRequest &req, UBSHcomResponse &rsp);

    /**
     * @brief 回复双边消息，接收端配合Call使用
     *
     * @param ctx 回复上下文
     * @param req 回复数据
     * @param done nullptr：同步发送；非nullptr：异步发送，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t Reply(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req, const Callback *done) = 0;
    int32_t Reply(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req);

    /**
     * @brief 发送单边写请求
     *
     * @param req 单边写请求
     * @param done nullptr：同步发送单边请求；非nullptr：异步发送单边请求，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t Put(const UBSHcomOneSideRequest &req, const Callback *done) = 0;
    int32_t Put(const UBSHcomOneSideRequest &req);

    /**
     * @brief 发送单边读请求
     *
     * @param req 单边读请求
     * @param done nullptr：同步发送单边读请求；非nullptr：异步发送单边读请求，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t Get(const UBSHcomOneSideRequest &req, const Callback *done) = 0;
    int32_t Get(const UBSHcomOneSideRequest &req);

    /**
     * @brief 发送单边写SGL请求
     *
     * @param req 单边写SGL请求
     * @param done nullptr：同步发送单边请求；非nullptr：异步发送单边请求，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t PutV(const UBSHcomOneSideSglRequest &req, const Callback *done) = 0;
    int32_t PutV(const UBSHcomOneSideSglRequest &req);

    /**
     * @brief 发送单边读SGL请求
     *
     * @param req 单边读SGL请求
     * @param done nullptr：同步发送单边读请求；非nullptr：异步发送单边读请求，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t GetV(const UBSHcomOneSideSglRequest &req, const Callback *done) = 0;
    int32_t GetV(const UBSHcomOneSideSglRequest &req);

    /**
     * @brief 发送单边写SGL请求，并指定承载该请求的 rail(网卡)
     *
     * @param req 单边写SGL请求
     * @param railIdx 指定的 rail 下标，取值 [0, driver 数)；该请求不做多 rail 扇出，整批只走这条 rail
     * @param done nullptr：同步发送单边请求；非nullptr：异步发送单边请求，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t PutVOnRail(const UBSHcomOneSideSglRequest &req, uint16_t railIdx, const Callback *done) = 0;

    /**
     * @brief 发送单边读SGL请求，并指定承载该请求的 rail(网卡)
     *
     * @param req 单边读SGL请求
     * @param railIdx 指定的 rail 下标，取值 [0, driver 数)；该请求不做多 rail 扇出，整批只走这条 rail
     * @param done nullptr：同步发送单边读请求；非nullptr：异步发送单边读请求，发送完成后回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t GetVOnRail(const UBSHcomOneSideSglRequest &req, uint16_t railIdx, const Callback *done) = 0;

    /**
     * @brief 只接收RNDV请求时使用,且RNDV请求接收后必须reply
     *
     * @param context: 接收到的service Context
     * @param address: recv的数据地址
     * @param size: recv的数据长度
     * @param done nullptr: 同步接受数据需要切换线程使用；非nullptr：异步收到数据请求，接收完成后执行回调函数
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t Recv(const UBSHcomServiceContext &context, uintptr_t address, uint32_t size,
        const Callback *done = nullptr) = 0;

    /**
     * @brief 流控设置
     *
     * @param opt 流控设置选项
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t SetFlowControlConfig(const UBSHcomFlowCtrlOptions &opt) = 0;

    /**
     * @brief 超时设置
     *
     * @param oneSideTimeout 单边请求超时时间
     * @param twoSideTimeout 双边请求超时时间
     */
    virtual void SetChannelTimeOut(int16_t oneSideTimeout, int16_t twoSideTimeout) = 0;

    /**
     * @brief 设置双边操作阈值
     *
     * @param threshold 双边操作阈值
     * @return int32_t 0：成功；非0：失败错误码
     */
    virtual int32_t SetTwoSideThreshold(const UBSHcomTwoSideThreshold &threshold) = 0;

    /**
     * @brief 设置trace id
     *
     * @param traceId trace id
     */
    virtual void SetTraceId(const std::string &traceId) = 0;

    virtual uint64_t GetId() = 0;
    virtual std::string GetPeerConnectPayload() = 0;
    virtual int32_t GetRemoteUdsIdInfo(UBSHcomNetUdsIdInfo &idInfo) = 0;
    virtual int32_t SendFds(int fds[], uint32_t len) = 0;
    virtual int32_t ReceiveFds(int fds[], uint32_t len, int32_t timeoutSec) = 0;
    virtual void SetUpCtx(uint64_t ctx) = 0;
    virtual uint64_t GetUpCtx() = 0;

    virtual ~UBSHcomChannel() {}
    DEFINE_RDMA_REF_COUNT_FUNCTIONS

protected:
    virtual auto SpliceMessage(const UBSHcomNetRequestContext &ctx, bool isResp)
            -> std::tuple<SpliceMessageResultType, SerResult, std::string> = 0;

    uint32_t mUserSplitSendThreshold = UINT32_MAX;  // 用户 payload 拆包阈值，已去除额外头部大小
private:
    virtual SerResult Initialize(std::vector<UBSHcomEndpointPtr> &ep, uintptr_t ctxMemPool, uintptr_t periodicMgr,
        uintptr_t pgTable, uint32_t ctxStoreCapacity = NN_NO2097152) = 0;
    virtual void UnInitialize() = 0;
    virtual std::string ToString() = 0;

    virtual void SetUuid(const std::string &uuid) = 0;
    virtual void SetPayload(const std::string &payLoad) = 0;
    virtual void SetBrokenInfo(UBSHcomChannelBrokenPolicy policy, const UBSHcomServiceChannelBrokenHandler &broken) = 0;
    virtual void SetEpBroken(uint32_t index) = 0;
    virtual void SetChannelState(UBSHcomChannelState state) = 0;
    virtual void SetMultiRail(bool multiRail, uint32_t threshold) = 0;
    virtual void SetDriverNum(uint16_t driverNum) = 0;
    virtual void SetTotalBandWidth(uint32_t bandWidth) = 0;
    virtual void SetEnableMrCache(bool enableMrCache) = 0;

    virtual bool AllEpBroken() = 0;
    virtual bool NeedProcessBroken() = 0;
    virtual void ProcessIoInBroken() = 0;
    virtual void InvokeChannelBrokenCb(UBSHcomChannelPtr &channel) = 0;

    virtual std::string GetUuid() = 0;
    virtual uintptr_t GetTimerList() = 0;
    virtual uint32_t GetLocalIp() = 0;
    virtual uint16_t GetDelayEraseTime() = 0;
    virtual HcomServiceCtxStore *GetCtxStore() = 0;
    virtual UBSHcomChannelCallBackType GetCallBackType() = 0;

private:
    DEFINE_RDMA_REF_COUNT_VARIABLE;

    friend class HcomServiceImp;
    friend class HcomServiceTimer;
    friend class HcomPeriodicManager;
};

inline int32_t UBSHcomChannel::Send(const UBSHcomRequest &req)
{
    return this->Send(req, nullptr);
}

inline int32_t UBSHcomChannel::Call(const UBSHcomRequest &req, UBSHcomResponse &rsp)
{
    return this->Call(req, rsp, nullptr);
}

inline int32_t UBSHcomChannel::Reply(const UBSHcomReplyContext &ctx, const UBSHcomRequest &req)
{
    return this->Reply(ctx, req, nullptr);
}

inline int32_t UBSHcomChannel::Put(const UBSHcomOneSideRequest &req)
{
    return this->Put(req, nullptr);
}

inline int32_t UBSHcomChannel::Get(const UBSHcomOneSideRequest &req)
{
    return this->Get(req, nullptr);
}
}
}
#endif // HCOM_API_HCOM_CHANNEL_H_