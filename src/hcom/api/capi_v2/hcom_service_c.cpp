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
#include "hcom_service_c.h"
#include <regex>
#include "hcom_def_inner_c.h"
#include "hcom_err.h"
#include "api/hcom_service_def.h"
#include "api/hcom_service.h"
#include "api/hcom_service_channel.h"
#include "api/hcom_service_context.h"
#include "net_common.h"

using namespace ock::hcom;

#define VALIDATE_SERVICE(service)                                       \
    if (NN_UNLIKELY((service) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, service must be correct address"); \
        return SER_INVALID_PARAM;                                       \
    }

#define VALIDATE_SERVICE_NO_RET(service)                                \
    if (NN_UNLIKELY((service) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, service must be correct address"); \
        return;                                                         \
    }

#define VALIDATE_CHANNEL(channel)                                       \
    if (NN_UNLIKELY((channel) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, channel must be correct address"); \
        return SER_INVALID_PARAM;                                       \
    }

#define VALIDATE_HANDLER(h)                                             \
    if (NN_UNLIKELY((h) == nullptr)) {                                  \
        NN_LOG_ERROR("Invalid param, handler must be correct address"); \
        return 0;                                                       \
    }

#define VALIDATE_HANDLER_NO_RET(h)                                      \
    if (NN_UNLIKELY((h) == nullptr)) {                                  \
        NN_LOG_ERROR("Invalid param, handler must be correct address"); \
        return;                                                         \
    }

#define VALIDATE_MR(mr)                                               \
    if (NN_UNLIKELY((mr) == 0)) {                                     \
        NN_LOG_ERROR("Invalid param, mr must be correct mr address"); \
        return SER_INVALID_PARAM;                                     \
    }

#define VALIDATE_INFO(info)                                             \
    if (NN_UNLIKELY((info) == 0)) {                                     \
        NN_LOG_ERROR("Invalid param, info must be correct mr address"); \
        return SER_INVALID_PARAM;                                       \
    }

#define VALIDATE_MR_POINT(mr)                                               \
    if (NN_UNLIKELY((mr) == nullptr)) {                                     \
        NN_LOG_ERROR("Invalid param, mr pointer must be correct address");  \
        return SER_INVALID_PARAM;                                           \
    }

#define VALIDATE_MR_ADDRESS(address)                                          \
    if (NN_UNLIKELY((address) == 0)) {                                        \
        NN_LOG_ERROR("Invalid param, mr address must be correct address");    \
        return SER_INVALID_PARAM;                                             \
    }

#define VALIDATE_MR_SIZE(size)                                       \
    if (NN_UNLIKELY((size) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, mr size must be correct size"); \
        return SER_INVALID_PARAM;                                    \
    }

#define VALIDATE_CHANNEL(channel)                                       \
    if (NN_UNLIKELY((channel) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, channel must be correct address"); \
        return SER_INVALID_PARAM;                                       \
    }

#define VALIDATE_CHANNEL_NO_RET(channel)                                \
    if (NN_UNLIKELY((channel) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, channel must be correct address"); \
        return;                                                         \
    }

#define VALIDATE_MESSAGE(req)                                           \
    if (NN_UNLIKELY((req) == nullptr)) {                                \
        NN_LOG_ERROR("Invalid param, message must be correct address"); \
        return SER_INVALID_PARAM;                                       \
    }

#define COPY_ONESIDE_KEY(input, output)                                 \
    for (uint32_t i = 0; i < NN_NO4; i++) {                             \
        (output).keys[i] = (input).keys[i];                             \
        (output).tokens[i] = (input).tokens[i];                         \
    }

#define VALIDATE_CONTEXT(context)                                       \
    if (NN_UNLIKELY((context) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, context should be correct address"); \
        return SER_INVALID_PARAM;                                       \
    }

#define VALIDATE_CONTEXT_RETURN_PTR(context)                            \
    if (NN_UNLIKELY((context) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, context should be correct address"); \
        return nullptr;                                                 \
    }

#define VALIDATE_CONTEXT_RETURN_ZERO(context)                           \
    if (NN_UNLIKELY((context) == 0)) {                                  \
        NN_LOG_ERROR("Invalid param, context should be correct address"); \
        return 0;                                                       \
    }

static ServiceHdlMgr<ServiceHdlAdp> g_serviceHandlerManager;
static ServiceHdlMgr<ServiceIdleHdlAdp> g_serviceIdleHandlerManager;
static ServiceHdlMgr<ChannelOpHdlAdp> g_channelHandlerManager;
static ServiceHdlMgr<OOBSecInfoProviderAdp> g_secProVider;
static ServiceHdlMgr<OOBSecInfoValidatorAdp> g_secValidator;
static ServiceHdlMgr<EpTLSHdlAdp> g_TlsHdl;

static bool IsNumberStr(const std::string &str)
{
    std::regex pattern("^[0-9]+$");
    return std::regex_match(str, pattern);
}

static bool ConvertCpuIdsRangeStrToPair(const char *cpuIdsStr, std::pair<uint32_t, uint32_t> &cpuIdsPair)
{
    std::string cpuRangeStr = std::string(cpuIdsStr); // 1-2
    if (cpuRangeStr.empty()) {
        return true;
    }
    if (NN_UNLIKELY(NetFunc::NN_ValidateName(cpuRangeStr) != NN_OK)) {
        NN_LOG_ERROR("Invalid cpu id");
        return false;
    }
    std::string::size_type pos = cpuRangeStr.find("-");
    if (pos == std::string::npos) {
        NN_LOG_ERROR("Invalid workerGroupCpuRange: " << cpuRangeStr);
        return false;
    }
    std::string beginNumStr = cpuRangeStr.substr(0, pos);
    std::string endNumStr = cpuRangeStr.substr(pos + 1);
    if (NN_UNLIKELY(!IsNumberStr(beginNumStr) || !IsNumberStr(endNumStr))) {
        NN_LOG_ERROR("Invalid workerGroupCpuRange: " << cpuRangeStr);
        return false;
    }

    long beginId = 0;
    long endId = 0;
    if (!NetFunc::NN_Stol(beginNumStr, beginId) || !NetFunc::NN_Stol(endNumStr, endId)) {
        NN_LOG_ERROR("Invalid begin id " << beginNumStr << " or end id: " << endNumStr);
        return false;
    }
    cpuIdsPair = {static_cast<uint32_t>(beginId), static_cast<uint32_t>(endId)};
    NN_LOG_DEBUG("Convert Cpu ids pair:" << beginId << "," << endId);
    return true;
}

static bool ConvertServiceOptionsToInnerOptions(const ubs_hcom_service_options &options,
    UBSHcomServiceOptions &innerOptions)
{
    innerOptions.maxSendRecvDataSize =
        options.maxSendRecvDataSize != 0 ? options.maxSendRecvDataSize : NN_NO1024 ;
    innerOptions.workerGroupId = options.workerGroupId;
    innerOptions.workerGroupThreadCount =
        options.workerGroupThreadCount != 0 ? options.workerGroupThreadCount : NN_NO1;
    if (options.workerGroupMode == C_SERVICE_BUSY_POLLING) {
        innerOptions.workerGroupMode = UBSHcomWorkerMode::NET_BUSY_POLLING;
    } else if (options.workerGroupMode == C_SERVICE_EVENT_POLLING) {
        innerOptions.workerGroupMode = UBSHcomWorkerMode::NET_EVENT_POLLING;
    }

    std::pair<uint32_t, uint32_t> cpuIdsRange = {UINT32_MAX, UINT32_MAX};
    if (NN_UNLIKELY(!ConvertCpuIdsRangeStrToPair(options.workerGroupCpuRange, cpuIdsRange))) {
        NN_LOG_ERROR("Invalid cpuIdsRange, for example: 1-2 means cpu 1 to cpu 2");
        return false;
    }
    innerOptions.workerGroupCpuIdsRange = cpuIdsRange;
    return true;
}

static void ConvertServiceConnectOptionsToInnerOptions(const ubs_hcom_service_connect_options &options,
    UBSHcomConnectOptions &innerOptions)
{
    innerOptions.clientGroupId = options.clientGroupId;
    innerOptions.serverGroupId = options.serverGroupId;
    innerOptions.linkCount = options.linkCount;
    if (options.mode == C_CLIENT_WORKER_POLL) {
        innerOptions.mode = UBSHcomClientPollingMode::WORKER_POLL;
    } else if (options.mode == C_CLIENT_SELF_POLL_BUSY) {
        innerOptions.mode = UBSHcomClientPollingMode::SELF_POLL_BUSY;
    } else if (options.mode == C_CLIENT_SELF_POLL_EVENT) {
        innerOptions.mode = UBSHcomClientPollingMode::SELF_POLL_EVENT;
    }
    if (options.cbType == C_CHANNEL_FUNC_CB) {
        innerOptions.cbType = UBSHcomChannelCallBackType::CHANNEL_FUNC_CB;
    } else if (options.cbType == C_CHANNEL_GLOBAL_CB) {
        innerOptions.cbType = UBSHcomChannelCallBackType::CHANNEL_GLOBAL_CB;
    }
    innerOptions.payload = NN_CHAR_ARRAY_TO_STRING(options.payLoad);
}

static void ConvertServiceTypeToInnerServiceProto(ubs_hcom_service_type t, UBSHcomServiceProtocol &proto)
{
    switch (t) {
        case ubs_hcom_service_type::C_SERVICE_RDMA:
            proto = UBSHcomServiceProtocol::RDMA;
            break;
        case ubs_hcom_service_type::C_SERVICE_TCP:
            proto = UBSHcomServiceProtocol::TCP;
            break;
        case ubs_hcom_service_type::C_SERVICE_UDS:
            proto = UBSHcomServiceProtocol::UDS;
            break;
        case ubs_hcom_service_type::C_SERVICE_SHM:
            proto = UBSHcomServiceProtocol::SHM;
            break;
        case ubs_hcom_service_type::C_SERVICE_UBC:
            proto = UBSHcomServiceProtocol::UBC;
            break;
        default:
            proto = UBSHcomServiceProtocol::UNKNOWN;
            break;
    }
}

void ubs_hcom_channel_refer(ubs_hcom_channel channel)
{
    VALIDATE_CHANNEL_NO_RET(channel)
    reinterpret_cast<UBSHcomChannel *>(channel)->IncreaseRef();
}

void ubs_hcom_channel_derefer(ubs_hcom_channel channel)
{
    VALIDATE_CHANNEL_NO_RET(channel)
    reinterpret_cast<UBSHcomChannel *>(channel)->DecreaseRef();
}

int ubs_hcom_channel_send(ubs_hcom_channel channel, ubs_hcom_channel_request req, ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)

    UBSHcomRequest request(req.address, req.size, req.opcode);
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);

    if (cb == nullptr) {
        return innerChannel->Send(request, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_send malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }

    auto result = innerChannel->Send(request, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_call(ubs_hcom_channel channel, ubs_hcom_channel_request req, ubs_hcom_channel_response *rsp,
    ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)
    VALIDATE_MESSAGE(rsp)
    UBSHcomRequest request(req.address, req.size, req.opcode);
    UBSHcomResponse response(rsp->address, rsp->size);
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);

    SerResult ret = SER_OK;
    if (cb == nullptr) {
        ret = innerChannel->Call(request, response, nullptr);
        rsp->address = response.address;
        rsp->size = response.size;
        rsp->errorCode = response.errorCode;
        return ret;
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_call malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }

    auto result = innerChannel->Call(request, response, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_reply(ubs_hcom_channel channel, ubs_hcom_channel_request req, ubs_hcom_channel_reply_context ctx,
    ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)

    UBSHcomRequest request(req.address, req.size, req.opcode);
    UBSHcomReplyContext replyCtx(reinterpret_cast<uintptr_t>(ctx.rspCtx), ctx.errorCode);
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);

    if (cb == nullptr) {
        return innerChannel->Reply(replyCtx, request, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_reply malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }

    auto result = innerChannel->Reply(replyCtx, request, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_put(ubs_hcom_channel channel, ubs_hcom_oneside_request req, ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)

    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    UBSHcomOneSideRequest oneSideReq {};
    oneSideReq.lAddress = reinterpret_cast<uintptr_t>(req.lAddress);
    COPY_ONESIDE_KEY(req.lKey, oneSideReq.lKey);
    oneSideReq.rAddress = reinterpret_cast<uintptr_t>(req.rAddress);
    COPY_ONESIDE_KEY(req.rKey, oneSideReq.rKey);
    oneSideReq.size = req.size;

    if (cb == nullptr) {
        return innerChannel->Put(oneSideReq, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_put malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }
    auto result = innerChannel->Put(oneSideReq, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_get(ubs_hcom_channel channel, ubs_hcom_oneside_request req, ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)

    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    UBSHcomOneSideRequest oneSideReq {};
    oneSideReq.lAddress = reinterpret_cast<uintptr_t>(req.lAddress);
    oneSideReq.rAddress = reinterpret_cast<uintptr_t>(req.rAddress);
    COPY_ONESIDE_KEY(req.lKey, oneSideReq.lKey);
    COPY_ONESIDE_KEY(req.rKey, oneSideReq.rKey);
    oneSideReq.size = req.size;

    if (cb == nullptr) {
        return innerChannel->Get(oneSideReq, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_get malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }
    auto result = innerChannel->Get(oneSideReq, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_putv(ubs_hcom_channel channel, ubs_hcom_onesidesgl_request req, ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)
    if (req.iovCount == 0 || req.iovCount > (sizeof(req.iov) / sizeof(req.iov[0]))) {
        NN_LOG_ERROR("Invalid param, iovCount must be in range [1, C_NET_SGE_MAX_IOV]");
        return SER_INVALID_PARAM;
    }

    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    UBSHcomOneSideRequest onesideReq[C_NET_SGE_MAX_IOV];
    for (uint16_t i = 0; i < req.iovCount; i++) {
        auto ret = memcpy_s(&onesideReq[i], sizeof(onesideReq[i]), &req.iov[i], sizeof(req.iov[i]));
        if (ret != 0) {
            NN_LOG_ERROR("memcpy req iov failed");
            return SER_ERROR;
        }
    }
    UBSHcomOneSideSglRequest oneSideSglReq {};
    oneSideSglReq.iov = onesideReq;
    oneSideSglReq.iovCount = req.iovCount;
    if (cb == nullptr) {
        return innerChannel->PutV(oneSideSglReq, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_put malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }
    auto result = innerChannel->PutV(oneSideSglReq, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_getv(ubs_hcom_channel channel, ubs_hcom_onesidesgl_request req, ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)
    if (req.iovCount == 0 || req.iovCount > (sizeof(req.iov) / sizeof(req.iov[0]))) {
        NN_LOG_ERROR("Invalid param, iovCount must be in range [1, C_NET_SGE_MAX_IOV]");
        return SER_INVALID_PARAM;
    }

    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    UBSHcomOneSideRequest onesideReq[C_NET_SGE_MAX_IOV];
    for (uint16_t i = 0; i < req.iovCount; i++) {
        auto ret = memcpy_s(&onesideReq[i], sizeof(onesideReq[i]), &req.iov[i], sizeof(req.iov[i]));
        if (ret != 0) {
            NN_LOG_ERROR("memcpy req iov failed");
            return SER_ERROR;
        }
    }
    UBSHcomOneSideSglRequest oneSideSglReq {};
    oneSideSglReq.iov = onesideReq;
    oneSideSglReq.iovCount = req.iovCount;

    if (cb == nullptr) {
        return innerChannel->GetV(oneSideSglReq, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_get malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }
    auto result = innerChannel->GetV(oneSideSglReq, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_putv_rail(ubs_hcom_channel channel, ubs_hcom_onesidesgl_request req, uint16_t railIdx,
    ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)
    if (req.iovCount == 0 || req.iovCount > (sizeof(req.iov) / sizeof(req.iov[0]))) {
        NN_LOG_ERROR("Invalid param, iovCount must be in range [1, C_NET_SGE_MAX_IOV]");
        return SER_INVALID_PARAM;
    }

    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    UBSHcomOneSideRequest onesideReq[C_NET_SGE_MAX_IOV];
    for (uint16_t i = 0; i < req.iovCount; i++) {
        auto ret = memcpy_s(&onesideReq[i], sizeof(onesideReq[i]), &req.iov[i], sizeof(req.iov[i]));
        if (ret != 0) {
            NN_LOG_ERROR("memcpy req iov failed");
            return SER_ERROR;
        }
    }
    UBSHcomOneSideSglRequest oneSideSglReq {};
    oneSideSglReq.iov = onesideReq;
    oneSideSglReq.iovCount = req.iovCount;
    if (cb == nullptr) {
        return innerChannel->PutVOnRail(oneSideSglReq, railIdx, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_putv_rail malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }
    auto result = innerChannel->PutVOnRail(oneSideSglReq, railIdx, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_getv_rail(ubs_hcom_channel channel, ubs_hcom_onesidesgl_request req, uint16_t railIdx,
    ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)
    if (req.iovCount == 0 || req.iovCount > (sizeof(req.iov) / sizeof(req.iov[0]))) {
        NN_LOG_ERROR("Invalid param, iovCount must be in range [1, C_NET_SGE_MAX_IOV]");
        return SER_INVALID_PARAM;
    }

    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    UBSHcomOneSideRequest onesideReq[C_NET_SGE_MAX_IOV];
    for (uint16_t i = 0; i < req.iovCount; i++) {
        auto ret = memcpy_s(&onesideReq[i], sizeof(onesideReq[i]), &req.iov[i], sizeof(req.iov[i]));
        if (ret != 0) {
            NN_LOG_ERROR("memcpy req iov failed");
            return SER_ERROR;
        }
    }
    UBSHcomOneSideSglRequest oneSideSglReq {};
    oneSideSglReq.iov = onesideReq;
    oneSideSglReq.iovCount = req.iovCount;
    if (cb == nullptr) {
        return innerChannel->GetVOnRail(oneSideSglReq, railIdx, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_getv_rail malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }
    auto result = innerChannel->GetVOnRail(oneSideSglReq, railIdx, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return SER_OK;
}

int ubs_hcom_channel_recv(ubs_hcom_channel channel, ubs_hcom_service_context ctx, uintptr_t address, uint32_t size,
    ubs_hcom_channel_callback *cb)
{
    VALIDATE_CHANNEL(channel)
    VALIDATE_CONTEXT(ctx)
    VALIDATE_MR_ADDRESS(address)
    VALIDATE_MR_SIZE(size)
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(ctx);

    if (cb == nullptr) {
        return innerChannel->Recv(*innerContext, address, size, nullptr);
    }

    ubs_hcom_channel_cb_func cbFunc = cb->cb;
    void *arg = cb->arg;
    Callback *newCallback = UBSHcomNewCallback(
        [cbFunc, arg]
        (UBSHcomServiceContext &context) { cbFunc(arg, reinterpret_cast<ubs_hcom_service_context>(&context)); },
        std::placeholders::_1);
    if (NN_UNLIKELY(newCallback == nullptr)) {
        NN_LOG_ERROR("ubs_hcom_channel_get malloc callback failed");
        return SER_NEW_OBJECT_FAILED;
    }
    auto result = innerChannel->Recv(*innerContext, address, size, newCallback);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }
    return SER_OK;
}

int ubs_hcom_channel_send_fds(ubs_hcom_channel channel, int fds[], uint32_t len)
{
    VALIDATE_CHANNEL(channel)
    return reinterpret_cast<UBSHcomChannel *>(channel)->SendFds(fds, len);
}

int ubs_hcom_channel_recv_fds(ubs_hcom_channel channel, int fds[], uint32_t len, int32_t timeoutSec)
{
    VALIDATE_CHANNEL(channel)
    return reinterpret_cast<UBSHcomChannel *>(channel)->ReceiveFds(fds, len, timeoutSec);
}

int ubs_hcom_channel_set_flowctl_cfg(ubs_hcom_channel channel, ubs_hcom_flowctl_opts opt)
{
    VALIDATE_CHANNEL(channel)
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);

    UBSHcomFlowCtrlOptions ctl {};
    ctl.intervalTimeMs = opt.intervalTimeMs;
    ctl.thresholdByte = opt.thresholdByte;
    ctl.flowCtrlLevel = static_cast<UBSHcomFlowCtrlLevel>(opt.flowCtrlLevel);
    return innerChannel->SetFlowControlConfig(ctl);
}

void ubs_hcom_channel_set_timeout(ubs_hcom_channel channel, int16_t oneSideTimeout, int16_t twoSideTimeout)
{
    VALIDATE_CHANNEL_NO_RET(channel)
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);

    innerChannel->SetChannelTimeOut(oneSideTimeout, twoSideTimeout);
}

int ubs_hcom_channel_set_twoside_threshold(ubs_hcom_channel channel, ubs_hcom_twoside_threshold threshold)
{
    VALIDATE_CHANNEL(channel)
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);

    UBSHcomTwoSideThreshold twoSideThreshold{};
    twoSideThreshold.splitThreshold = threshold.splitThreshold;
    twoSideThreshold.rndvThreshold = threshold.rndvThreshold;
    return innerChannel->SetTwoSideThreshold(twoSideThreshold);
}

uint64_t ubs_hcom_channel_get_id(ubs_hcom_channel channel)
{
    VALIDATE_CHANNEL(channel)
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);

    return innerChannel->GetId();
}

int ubs_hcom_context_get_rspctx(ubs_hcom_service_context context, ubs_hcom_channel_reply_context *rspCtx)
{
    VALIDATE_CONTEXT(context)
    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    rspCtx->rspCtx = reinterpret_cast<void *>(innerContext->RspCtx());
    return SER_OK;
}

int ubs_hcom_context_get_channel(ubs_hcom_service_context context, ubs_hcom_channel *channel)
{
    VALIDATE_CONTEXT(context)
    if (NN_UNLIKELY(channel == nullptr)) {
        NN_LOG_ERROR("Invalid param, channel must be correct address");
        return SER_INVALID_PARAM;
    }

    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    *channel = reinterpret_cast<ubs_hcom_channel>(innerContext->Channel().Get());
    return SER_OK;
}

int ubs_hcom_context_get_type(ubs_hcom_service_context context, ubs_hcom_service_context_type *type)
{
    VALIDATE_CONTEXT(context)
    if (NN_UNLIKELY(type == nullptr)) {
        NN_LOG_ERROR("Invalid param, type must be correct address");
        return SER_INVALID_PARAM;
    }

    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    *type = static_cast<ubs_hcom_service_context_type>(innerContext->OpType());
    return SER_OK;
}

int ubs_hcom_context_get_result(ubs_hcom_service_context context, int *result)
{
    VALIDATE_CONTEXT(context)
    if (NN_UNLIKELY(result == nullptr)) {
        NN_LOG_ERROR("Invalid param, result must be correct address");
        return SER_INVALID_PARAM;
    }

    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    *result = innerContext->Result();
    return SER_OK;
}

uint16_t ubs_hcom_context_get_opcode(ubs_hcom_service_context context)
{
    VALIDATE_CONTEXT(context);
    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    return innerContext->OpCode();
}

void *ubs_hcom_context_get_data(ubs_hcom_service_context context)
{
    VALIDATE_CONTEXT_RETURN_PTR(context)

    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    return innerContext->MessageData();
}

uint32_t ubs_hcom_context_get_datalen(ubs_hcom_service_context context)
{
    VALIDATE_CONTEXT_RETURN_ZERO(context)

    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    return innerContext->MessageDataLen();
}

int ubs_hcom_service_create(ubs_hcom_service_type t, const char *name, ubs_hcom_service_options options,
    ubs_hcom_service *service)
{
    if (NN_UNLIKELY(name == nullptr || service == nullptr)) {
        NN_LOG_ERROR("Invalid param, name or service is nullptr");
        return SER_INVALID_PARAM;
    }

    if (strlen(name) > NN_NO64) {
        NN_LOG_ERROR("Invalid param, name length must be than " << NN_NO64);
        return SER_INVALID_PARAM;
    }

    UBSHcomServiceOptions innerOptions;
    if (NN_UNLIKELY(!ConvertServiceOptionsToInnerOptions(options, innerOptions))) {
        NN_LOG_ERROR("Invalid options");
        return SER_INVALID_PARAM;
    }

    UBSHcomServiceProtocol proto = UBSHcomServiceProtocol::RDMA;
    ConvertServiceTypeToInnerServiceProto(t, proto);

    auto tmpService = UBSHcomService::Create(proto, name, innerOptions);
    if (tmpService == nullptr) {
        NN_LOG_ERROR("Failed to create UBSHcomService");
        return SER_NEW_OBJECT_FAILED;
    }
    *service = reinterpret_cast<ubs_hcom_service>(tmpService);
    return SER_OK;
}

int ubs_hcom_service_bind(ubs_hcom_service service, const char *listenerUrl, ubs_hcom_service_channel_handler h)
{
    VALIDATE_SERVICE(service);
    VALIDATE_HANDLER(h);
    if (NN_UNLIKELY(listenerUrl == nullptr)) {
        NN_LOG_ERROR("Invalid paraim, listenerUrl is null");
        return SER_INVALID_PARAM;
    }

    auto tmpH = new (std::nothrow) ServiceHdlAdp(
            ubs_hcom_service_channel_handler_type::C_CHANNEL_NEW, h, 0);
    if (NN_UNLIKELY(tmpH == nullptr)) {
        NN_LOG_ERROR("Failed to new channel handler adaptor, probably out of memory");
        return SER_NEW_OBJECT_FAILED;
    }
    g_serviceHandlerManager.AddHdlAdp(service, reinterpret_cast<uintptr_t>(tmpH));

    return reinterpret_cast<UBSHcomService *>(service)->Bind(listenerUrl, std::bind(&ServiceHdlAdp::NewChannel, tmpH,
        std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
}

int ubs_hcom_service_start(ubs_hcom_service service)
{
    VALIDATE_SERVICE(service);
    return reinterpret_cast<UBSHcomService *>(service)->Start();
}

int ubs_hcom_service_destroy(ubs_hcom_service service, const char *name)
{
    VALIDATE_SERVICE(service);
    if (NN_UNLIKELY(name == nullptr)) {
        NN_LOG_ERROR("Failed to destroy as name is nullptr");
        return SER_INVALID_PARAM;
    }
    g_serviceHandlerManager.RemoveAll(service);
    g_serviceIdleHandlerManager.RemoveAll(service);
    g_channelHandlerManager.RemoveAll(service);
    g_secProVider.RemoveAll(service);
    g_secValidator.RemoveAll(service);
    g_TlsHdl.RemoveAll(service);
    return reinterpret_cast<UBSHcomService *>(service)->Destroy(name);
}

int ubs_hcom_service_connect(ubs_hcom_service service, const char *serverUrl, ubs_hcom_channel *channel,
    ubs_hcom_service_connect_options options)
{
    VALIDATE_SERVICE(service);
    if (NN_UNLIKELY(serverUrl == nullptr)) {
        NN_LOG_ERROR("Failed to connect as serverUrl is nullptr");
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(channel == nullptr)) {
        NN_LOG_ERROR("Failed to connect as channel is nullptr");
        return SER_INVALID_PARAM;
    }

    UBSHcomConnectOptions innerOptions;
    ConvertServiceConnectOptionsToInnerOptions(options, innerOptions);
    UBSHcomChannelPtr tmpChannel;
    auto result  = reinterpret_cast<UBSHcomService *>(service)->Connect(serverUrl, tmpChannel, innerOptions);
    if (NN_UNLIKELY(result != NN_OK)) {
        return result;
    }

    // increase ref, need to call Channel_Destroy() to decrease ref
    tmpChannel->IncreaseRef();

    *channel = reinterpret_cast<ubs_hcom_channel>(tmpChannel.Get());
    return SER_OK;
}

int ubs_hcom_service_disconnect(ubs_hcom_service service, ubs_hcom_channel channel)
{
    VALIDATE_SERVICE(service);
    VALIDATE_CHANNEL(channel);
    auto innerChannel = reinterpret_cast<UBSHcomChannel *>(channel);
    reinterpret_cast<UBSHcomService *>(service)->Disconnect(innerChannel);
    innerChannel->DecreaseRef();
    return SER_OK;
}

int ubs_hcom_service_register_memory_region(ubs_hcom_service service, uint64_t size, ubs_hcom_memory_region *mr)
{
    VALIDATE_SERVICE(service);
    VALIDATE_MR_POINT(mr);

    auto tmpMr = new (std::nothrow) UBSHcomRegMemoryRegion;
    if (tmpMr == nullptr) {
        NN_LOG_ERROR("Failed to malloc memory");
        return SER_NEW_OBJECT_FAILED;
    }

    auto result = reinterpret_cast<UBSHcomService *>(service)->RegisterMemoryRegion(size, *tmpMr);
    if (NN_UNLIKELY(result != NN_OK)) {
        delete tmpMr;
        return result;
    }
    *mr = reinterpret_cast<ubs_hcom_memory_region>(tmpMr);
    return SER_OK;
}

int ubs_hcom_service_register_assign_memory_region(ubs_hcom_service service, uintptr_t address, uint64_t size,
    ubs_hcom_memory_region *mr)
{
    VALIDATE_SERVICE(service);
    VALIDATE_MR_POINT(mr);

    auto tmpMr = new (std::nothrow) UBSHcomRegMemoryRegion;
    if (tmpMr == nullptr) {
        NN_LOG_ERROR("Failed to malloc memory");
        return SER_NEW_OBJECT_FAILED;
    }

    auto result = reinterpret_cast<UBSHcomService *>(service)->RegisterMemoryRegion(address, size, *tmpMr);
    if (NN_UNLIKELY(result != NN_OK)) {
        delete tmpMr;
        NN_LOG_ERROR("Failed to register memory");
        return result;
    }
    *mr = reinterpret_cast<ubs_hcom_memory_region>(tmpMr);
    return SER_OK;
}

int ubs_hcom_reg_seg(ubs_hcom_service service, uintptr_t address, uint64_t size, ubs_hcom_oneside_key *key)
{
    VALIDATE_SERVICE(service);
 
    UBSHcomMemoryKey mrKey;
    auto result = memcpy_s(&mrKey, sizeof(UBSHcomMemoryKey), key, sizeof(ubs_hcom_oneside_key));
    if (result != 0) {
        NN_LOG_ERROR("Failed to register seg as memcpy_s input failed");
        return result;
    }
 
    result = reinterpret_cast<UBSHcomService *>(service)->ImportUrmaSeg(address, size, mrKey);
    if (NN_UNLIKELY(result != NN_OK)) {
        NN_LOG_ERROR("Failed to register seg");
        return result;
    }
    result = memcpy_s(key, sizeof(ubs_hcom_oneside_key), &mrKey, sizeof(UBSHcomMemoryKey));
    if (result != 0) {
        NN_LOG_ERROR("Failed to register seg as memcpy_s to output failed");
        return result;
    }
    NN_LOG_DEBUG("ImportUrmaSeg success with key: " << mrKey.keys[0] << ", size: " << size);
    return SER_OK;
}

int ubs_hcom_service_get_memory_region_info(ubs_hcom_memory_region mr, ubs_hcom_mr_info *info)
{
    VALIDATE_MR(mr);
    VALIDATE_INFO(info);

    auto tmp = reinterpret_cast<UBSHcomRegMemoryRegion *>(mr);
    if (NN_UNLIKELY(tmp == nullptr)) {
        NN_LOG_ERROR("convert to mr failed");
        return SER_ERROR;
    }
    info->lAddress = tmp->GetAddress();
    UBSHcomMemoryKey mrKey;
    tmp->GetMemoryKey(mrKey);
    if (memcpy_s(&(info->lKey), sizeof(ubs_hcom_oneside_key), &mrKey, sizeof(UBSHcomMemoryKey)) != 0) {
        NN_LOG_ERROR("copy mrkey failed!");
        return SER_ERROR;
    }

    info->size = tmp->GetSize();
    return SER_OK;
}

int ubs_hcom_service_destroy_memory_region(ubs_hcom_service service, ubs_hcom_memory_region mr)
{
    VALIDATE_SERVICE(service);
    VALIDATE_MR(mr);
    auto tmpMr = reinterpret_cast<UBSHcomRegMemoryRegion *>(mr);
    reinterpret_cast<UBSHcomService *>(service)->DestroyMemoryRegion(*tmpMr);
    delete tmpMr;
    return SER_OK;
}

void ubs_hcom_service_register_broken_handler(ubs_hcom_service service, ubs_hcom_service_channel_handler h,
    ubs_hcom_service_channel_policy policy, uint64_t usrCtx)
{
    VALIDATE_SERVICE_NO_RET(service);
    VALIDATE_HANDLER_NO_RET(h);

    auto tmpHdl = new (std::nothrow) ServiceHdlAdp(
            ubs_hcom_service_channel_handler_type::C_CHANNEL_BROKEN, h, usrCtx);
    if (NN_UNLIKELY(tmpHdl == nullptr)) {
        NN_LOG_ERROR("Failed to new channel handler adapter, probably out of memory");
        return;
    }

    reinterpret_cast<UBSHcomService *>(service)->RegisterChannelBrokenHandler(
        std::bind(&ServiceHdlAdp::ChannelBroken, tmpHdl, std::placeholders::_1),
        static_cast<UBSHcomChannelBrokenPolicy>(policy));
    g_serviceHandlerManager.AddHdlAdp(service, reinterpret_cast<uintptr_t>(tmpHdl));
    return;
}

void ubs_hcom_service_register_idle_handler(ubs_hcom_service service, ubs_hcom_service_idle_handler h, uint64_t usrCtx)
{
    VALIDATE_SERVICE_NO_RET(service)
    VALIDATE_HANDLER_NO_RET(h)

    auto tmpHdl = new (std::nothrow) ServiceIdleHdlAdp(h, usrCtx);
    if (NN_UNLIKELY(tmpHdl == nullptr)) {
        NN_LOG_ERROR("Failed to new Endpoint handler adapter, probably out of memory");
        return;
    }

    reinterpret_cast<UBSHcomService *>(service)->RegisterIdleHandler(
        std::bind(&ServiceIdleHdlAdp::Idle, tmpHdl, std::placeholders::_1));

    g_serviceIdleHandlerManager.AddHdlAdp(service, reinterpret_cast<uintptr_t>(tmpHdl));
    return;
}

void ubs_hcom_service_register_handler(ubs_hcom_service service, ubs_hcom_service_handler_type t,
    ubs_hcom_service_request_handler h, uint64_t usrCtx)
{
    VALIDATE_SERVICE_NO_RET(service)
    VALIDATE_HANDLER_NO_RET(h)

    auto tmpHdl = new (std::nothrow) ChannelOpHdlAdp(h, usrCtx);
    if (NN_UNLIKELY(tmpHdl == nullptr)) {
        NN_LOG_ERROR("Failed to new Endpoint handler adapter, probably out of memory");
        return;
    }

    if (t == C_SERVICE_REQUEST_RECEIVED) {
        reinterpret_cast<UBSHcomService *>(service)->RegisterRecvHandler(
            std::bind(&ChannelOpHdlAdp::Requested, tmpHdl, std::placeholders::_1));
    } else if (t == C_SERVICE_REQUEST_POSTED) {
        reinterpret_cast<UBSHcomService *>(service)->RegisterSendHandler(
            std::bind(&ChannelOpHdlAdp::Requested, tmpHdl, std::placeholders::_1));
    } else if (t == C_SERVICE_READWRITE_DONE) {
        reinterpret_cast<UBSHcomService *>(service)->RegisterOneSideHandler(
            std::bind(&ChannelOpHdlAdp::Requested, tmpHdl, std::placeholders::_1));
    } else {
        NN_LOG_ERROR("Unreachable");
        delete tmpHdl;
        return;
    }
    g_channelHandlerManager.AddHdlAdp(service, reinterpret_cast<uintptr_t>(tmpHdl));

    return;
}

void ubs_hcom_service_add_workergroup(ubs_hcom_service service, int8_t priority, uint16_t workerGroupId,
    uint32_t threadCount, const char *cpuIdsRange)
{
    VALIDATE_SERVICE_NO_RET(service);
    if (NN_UNLIKELY(cpuIdsRange == nullptr)) {
        NN_LOG_ERROR("Invalid cpuIdsRange, cpuIdsRange is NULL");
        return;
    }

    std::pair<uint32_t, uint32_t> cpuIdsPair;
    if (NN_UNLIKELY(!ConvertCpuIdsRangeStrToPair(cpuIdsRange, cpuIdsPair))) {
        NN_LOG_ERROR("Invalid cpuIdsRange, for example: 1-2 means cpu 1 to cpu 2");
        return;
    }
    reinterpret_cast<UBSHcomService *>(service)->AddWorkerGroup(workerGroupId, threadCount, cpuIdsPair, priority);
}

void ubs_hcom_service_add_listener(ubs_hcom_service service, const char *url, uint16_t workerCount)
{
    VALIDATE_SERVICE_NO_RET(service);
    if (NN_UNLIKELY(url == nullptr)) {
        NN_LOG_ERROR("Invalid url as url is nullptr");
        return;
    }
    reinterpret_cast<UBSHcomService *>(service)->AddListener(url, workerCount);
}

void ubs_hcom_service_set_lbpolicy(ubs_hcom_service service, ubs_hcom_service_lb_policy lbPolicy)
{
    VALIDATE_SERVICE_NO_RET(service);
    UBSHcomServiceLBPolicy policy = UBSHcomServiceLBPolicy::NET_ROUND_ROBIN;
    if (lbPolicy == SERVICE_HASH_IP_PORT) {
        policy = UBSHcomServiceLBPolicy::NET_HASH_IP_PORT;
    }
    reinterpret_cast<UBSHcomService *>(service)->SetConnectLBPolicy(policy);
}

void ubs_hcom_service_set_tls_opt(ubs_hcom_service service, bool enableTls, ubs_hcom_service_tls_version version,
    ubs_hcom_service_cipher_suite cipherSuite, ubs_hcom_tls_get_cert_cb certCb, ubs_hcom_tls_get_pk_cb priKeyCb,
    ubs_hcom_tls_get_ca_cb caCb)
{
    VALIDATE_SERVICE_NO_RET(service);

    UBSHcomTlsOptions opt;
    opt.enableTls = enableTls;
    if (!enableTls) {
        reinterpret_cast<UBSHcomService *>(service)->SetTlsOptions(opt);
        return;
    }
    if (NN_UNLIKELY(certCb == nullptr) || NN_UNLIKELY(priKeyCb == nullptr) || NN_UNLIKELY(caCb == nullptr)) {
        NN_LOG_ERROR("Failed to set tls options as cb is nullptr");
        return;
    }
    opt.tlsVersion = version == C_SERVICE_TLS_1_2 ? UBSHcomTlsVersion::TLS_1_2 : UBSHcomTlsVersion::TLS_1_3;
    if (cipherSuite == C_SERVICE_AES_GCM_128) {
        opt.netCipherSuite = UBSHcomNetCipherSuite::AES_GCM_128;
    } else if (cipherSuite == C_SERVICE_AES_GCM_256) {
        opt.netCipherSuite = UBSHcomNetCipherSuite::AES_GCM_256;
    } else if (cipherSuite == C_SERVICE_AES_CCM_128) {
        opt.netCipherSuite = UBSHcomNetCipherSuite::AES_CCM_128;
    } else if (cipherSuite == C_SERVICE_CHACHA20_POLY1305) {
        opt.netCipherSuite = UBSHcomNetCipherSuite::CHACHA20_POLY1305;
    }

    auto tmpH = new (std::nothrow) EpTLSHdlAdp();
    if (NN_UNLIKELY(tmpH == nullptr)) {
        NN_LOG_ERROR("Failed to new service tls handler adapter, probably out of memory");
        return;
    }
    tmpH->SetTLSCertCb(certCb);
    tmpH->SetTLSPrivateKeyCb(priKeyCb);
    tmpH->SetTLSCaCb(caCb);
    opt.caCb = (std::bind(&EpTLSHdlAdp::UBSHcomTLSCaCallback, tmpH, std::placeholders::_1, std::placeholders::_2,
        std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
    opt.cfCb = (std::bind(&EpTLSHdlAdp::UBSHcomTLSCertificationCallback, tmpH, std::placeholders::_1,
        std::placeholders::_2));
    opt.pkCb = (std::bind(&EpTLSHdlAdp::UBSHcomTLSPrivateKeyCallback, tmpH, std::placeholders::_1,
        std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
    g_TlsHdl.AddHdlAdp(service, reinterpret_cast<uintptr_t>(tmpH));
    reinterpret_cast<UBSHcomService *>(service)->SetTlsOptions(opt);
}

void ubs_hcom_service_set_secure_opt(ubs_hcom_service service, ubs_hcom_service_secure_type secType,
    ubs_hcom_secinfo_provider provider, ubs_hcom_secinfo_validator validator, uint16_t magic, uint8_t version)
{
    VALIDATE_SERVICE_NO_RET(service);
    if (NN_UNLIKELY(provider == nullptr) || NN_UNLIKELY(validator == nullptr)) {
        NN_LOG_ERROR("Failed to SetSecureOptions as provider or validator is nullptr");
        return;
    }

    UBSHcomConnSecureOptions opt;
    if (secType == C_SERVICE_NET_SEC_DISABLED) {
        opt.secType = UBSHcomNetDriverSecType::NET_SEC_DISABLED;
    } else if (secType == C_SERVICE_NET_SEC_ONE_WAY) {
        opt.secType = UBSHcomNetDriverSecType::NET_SEC_VALID_ONE_WAY;
    } else if (secType == C_SERVICE_NET_SEC_TWO_WAY) {
        opt.secType = UBSHcomNetDriverSecType::NET_SEC_VALID_TWO_WAY;
    }
    opt.version = version;
    opt.magic = magic;

    auto providerTmpH = new (std::nothrow) OOBSecInfoProviderAdp(provider);
    if (NN_UNLIKELY(providerTmpH == nullptr)) {
        NN_LOG_ERROR("Register Service_SecInfoProvider failed, probably out of memory");
        return;
    }
    opt.provider = std::bind(&OOBSecInfoProviderAdp::CreateSecInfo, providerTmpH, std::placeholders::_1,
        std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5,
        std::placeholders::_6);

    auto validatorTmpH = new (std::nothrow) OOBSecInfoValidatorAdp(validator);
    if (NN_UNLIKELY(validatorTmpH == nullptr)) {
        NN_LOG_ERROR("Register Service_SecInfoValidator failed, probably out of memory");
        opt.provider = nullptr;
        delete providerTmpH;
        return;
    }
    opt.validator = std::bind(&OOBSecInfoValidatorAdp::SecInfoValidate, validatorTmpH, std::placeholders::_1,
        std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);

    g_secProVider.AddHdlAdp(service, reinterpret_cast<uintptr_t>(providerTmpH));
    g_secValidator.AddHdlAdp(service, reinterpret_cast<uintptr_t>(validatorTmpH));
    reinterpret_cast<UBSHcomService *>(service)->SetConnSecureOpt(opt);
}

void ubs_hcom_service_set_tcp_usr_timeout(ubs_hcom_service service, uint16_t timeOutSec)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetTcpUserTimeOutSec(timeOutSec);
}

void ubs_hcom_service_set_tcp_send_zcopy(ubs_hcom_service service, bool tcpSendZCopy)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetTcpSendZCopy(tcpSendZCopy);
}

void ubs_hcom_service_set_ipmask(ubs_hcom_service service, const char *ipMask)
{
    VALIDATE_SERVICE_NO_RET(service);
    if (NN_UNLIKELY(ipMask == nullptr)) {
        NN_LOG_ERROR("Failed to set as ipMask is nullptr");
        return;
    }
    std::vector<std::string> ipMasks;
    NetFunc::NN_SplitStr(ipMask, ",", ipMasks);
    reinterpret_cast<UBSHcomService *>(service)->SetDeviceIpMask(ipMasks);
}

void ubs_hcom_service_set_ipgroup(ubs_hcom_service service, const char *ipGroup)
{
    VALIDATE_SERVICE_NO_RET(service);
    if (NN_UNLIKELY(ipGroup == nullptr)) {
        NN_LOG_ERROR("Failed to set as ipGroup is nullptr");
        return;
    }
    std::vector<std::string> ipGroups;
    NetFunc::NN_SplitStr(ipGroup, ",", ipGroups);
    reinterpret_cast<UBSHcomService *>(service)->SetDeviceIpGroups(ipGroups);
}

void ubs_hcom_service_set_cq_depth(ubs_hcom_service service, uint16_t depth)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetCompletionQueueDepth(depth);
}

void ubs_hcom_service_set_sq_size(ubs_hcom_service service, uint32_t sqSize)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetSendQueueSize(sqSize);
}

void ubs_hcom_service_set_rq_size(ubs_hcom_service service, uint32_t rqSize)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetRecvQueueSize(rqSize);
}

void ubs_hcom_service_set_prepost_size(ubs_hcom_service service, uint32_t prePostSize)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetQueuePrePostSize(prePostSize);
}

void ubs_hcom_service_set_polling_batchsize(ubs_hcom_service service, uint16_t pollSize)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetPollingBatchSize(pollSize);
}

void ubs_hcom_service_set_polling_timeoutus(ubs_hcom_service service, uint16_t pollTimeout)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetEventPollingTimeOutUs(pollTimeout);
}

void ubs_hcom_service_set_timeout_threadnum(ubs_hcom_service service, uint32_t threadNum)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetTimeOutDetectionThreadNum(threadNum);
}

void ubs_hcom_service_set_max_connection_cnt(ubs_hcom_service service, uint32_t maxConnCount)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetMaxConnectionCount(maxConnCount);
}

void ubs_hcom_service_set_heartbeat_opt(ubs_hcom_service service, uint16_t idleSec, uint16_t probeTimes,
    uint16_t intervalSec)
{
    VALIDATE_SERVICE_NO_RET(service);
    UBSHcomHeartBeatOptions opt;
    opt.heartBeatIdleSec = idleSec;
    opt.heartBeatProbeTimes = probeTimes;
    opt.heartBeatProbeIntervalSec = intervalSec;
    reinterpret_cast<UBSHcomService *>(service)->SetHeartBeatOptions(opt);
}

void ubs_hcom_service_set_multirail_opt(ubs_hcom_service service, bool enable, uint32_t threshold)
{
    VALIDATE_SERVICE_NO_RET(service);
    UBSHcomMultiRailOptions opt;
    opt.enable = enable;
    opt.threshold = threshold;
    reinterpret_cast<UBSHcomService *>(service)->SetMultiRailOptions(opt);
}

void ubs_hcom_service_set_enable_mrcache(ubs_hcom_service service, bool enableMrCache)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetEnableMrCache(enableMrCache);
}

void ubs_hcom_service_set_ubcmode(ubs_hcom_service service, ubs_hcom_service_ubc_mode ubcMode)
{
    VALIDATE_SERVICE_NO_RET(service);
    UBSHcomUbcMode tmpUbcMode = UBSHcomUbcMode::LowLatency;
    if (ubcMode == C_SERVICE_HIGHBANDWIDTH) {
        tmpUbcMode = UBSHcomUbcMode::HighBandwidth;
    }
    reinterpret_cast<UBSHcomService *>(service)->SetUbcMode(tmpUbcMode);
}

void ubs_hcom_service_set_max_send_recv_data_cnt(ubs_hcom_service service, uint32_t maxSendRecvDataCount)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetMaxSendRecvDataCount(maxSendRecvDataCount);
}

void ubs_hcom_service_set_ub_priority(ubs_hcom_service service, uint32_t ubPriority)
{
    VALIDATE_SERVICE_NO_RET(service);
    reinterpret_cast<UBSHcomService *>(service)->SetUbPriority(ubPriority);
}

ubs_hcom_service_context ubs_hcom_context_clone(ubs_hcom_service_context context)
{
    VALIDATE_CONTEXT_RETURN_ZERO(context)

    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    auto tmpCtx = new (std::nothrow) UBSHcomServiceContext;
    if (NN_UNLIKELY(tmpCtx == nullptr)) {
        NN_LOG_ERROR("Failed to new service ctx by oom");
        return 0;
    }

    if (NN_UNLIKELY(UBSHcomServiceContext::Clone(*tmpCtx, *innerContext) != SER_OK)) {
        delete tmpCtx;
        NN_LOG_ERROR("Failed to new service ctx by oom");
        return 0;
    }

    return reinterpret_cast<ubs_hcom_service_context>(tmpCtx);
}

void ubs_hcom_context_free(ubs_hcom_service_context context)
{
    if (NN_UNLIKELY(context == 0)) {
        NN_LOG_ERROR("Invalid param, context should be correct address");
        return;
    }
    auto innerContext = reinterpret_cast<UBSHcomServiceContext *>(context);
    if (NN_UNLIKELY(innerContext == nullptr)) {
        NN_LOG_ERROR("Failed to free service ctx by nullptr");
        return;
    }
    delete innerContext;
    return;
}