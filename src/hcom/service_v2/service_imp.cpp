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
#include "service_imp.h"

#include <arpa/inet.h>
#include <cstdint>
#include <mutex>
#include "securec.h"

#include "hcom_def.h"
#include "hcom_err.h"
#include "hcom_log.h"
#include "hcom_num_def.h"
#include "api/hcom_service_def.h"
#include "api/hcom_service.h"

#include "net_common.h"
#include "net_load_balance.h"
#include "net_mem_pool_fixed.h"
#include "net_param_validator.h"

#include "service_common.h"
#include "service_callback.h"
#include "service_periodic_manager.h"
#include "service_channel_imp.h"

namespace ock {
namespace hcom {

constexpr uint16_t MAX_ENABLE_DEVCOUNT = 4;
constexpr uint16_t MAX_TIME_OUT_DETECT_THREAD_NUM = 4;
constexpr uint16_t MAX_USER_OPCODE = 1000;
constexpr uint16_t MAX_SYS_OPCODE = 1024;

int32_t HcomServiceImp::Bind(const std::string &listenerUrl, const UBSHcomServiceNewChannelHandler &handler)
{
    VALIDATE_PARAM_RET(Bind, listenerUrl, handler);
    mOptions.chNewHandler = handler;
    NetProtocol protocal;
    std::string url;
    if (NN_UNLIKELY(!NetFunc::NN_SplitProtoUrl(listenerUrl, protocal, url))) {
        NN_LOG_ERROR("Invalid url, should be like tcp://127.0.0.1:9981 or uds://name or ubc://eid:jettyId");
        return SER_INVALID_PARAM;
    }

    mOptions.startOobSvr = true;
    if (NetProtocol::NET_TCP == protocal) {
        mOptions.oobType = NET_OOB_TCP;
        return AddTcpOobListener(url);
    } else if (NetProtocol::NET_UDS == protocal) {
        mOptions.oobType = NET_OOB_UDS;
        return AddUdsOobListener(url);
    } else if (NetProtocol::NET_UBC == protocal) {
        mOptions.oobType = NET_OOB_UB;
        std::string eid;
        uint16_t jettyId = 0;
        if (NN_UNLIKELY(!NetFunc::NN_ConvertEidAndJettyId(url, eid, jettyId))) {
            NN_LOG_ERROR("Invalid url: " << url << " should be like 1111:1111:0000:0000:0000:0000:4444:0000:888");
            return NN_PARAM_INVALID;
        }

        mOptions.eid = eid;
        mOptions.jettyId = jettyId;

        return SER_OK;
    }

    NN_LOG_ERROR("Invalid protocal, only support tcp and uds and ubc, url should be like tcp://127.0.0.1:9981 or "
                 "uds://name or ubc://eid:jettyId");
    return SER_INVALID_PARAM;
}

SerResult HcomServiceImp::AddTcpOobListener(const std::string &url, uint16_t workerCount)
{
    std::string ip;
    uint16_t port;
    if (NN_UNLIKELY(!NetFunc::NN_ConvertIpAndPort(url, ip, port))) {
        NN_LOG_ERROR("Invalid url, should be like 127.0.0.1:9981");
        return SER_INVALID_PARAM;
    }

    UBSHcomNetOobListenerOptions option;
    if (NN_UNLIKELY(!option.Set(ip, port, workerCount))) {
        NN_LOG_ERROR("Oob Tcp listener set failed");
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mOptions.oobOption.find(url) != mOptions.oobOption.end())) {
        NN_LOG_WARN("Duplicated listen ip/port adding to driver Manager " <<
            mOptions.name << ", ignored");
        return SER_INVALID_PARAM;
    }

    mOptions.oobOption[url] = option;
    return SER_OK;
}

SerResult HcomServiceImp::AddUdsOobListener(const std::string &url, uint16_t workerCount)
{
    std::string name;
    uint16_t perm = 0;
    if (NN_UNLIKELY(!NetFunc::NN_ConvertNameAndPerm(url, name, perm))) {
        NN_LOG_ERROR("Convert url to name and perm failed");
        return SER_INVALID_PARAM;
    }

    UBSHcomNetOobUDSListenerOptions option;
    option.perm = perm;
    if (NN_UNLIKELY(!option.Set(name, workerCount))) {
        NN_LOG_ERROR("Oob Uds listener set failed");
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mOptions.udsOobOption.find(name) != mOptions.udsOobOption.end())) {
        NN_LOG_WARN("Duplicated listen url adding to driver " << mOptions.name <<
            ", ignored");
        return SER_INVALID_PARAM;
    }

    mOptions.udsOobOption[name] = option;
    return SER_OK;
}

int32_t HcomServiceImp::Start()
{
    std::lock_guard<std::mutex> locker(mStartMutex);
    int32_t result = SER_OK;
    if (mStarted) {
        return SER_OK;
    }

    if (NN_UNLIKELY((result = ValidateServiceOption()) != SER_OK)) {
        NN_LOG_ERROR("Invalid service info, res:" << result);
        return result;
    }

    if (NN_UNLIKELY((result = CreateResource()) != SER_OK)) {
        NN_LOG_ERROR("CreateResource failed, res:" << result);
        return result;
    }
    if (NN_UNLIKELY((result = InitDriver()) != SER_OK)) {
        NN_LOG_ERROR("Driver start failed, res:" << result);
        return result;
    }

    if (NN_UNLIKELY((result = StartDriver()) != SER_OK)) {
        NN_LOG_ERROR("Driver start failed, res:" << result);
        return result;
    }

    NetPgTable *pgtable = new (std::nothrow) NetPgTable(pgdAlloc, pgdFree);
    if (NN_UNLIKELY(pgtable == nullptr)) {
        NN_LOG_ERROR("Fail to create pgTable ");
        return SER_ERROR;
    }
    mPgtable = pgtable;

    if (NN_LIKELY(mOptions.protocol != UBSHcomNetDriverProtocol::SHM
            && mOptions.protocol != UBSHcomNetDriverProtocol::UDS && !mOptions.ipMasks.empty())) {
        mOobIp = GetFilteredDeviceIP(mOptions.ipMasks[0]);
    }

    mStarted = true;
    return result;
}

SerResult HcomServiceImp::DoInitDriver()
{
    SerResult res = SER_OK;
    UBSHcomNetDriverOptions driverOpt;
    ConvertHcomSerImpOptsToHcomDriOpts(mOptions, driverOpt);
    RegisterDriverCb();
    uint16_t driverIdx = 0;
    for (auto &driver : mDriverPtrs) {
        if (!mOptions.workerGroupInfos.empty()) {
            if (driverIdx >= mOptions.workerGroupInfos.size()) {
                driverOpt.SetWorkerGroupsInfo(mOptions.workerGroupInfos[0]);
            } else {
                driverOpt.SetWorkerGroupsInfo(mOptions.workerGroupInfos[driverIdx]);
                ++driverIdx;
            }
        }
        driver->RegisterNewEPHandler(std::bind(&HcomServiceImp::ServiceHandleNewEndPoint, this,
            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        driver->RegisterEPBrokenHandler(std::bind(&HcomServiceImp::ServiceEndPointBroken, this, std::placeholders::_1));
        driver->RegisterNewReqHandler(std::bind(&HcomServiceImp::ServiceRequestReceived, this, std::placeholders::_1));
        driver->RegisterReqPostedHandler(std::bind(&HcomServiceImp::ServiceRequestPosted, this, std::placeholders::_1));
        driver->RegisterOneSideDoneHandler(std::bind(&HcomServiceImp::ServiceOneSideDone, this, std::placeholders::_1));

        if (mOptions.connSecOption.provider != nullptr) {
            driver->RegisterEndpointSecInfoProvider(std::bind(&HcomServiceImp::ServiceSecInfoProvider, this,
                std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4,
                std::placeholders::_5, std::placeholders::_6));
        }

        if (mOptions.connSecOption.validator != nullptr) {
            driver->RegisterEndpointSecInfoValidator(std::bind(&HcomServiceImp::ServiceSecInfoValidator, this,
                std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
        }

        res = driver->Initialize(driverOpt);
        if (NN_UNLIKELY(res != SER_OK)) {
            ForceStop();
            return res;
        }
    }

    if (mOptions.startOobSvr && mOptions.enableMultiRail && mOptions.protocol == UBSHcomServiceProtocol::RDMA) {
        res = CreateOobListeners(driverOpt);
        if (NN_UNLIKELY(res != SER_OK)) {
            ForceStop();
            return res;
        }

        /* set cb for listeners */
        for (auto &oobServer : mOobServers) {
            oobServer->SetNewConnCB(std::bind(&HcomServiceImp::NewConnectionCB, this, std::placeholders::_1));
            oobServer->SetNewConnCbThreadNum(driverOpt.oobConnHandleThreadCount);
            oobServer->SetNewConnCbQueueCap(driverOpt.oobConnHandleQueueCap);
        }
    }
    return SER_OK;
}

SerResult HcomServiceImp::CreateOobUdsListeners(const UBSHcomNetDriverOptions &driverOpt)
{
    if (mOptions.udsOobOption.empty()) {
        NN_LOG_ERROR("No listen info is set in driver " << mOptions.name);
        return SER_INVALID_PARAM;
    }

    if (mOptions.udsOobOption.size() > NN_NO65535) {
        NN_LOG_ERROR("udsOobOption size is over 65535 in driver " << mOptions.name);
        return SER_INVALID_PARAM;
    }

    uint16_t oobIndex = 0;
    for (auto &lOpt : mOptions.udsOobOption) {
        NetOOBServerPtr oobServer = nullptr;
        /* create oob server */
        if (driverOpt.enableTls) { // to check
            auto oobSSLServer = new (std::nothrow) OOBSSLServer(driverOpt.oobType, lOpt.second.Name(),
                lOpt.second.perm, mOptions.tlsOption.pkCb, mOptions.tlsOption.cfCb, mOptions.tlsOption.caCb);
            NN_ASSERT_LOG_RETURN(oobSSLServer != nullptr, NN_NEW_OBJECT_FAILED)
            oobSSLServer->SetTlsOptions(mOptions.tlsOption.netCipherSuite, mOptions.tlsOption.tlsVersion);
            oobSSLServer->SetPSKCallback(mOptions.tlsOption.pskFindCb, mOptions.tlsOption.pskUseCb);
            oobServer = oobSSLServer;
        } else {
            oobServer = new (std::nothrow)
                OOBTCPServer(driverOpt.oobType, lOpt.second.Name(), lOpt.second.perm, lOpt.second.isCheck);
            NN_ASSERT_LOG_RETURN(oobServer.Get() != nullptr, NN_NEW_OBJECT_FAILED)
        }
        oobServer->Index({ 0, oobIndex++ });
        oobServer->SetMaxConntionNum(driverOpt.maxConnectionNum);
        oobServer->SetMultiRail(driverOpt.enableMultiRail);
        oobServer->IncreaseRef();
        mOobServers.emplace_back(oobServer.Get());
    }

    if (mOptions.udsOobOption.size() != mOobServers.size()) {
        NN_LOG_ERROR("Created oob server count " << mOobServers.size() << " is not equal to listener options size " <<
            mOptions.udsOobOption.size() << " in uds driver " << mOptions.name);
        return SER_ERROR;
    }

    return SER_OK;
}

SerResult HcomServiceImp::CreateOobListeners(const UBSHcomNetDriverOptions &driverOpt)
{
    if (driverOpt.oobType != NET_OOB_UDS && driverOpt.oobType != NET_OOB_TCP) {
        NN_LOG_ERROR("Un-supported oob type " << driverOpt.oobType << " is set in driver Manager " <<
            mOptions.name);
        return SER_INVALID_PARAM;
    } else if (driverOpt.oobType == NET_OOB_UDS) {
        return CreateOobUdsListeners(driverOpt);
    }

    if (mOptions.oobOption.empty()) {
        NN_LOG_ERROR("No listen info is set for oob type " << UBSHcomNetDriverOobTypeToString(driverOpt.oobType) <<
            " in driver " << mOptions.name);
        return SER_INVALID_PARAM;
    }

    if (mOptions.oobOption.size() > NN_NO65535) {
        NN_LOG_ERROR("OobOption size is over 65535 in driver " << mOptions.name);
        return SER_INVALID_PARAM;
    }

    uint16_t oobIndex = 0;
    for (auto &lOpt : mOptions.oobOption) {
        NetOOBServerPtr oobServer = nullptr;
        if (driverOpt.enableTls) {
            auto oobSSLServer = new (std::nothrow) OOBSSLServer(driverOpt.oobType, lOpt.second.Ip(),
                lOpt.second.port, mOptions.tlsOption.pkCb, mOptions.tlsOption.cfCb, mOptions.tlsOption.caCb);
            NN_ASSERT_LOG_RETURN(oobSSLServer != nullptr, NN_NEW_OBJECT_FAILED)
            oobSSLServer->SetTlsOptions(mOptions.tlsOption.netCipherSuite, mOptions.tlsOption.tlsVersion);
            oobSSLServer->SetPSKCallback(mOptions.tlsOption.pskFindCb, mOptions.tlsOption.pskUseCb);
            oobServer = oobSSLServer;
        } else {
            oobServer = new (std::nothrow) OOBTCPServer(driverOpt.oobType, lOpt.second.Ip(), lOpt.second.port);
            NN_ASSERT_LOG_RETURN(oobServer.Get() != nullptr, NN_NEW_OBJECT_FAILED)
        }

        NN_LOG_TRACE_INFO(lOpt.second.Ip());
        oobServer->Index({ 0, oobIndex++ });
        oobServer->SetMaxConntionNum(driverOpt.maxConnectionNum);
        oobServer->SetMultiRail(driverOpt.enableMultiRail);
        oobServer->IncreaseRef();
        mOobServers.emplace_back(oobServer.Get());
    }

    if (mOptions.oobOption.size() != mOobServers.size()) {
        NN_LOG_ERROR("Created oob server count " << mOobServers.size() << " is not equal to listener options size " <<
            mOptions.oobOption.size() << " in driver " << mOptions.name);
        return SER_ERROR;
    }

    return SER_OK;
}

SerResult HcomServiceImp::InitDriver()
{
    if (mOptions.enableMultiRail && mOptions.protocol == UBSHcomServiceProtocol::RDMA) {
        if (CreateMultiRailDriver() != SER_OK) {
            NN_LOG_ERROR("failed to create driver for service " << mOptions.name);
            return SER_ERROR;
        }
        return DoInitDriver();
    }

    UBSHcomNetDriver *driver = UBSHcomNetDriver::Instance(mOptions.protocol, mOptions.name, mOptions.startOobSvr);
    if (driver == nullptr) {
        NN_LOG_ERROR("failed to create driver for service " << mOptions.name);
        return SER_ERROR;
    }
    mDriverPtrs.emplace_back(driver);

    if (mOptions.startOobSvr) {
        for (auto &option : mOptions.oobOption) {
            driver->AddOobOptions(option.second);
        }
        for (auto &option : mOptions.udsOobOption) {
            driver->AddOobUdsOptions(option.second);
        }

        if (mOptions.oobType == NET_OOB_UB) {
            driver->OobEidAndJettyId(mOptions.eid, mOptions.jettyId);
        }
    }
    return DoInitDriver();
}


SerResult HcomServiceImp::CreateMultiRailDriver()
{
    uint16_t enableDevCount = 0;
    std::string ipMasksStr;
    NetFunc::NN_VecStrToStr(mOptions.ipMasks, ",", ipMasksStr);
    std::string ipGroupsStr;
    NetFunc::NN_VecStrToStr(mOptions.ipGroups, ";", ipGroupsStr);

    if (NN_UNLIKELY(!UBSHcomNetDriver::MultiRailGetDevCount(mOptions.protocol, ipMasksStr, enableDevCount,
        ipGroupsStr))) {
        NN_LOG_ERROR("Failed to new multi rail service, because not get active RDMA devices. ");
        return SER_ERROR;
    }

    if (NN_UNLIKELY((enableDevCount == 0) || (enableDevCount > MAX_ENABLE_DEVCOUNT))) {
        NN_LOG_ERROR("The number of available devices is " << enableDevCount << ", only 1~" << MAX_ENABLE_DEVCOUNT <<
            " driver is allowed in MultiRail Service.");
        return SER_ERROR;
    }
    mDriverPtrs.reserve(enableDevCount);
    for (uint16_t i = 0; i < enableDevCount; i++) {
        UBSHcomNetDriver *driver = UBSHcomNetDriver::Instance(mOptions.protocol,
            mOptions.name + "_" + std::to_string(i), mOptions.startOobSvr);
        if (NN_UNLIKELY(driver == nullptr)) {
            NN_LOG_WARN("Failed to new driver in devIndex " << i << "for " << RDMA);
            continue;
        }
        driver->SetDeviceId(i);
        NN_LOG_INFO("create driver " << driver->Name());
        mDriverPtrs.emplace_back(driver);
        driver->IncreaseRef();
    }
    return SER_OK;
}

SerResult HcomServiceImp::StartDriver()
{
    SerResult result = SER_OK;
    for (auto &driver : mDriverPtrs) {
        result = driver->Start();
        if (NN_UNLIKELY(result != SER_OK)) {
            ForceStop();
            return result;
        }
    }

    if (!mOptions.startOobSvr) {
        return SER_OK;
    }

    for (uint32_t i = 0; i < mOobServers.size(); i++) {
        if (NN_UNLIKELY(mOobServers[i] == nullptr)) {
            for (uint32_t j = 0; j < i; j++) {
                mOobServers[j]->Stop();
            }
            return result;
        }
        if ((result = mOobServers[i]->Start()) != SER_OK) {
            for (uint32_t j = 0; j < i; j++) {
                mOobServers[j]->Stop();
            }
            return result;
        }
    }
    return SER_OK;
}

void HcomServiceImp::ForceStop()
{
    for (auto &server : mOobServers) {
        server->Stop();
        server->DecreaseRef();
    }
    mOobServers.clear();

    for (auto &driver : mDriverPtrs) {
        driver->Stop();
    }

    for (const auto& pair : mChannelMap) {
        UBSHcomChannelPtr channel = pair.second;
        Disconnect(channel);
    }

    if (mPeriodicMgr.Get() != nullptr) {
        mPeriodicMgr->Stop();
    }

    for (auto &driver : mDriverPtrs) {
        driver->UnInitialize();
        UBSHcomNetDriver::DestroyInstance(driver->Name());
    }
    mDriverPtrs.clear();

    if (mPeriodicMgr.Get() != nullptr) {
        mPeriodicMgr->Stop();
        mPeriodicMgr.Set(nullptr);
    }

    if (mContextMemPool.Get() != nullptr) {
        mContextMemPool.Set(nullptr);
    }

    if (mPgtable.Get() != nullptr) {
        mPgtable->Cleanup();
        mPgtable.Set(nullptr);
    }
    mStarted = false;
}

void HcomServiceImp::RegisterDriverCb()
{
    if (NN_UNLIKELY(mOptions.tlsOption.enableTls)) {
        for (auto &driver : mDriverPtrs) {
            driver->RegisterTLSCaCallback(mOptions.tlsOption.caCb);
            driver->RegisterTLSCertificationCallback(mOptions.tlsOption.cfCb);
            driver->RegisterTLSPrivateKeyCallback(mOptions.tlsOption.pkCb);
            driver->RegisterPskFindSessionCb(mOptions.tlsOption.pskFindCb);
            driver->RegisterPskUseSessionCb(mOptions.tlsOption.pskUseCb);
        }
    }
}

SerResult HcomServiceImp::ValidateServiceOption()
{
    if (NN_UNLIKELY(mOptions.timeOutDetectThreadNum == 0
        || mOptions.timeOutDetectThreadNum > MAX_TIME_OUT_DETECT_THREAD_NUM)) {
        NN_LOG_ERROR("Invalid time out detect thread num " << mOptions.timeOutDetectThreadNum << ", must range [1, 4]");
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mOptions.chBrokenHandler == nullptr)) {
        NN_LOG_ERROR("Invoke RegisterChannelBrokenHandler to register callback first");
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mOptions.recvHandler == nullptr)) {
        NN_LOG_ERROR("Invoke RegisterRecvHandler to register callback first");
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mOptions.sendHandler == nullptr)) {
        NN_LOG_ERROR("Invoke RegisterSendHandler to register callback first");
        return SER_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mOptions.oneSideDoneHandler == nullptr)) {
        NN_LOG_ERROR("Invoke RegisterOneSideHandler to register callback first");
        return SER_INVALID_PARAM;
    }

    return SER_OK;
}

SerResult HcomServiceImp::CreateResource()
{
    SerResult res = SER_OK;
    if ((res = CreatePeriodicMgr()) != SER_OK) {
        NN_LOG_ERROR("CreatePeriodicMgr failed");
        return res;
    }

    if ((res = CreateCtxMemPool()) != SER_OK) {
        NN_LOG_ERROR("CreateCtxStore failed");
        return res;
    }
    return res;
}

SerResult HcomServiceImp::CreatePeriodicMgr()
{
    HcomPeriodicManagerPtr periodicMgr
            = new (std::nothrow) HcomPeriodicManager(mOptions.timeOutDetectThreadNum, mOptions.name);
    if (NN_UNLIKELY(periodicMgr.Get() == nullptr)) {
        NN_LOG_ERROR("Create periodic manager failed");
        return SER_NEW_OBJECT_FAILED;
    }
    if (NN_UNLIKELY(periodicMgr->Start() != SER_OK)) {
        NN_LOG_ERROR("Start periodic manager failed");
        return SER_TIMER_NOT_WORK;
    }
    mPeriodicMgr = periodicMgr;
    return SER_OK;
}

SerResult HcomServiceImp::CreateCtxMemPool()
{
    NetMemPoolFixedOptions options = {};
    options.superBlkSizeMB = NN_NO1;
    options.minBlkSize = NN_NO64;
    if (mOptions.enableRndv) {
        options.minBlkSize = NN_NO64 * NN_NO4;
    }
    options.tcExpandBlkCnt = NN_NO256;
    NetMemPoolFixedPtr contextMemPool =
        new (std::nothrow) NetMemPoolFixed("ServiceContextTimer-" + mOptions.name, options);
    if (NN_UNLIKELY(contextMemPool.Get() == nullptr)) {
        NN_LOG_ERROR("Create mem pool failed");
        return SER_NEW_OBJECT_FAILED;
    }

    auto ret = contextMemPool->Initialize();
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Init mem pool failed");
        return SER_NEW_OBJECT_FAILED;
    }

    mContextMemPool = contextMemPool;
    return SER_OK;
}

int32_t HcomServiceImp::DoDestroy(const std::string &name)
{
    if (mStarted) {
        ForceStop();
    }
    return SER_OK;
}

int32_t HcomServiceImp::Connect(const std::string &serverUrl, UBSHcomChannelPtr &ch, const UBSHcomConnectOptions &opt)
{
    if (!mStarted) {
        NN_LOG_ERROR("Failed to validate state as service is not started");
        return SER_STOP;
    }

    VALIDATE_PARAM_RET(ConnectOptions, opt);
    SerResult res = SER_OK;

    UBSHcomChannelPtr tmpChannel;
    const uint32_t version = 0;
    SerConnInfo connInfo(version, NetUuid::GenerateUuid(mOobIp), mDriverPtrs.size(),
         mOptions.chBrokenPolicy, opt);

    res = DoConnect(serverUrl, connInfo, opt.payload, tmpChannel);
    if (NN_UNLIKELY(res != SER_OK)) {
        return res;
    }

    if (HcomEnv::RndvThreshold() != UINT32_MAX) {
        res = ExchangeTimestamp(tmpChannel.Get());
        if (NN_UNLIKELY(res != SER_OK)) {
            NN_LOG_ERROR("Failed to exchange timestamp in service connect");
            Disconnect(tmpChannel);
            return res;
        }
    }

    std::string uuid;
    if (NN_UNLIKELY(GenerateUuid(tmpChannel->GetLocalIp(), tmpChannel->GetId(), uuid) != SER_OK)) {
        res = SER_INVALID_PARAM;
        NN_LOG_ERROR("Failed to Generate uuid");
        Disconnect(tmpChannel);
        return res;
    }

    tmpChannel->SetUuid(uuid);
    tmpChannel->SetBrokenInfo(connInfo.policy, mOptions.chBrokenHandler);
    if (NN_UNLIKELY(EmplaceChannelUuid(tmpChannel) != SER_OK)) {
        res = SER_CHANNEL_ID_DUP;
        NN_LOG_ERROR("Failed to Emplace uuid");
        Disconnect(tmpChannel);
        return res;
    }
    tmpChannel->SetMultiRail(mOptions.enableMultiRail, mOptions.multiRailThresh);
    tmpChannel->SetDriverNum(mDriverPtrs.size());
    tmpChannel->SetPayload(opt.payload);
    ch = tmpChannel;
    return res;
}

SerResult HcomServiceImp::DoConnectInner(const std::string &serverUrl, SerConnInfo &opt, const std::string &payLoad,
    std::vector<UBSHcomNetEndpointPtr> &epVector, uint32_t &totalBandWidth)
{
    opt.totalLinkCount = opt.options.linkCount * mDriverPtrs.size();
    for (int j = 0; j < static_cast<int>(mDriverPtrs.size()); ++j) {
        opt.driverIndex = mDriverPtrs[j]->GetDeviceId();
        for (uint8_t i = 0; i < opt.options.linkCount; i++) {
            opt.index = i + j * opt.options.linkCount;
            opt.SetCrc32();
            std::string serializeConnInfo;
            if (SerConnInfo::Serialize(opt, payLoad, serializeConnInfo) != SER_OK) {
                NN_LOG_ERROR("Failed to serializable payload for connect");
                return SER_INVALID_PARAM;
            }

            UBSHcomNetEndpointPtr ep;
            auto result = mDriverPtrs[j]->Connect(serverUrl, serializeConnInfo, ep,
                static_cast<uint32_t>(opt.options.mode), opt.options.serverGroupId, opt.options.clientGroupId,
                opt.channelId);
            if (NN_LIKELY(result == SER_OK)) {
                epVector.emplace_back(ep);
                continue;
            }
            // 失败处理
            for (auto &iter : epVector) {
                iter->Close();
            }
            {
                std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
                mSecInfoMap.erase(opt.channelId);
                return result;
            }
        }
        totalBandWidth += mDriverPtrs[j]->GetBandWidth();
    }
    return SER_OK;
}

SerResult HcomServiceImp::DoConnect(const std::string &serverUrl, SerConnInfo &opt, const std::string &payLoad,
    UBSHcomChannelPtr &channel)
{
    SerResult res = SER_OK;
    std::vector<UBSHcomNetEndpointPtr> epVector;
    epVector.reserve(opt.options.linkCount * mDriverPtrs.size());
    uint32_t totalBandWidth = 0;
    res = DoConnectInner(serverUrl, opt, payLoad, epVector, totalBandWidth);
    if (NN_UNLIKELY(res != SER_OK)) {
        return res;
    }

    bool selfPoll = (opt.options.mode == UBSHcomClientPollingMode::SELF_POLL_BUSY ||
                     opt.options.mode == UBSHcomClientPollingMode::SELF_POLL_EVENT);

    UBSHcomChannelPtr tmpChannel = new (std::nothrow)
            HcomChannelImp(opt.channelId, selfPoll, opt.options, Protocol(), mOptions.maxSendRecvDataSize);
    if (NN_UNLIKELY(tmpChannel == nullptr)) {
        NN_LOG_ERROR("Failed to new channel obj");
        for (auto &iter : epVector) {
            iter->Close();
        }
        std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
        mSecInfoMap.erase(opt.channelId);
        return SER_NEW_OBJECT_FAILED;
    }

    tmpChannel->SetEnableMrCache(mEnableMrCache);

    if (NN_UNLIKELY(tmpChannel->Initialize(epVector, reinterpret_cast<uintptr_t>(mContextMemPool.Get()),
        reinterpret_cast<uintptr_t>(mPeriodicMgr.Get()), reinterpret_cast<uintptr_t>(mPgtable.Get()),
        mOptions.ctxStoreCapacity))) {
        for (auto &iter : epVector) {
            if (iter != nullptr) {
                iter->Close();
            }
        }
        std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
        mSecInfoMap.erase(opt.channelId);
        return SER_NEW_OBJECT_FAILED;
    }
    tmpChannel->SetTotalBandWidth(totalBandWidth);
    NN_LOG_INFO(tmpChannel->ToString());
    channel = tmpChannel;
    std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
    mSecInfoMap.erase(opt.channelId);
    return SER_OK;
}

void HcomServiceImp::DoChooseDriver(uint8_t devInex, uint8_t bandWidth,
    int8_t &selectDevIndex, uint8_t &selectBandWidth, UBSHcomNetDriver *&driver)
{
    bool isUsed = false;
    for (auto it = mDriverPair.begin(); it != mDriverPair.end(); ++it) {
        if (it->second == devInex) {
            // The peer driver has established, which is not the first time
            isUsed = true;
            selectDevIndex = it->first;
            break;
        }
    }
    if (isUsed) {
        for (auto driverPtr : mDriverPtrs) {
            if (driverPtr->GetDeviceId() == selectDevIndex) {
                driver = driverPtr.Get();
            }
        }
        return;
    }
    // 1. find driver
    for (uint16_t i = 0; i < static_cast<uint16_t>(mDriverPtrs.size()); ++i) {
        selectBandWidth = mDriverPtrs[i]->GetBandWidth();
        selectDevIndex = mDriverPtrs[i]->GetDeviceId();

        // 1.1 find the driver maximum bandwidth
        if (bandWidth > selectBandWidth) {
            continue;
        }
        // 1.2 Used or Not
        bool isFound = false;
        for (int j = 0; j < static_cast<int>(mUseId.size()); ++j) {
            if (mUseId[j] == selectDevIndex) {
                isFound = true;
                break;
            }
        }

        if (isFound) {
            // 1.2.1 Already used
            continue;
        }
        // 1.2.2 find
        mUseId.emplace_back(selectDevIndex);
        mDriverPair.emplace(selectDevIndex, devInex);
        break;
    }

    // 2. if no found, random select a driver.
    auto innerIdx = __sync_fetch_and_add(&mDriverIndex, 1) % mDriverPtrs.size();
    driver = mDriverPtrs[innerIdx].Get();
    selectDevIndex = driver->GetDeviceId();
    mDriverPair.emplace(selectDevIndex, devInex);
}

SerResult HcomServiceImp::ChooseDriver(OOBTCPConnection &conn, UBSHcomNetDriver *&driver)
{
    ConnectHeader header{};
    void *receiveBuf = &header;
    auto result = conn.Receive(receiveBuf, sizeof(ConnectHeader));
    if (result != 0) {
        NN_LOG_ERROR("Failed to receive specified device info , result " << result);
        return result;
    }
    uint8_t bandWidth = header.bandWidth;
    uint8_t devInex = header.devIndex;
    uint8_t selectBandWidth = 0;
    int8_t selectDevIndex = -1;
    DoChooseDriver(devInex, bandWidth, selectDevIndex, selectBandWidth, driver);

    if (NN_UNLIKELY(driver == nullptr)) {
        NN_LOG_ERROR("Failed to select driver when peer connect. ");
        return SER_ERROR;
    }
    selectBandWidth = driver->GetBandWidth();
    driver->SetPeerDevId(devInex);
    ConnectHeader driverHeader;
    SetDriverConnHeader(driverHeader, selectBandWidth, static_cast<uint8_t>(selectDevIndex));
    result = conn.Send(&driverHeader, sizeof(ConnectHeader));
    if (result != 0) {
        NN_LOG_ERROR("Send driver info to client failed " << driver->Name() << ", result " << result);
    }
    return result;
}

SerResult HcomServiceImp::NewConnectionCB(OOBTCPConnection &conn)
{
    // choose driver
    UBSHcomNetDriver *driver = nullptr;
    auto result = ChooseDriver(conn, driver);
    if (NN_UNLIKELY(result != SER_OK)) {
        return result;
    }

    return driver->MultiRailNewConnection(conn);
}

void HcomServiceImp::Disconnect(const UBSHcomChannelPtr &ch)
{
    if (ch.Get() != nullptr) {
        ch->UnInitialize();
    }
}
// create one mr for each driver
int32_t HcomServiceImp::RegisterMemoryRegion(uint64_t size, UBSHcomRegMemoryRegion &mr)
{
    if (mDriverPtrs.size() == 0) {
        NN_LOG_ERROR("RegisterMemoryRegion failed, as driverPtr not created");
        return NN_ERROR;
    }
    int32_t res = 0;
    auto &netMrs = mr.GetHcomMrs();
    uint32_t driverSize = mDriverPtrs.size();
    netMrs.reserve(driverSize);
    uint32_t i = 0;
    for (; i < driverSize; i++) {
        auto driverPtr = mDriverPtrs[i].Get();
        if (driverPtr == nullptr) {
            NN_LOG_ERROR("CreateMemoryRegion failed because driverPtr empty");
            break;
        }
        UBSHcomMemoryRegionPtr netMr;
        res = driverPtr->CreateMemoryRegion(size, netMr);
        if (res != 0) {
            NN_LOG_ERROR("CreateMemoryRegion failed, res:" << res);
            break;
        }
        if (mEnableMrCache) {
            res = InsertPgTable(netMr);
            if (res != SER_OK) {
                break;
            }
        }
        netMrs.emplace_back(netMr);
    }

    if (i < driverSize) {
        DestroyNetMrs(netMrs, 0, i);
    }

    return res;
}

int32_t HcomServiceImp::RegisterMemoryRegion(uintptr_t address, uint64_t size, UBSHcomRegMemoryRegion &mr)
{
    if (mDriverPtrs.size() == 0) {
        NN_LOG_ERROR("RegisterMemoryRegion failed, as driver not created");
        return NN_ERROR;
    }
    int32_t res = 0;
    auto &netMrs = mr.GetHcomMrs();
    uint32_t driverSize = mDriverPtrs.size();
    netMrs.reserve(driverSize);
    uint32_t i = 0;
    for (; i < driverSize; i++) {
        auto driver = mDriverPtrs[i].Get();
        if (driver == nullptr) {
            NN_LOG_ERROR("CreateMemoryRegion failed because driver empty");
            break;
        }
        UBSHcomMemoryRegionPtr netMr;
        res = driver->CreateMemoryRegion(address, size, netMr);
        if (res != 0) {
            NN_LOG_ERROR("CreateMemoryRegion failed, res:" << res);
            break;
        }
        if (mEnableMrCache) {
            res = InsertPgTable(netMr);
            if (res != SER_OK) {
                break;
            }
        }
        netMrs.emplace_back(netMr);
    }

    if (i < driverSize) {
        DestroyNetMrs(netMrs, 0, i);
    }

    return res;
}
 
int32_t HcomServiceImp::ImportUrmaSeg(uintptr_t address, uint64_t size, UBSHcomMemoryKey &key)
{
    if (mDriverPtrs.size() == 0) {
        NN_LOG_ERROR("RegisterMemoryRegion failed, as driver not created");
        return NN_ERROR;
    }
    int32_t res = 0;
    auto driver = mDriverPtrs[0].Get();
    if (driver == nullptr) {
        NN_LOG_ERROR("CreateMemoryRegion failed because driver empty");
        return NN_ERROR;
    }
    void *tSeg = nullptr;
    res = driver->ImportUrmaSeg(address, size, key.keys[0], &tSeg, key.eid, sizeof(key.eid));
    if (res != 0) {
        NN_LOG_ERROR("ImportUrmaSeg failed, res:" << res);
        return NN_ERROR;
    }
    key.tokens[0] = reinterpret_cast<uint64_t>(tSeg);
    NN_LOG_DEBUG("ImportUrmaSeg success, key.keys[0]:" << key.keys[0]);
    return res;
}

SerResult HcomServiceImp::InsertPgTable(UBSHcomNetMemoryRegionPtr &mr)
{
    SerResult res = SER_OK;
    PgtRegion *pgtRegion = new (std::nothrow) PgtRegion();
    if (pgtRegion == nullptr) {
        res = NN_ERROR;
        NN_LOG_ERROR("Fail to new PgtRegion, res:" << res);
        return res;
    }
    // pgtRegion [start,end)  使用pgTable首地址和(尾地址+1)需要16字节对齐,若使用UBC协议则UBC硬件限制需要支持4096字节对齐
    pgtRegion->start = mr->GetAddress();
    pgtRegion->end = mr->GetAddress() + mr->Size();
    pgtRegion->key = mr->GetLKey();
    pgtRegion->token = reinterpret_cast<uint64_t>(mr->GetMemorySeg());
    res = mPgtable->Insert(*pgtRegion);
    if (res != NN_OK) {
        NN_LOG_ERROR("CreateMemoryRegion insert pgTable fail, res:" << res);
        delete pgtRegion;
        return res;
    }
    mr->mPgRegion = reinterpret_cast<uintptr_t>(pgtRegion);
    return res;
}

void HcomServiceImp::DestroyMemoryRegion(UBSHcomRegMemoryRegion &mr)
{
    auto &netMrs = mr.GetHcomMrs();
    if (NN_UNLIKELY(netMrs.empty())) {
        NN_LOG_WARN("No need to destroy as UBSHcomMemoryRegionPtr is empty");
        return;
    }

    if (NN_UNLIKELY(netMrs.size() != mDriverPtrs.size())) {
        NN_LOG_WARN("Size of UBSHcomMemoryRegionPtr is not equal to dirvers, mr size:" << netMrs.size() <<
            ", driver size:" << mDriverPtrs.size());
        return;
    }

    DestroyNetMrs(netMrs, 0, netMrs.size());
}

void HcomServiceImp::SetEnableMrCache(bool enableMrCache)
{
    mEnableMrCache = enableMrCache;
}

void HcomServiceImp::DestroyNetMrs(std::vector<UBSHcomMemoryRegionPtr> &netMrs, uint32_t start, uint32_t end)
{
    for (uint32_t i = start; i < end; i++) {
        uintptr_t delPgRegion = netMrs[i]->mPgRegion;
        mDriverPtrs[i]->DestroyMemoryRegion(netMrs[i]);
        if (!mEnableMrCache) {
            continue;
        }
        PgtRegion *pgtRegion = reinterpret_cast<PgtRegion *>(delPgRegion);
        if (pgtRegion != nullptr) {
            SerResult res = mPgtable->Remove(*pgtRegion);
            if (res != 0) {
                NN_LOG_WARN("Unable to Remove PgTable in destroyMemoryRegion, res:" << res);
            }
            delete pgtRegion;
            netMrs[i]->mPgRegion = 0;
        }
    }
    netMrs.clear();
}

void HcomServiceImp::RegisterChannelBrokenHandler(const UBSHcomServiceChannelBrokenHandler &handler,
    const UBSHcomChannelBrokenPolicy policy)
{
    mOptions.chBrokenHandler = handler;
    mOptions.chBrokenPolicy = policy;
}

void HcomServiceImp::RegisterIdleHandler(const UBSHcomServiceIdleHandler &handler)
{
    mOptions.idleHandler = handler;
}

void HcomServiceImp::RegisterRecvHandler(const UBSHcomServiceRecvHandler &recvHandler)
{
    mOptions.recvHandler = recvHandler;
}

void HcomServiceImp::RegisterSendHandler(const UBSHcomServiceSendHandler &sendHandler)
{
    mOptions.sendHandler = sendHandler;
}

void HcomServiceImp::RegisterOneSideHandler(const UBSHcomServiceOneSideDoneHandler &oneSideDoneHandler)
{
    mOptions.oneSideDoneHandler = oneSideDoneHandler;
}

void HcomServiceImp::AddWorkerGroup(uint16_t workerGroupId, uint32_t threadCount,
    const std::pair<uint32_t, uint32_t> &cpuIdsRange, int8_t priority, uint16_t multirailIdx)
{
    if (multirailIdx >= MAX_MULTI_RAIL_NUM) {
        NN_LOG_ERROR("Invalid multirailIdx, should be in range [0, 3]");
        return;
    }
    UBSHcomWorkerGroupInfo groupInfo;
    groupInfo.threadPriority = priority;
    groupInfo.groupId = workerGroupId;
    groupInfo.threadCount = threadCount;
    groupInfo.cpuIdsRange = cpuIdsRange;
    {
        std::lock_guard<std::mutex> locker(mOptionsMutex);
        if (mOptions.workerGroupInfos.size() <= multirailIdx) {
            mOptions.workerGroupInfos.resize(multirailIdx + 1);
        }
        mOptions.workerGroupInfos[multirailIdx].emplace_back(groupInfo);
    }
}

void HcomServiceImp::AddListener(const std::string &url, uint16_t workerCount)
{
    NetProtocol protocal;
    std::string urlSuffix;
    if (NN_UNLIKELY(!NetFunc::NN_SplitProtoUrl(url, protocal, urlSuffix))) {
        NN_LOG_ERROR("Invalid url,  should be like tcp://127.0.0.1:9981 or uds://name");
        return;
    }

    if (NetProtocol::NET_TCP == protocal) {
        AddTcpOobListener(urlSuffix, workerCount);
    } else if (NetProtocol::NET_UDS == protocal) {
        AddUdsOobListener(urlSuffix, workerCount);
    }
}

void HcomServiceImp::SetConnectLBPolicy(UBSHcomServiceLBPolicy lbPolicy)
{
    mOptions.lbPolicy = lbPolicy;
}

void HcomServiceImp::SetTlsOptions(const UBSHcomTlsOptions &opt)
{
    mOptions.tlsOption = opt;
}

void HcomServiceImp::SetConnSecureOpt(const UBSHcomConnSecureOptions &opt)
{
    mOptions.connSecOption = opt;
}

void HcomServiceImp::SetTcpUserTimeOutSec(uint16_t timeOutSec)
{
    mOptions.tcpTimeOutSec = timeOutSec;
}

void HcomServiceImp::SetTcpSendZCopy(bool tcpSendZCopy)
{
    mOptions.tcpSendZCopy = tcpSendZCopy;
}

void HcomServiceImp::SetDeviceIpMask(const std::vector<std::string> &ipMasks)
{
    mOptions.ipMasks = ipMasks;
}

void HcomServiceImp::SetDeviceIpGroups(const std::vector<std::string> &ipGroups)
{
    mOptions.ipGroups = ipGroups;
}

void HcomServiceImp::SetCompletionQueueDepth(uint16_t depth)
{
    mOptions.completionQueueDepth = depth;
}

void HcomServiceImp::SetSendQueueSize(uint32_t sqSize)
{
    mOptions.qpSendQueueSize = sqSize;
}

void HcomServiceImp::SetRecvQueueSize(uint32_t rqSize)
{
    mOptions.qpRecvQueueSize = rqSize;
}

void HcomServiceImp::SetQueuePrePostSize(uint32_t prePostSize)
{
    mOptions.qpPrePostSize = prePostSize;
}

void HcomServiceImp::SetPollingBatchSize(uint16_t pollSize)
{
    mOptions.pollingBatchSize = pollSize;
}

void HcomServiceImp::SetEventPollingTimeOutUs(uint16_t pollTimeout)
{
    mOptions.eventPollingTimeOutUs = pollTimeout;
}

void HcomServiceImp::SetTimeOutDetectionThreadNum(uint32_t threadNum)
{
    mOptions.timeOutDetectThreadNum = threadNum;
}

void HcomServiceImp::SetMaxConnectionCount(uint32_t maxConnCount)
{
    mOptions.maxConnCount = maxConnCount;
}

void HcomServiceImp::SetHeartBeatOptions(const UBSHcomHeartBeatOptions &opt)
{
    mOptions.heartBeatOption = opt;
}

void HcomServiceImp::SetMultiRailOptions(const UBSHcomMultiRailOptions &opt)
{
    mOptions.enableMultiRail = opt.enable;
    mOptions.multiRailThresh = opt.threshold;
}

void HcomServiceImp::SetUbcMode(UBSHcomUbcMode ubcMode)
{
    mOptions.ubcMode = ubcMode;
}

void HcomServiceImp::SetCtxStoreCapacity(uint32_t ctxStoreCapacity)
{
    if (mStarted) {
        return;
    }

    if (ctxStoreCapacity < NN_NO128 || ctxStoreCapacity > NN_NO16777216) {
        NN_LOG_WARN("CtxStore Capacity " << ctxStoreCapacity <<
            " is invalid, must be in range [128, 16777216], set to 2097152");
        return;
    }
    mOptions.ctxStoreCapacity = ctxStoreCapacity;
}

void HcomServiceImp::SetUbPriority(uint32_t ubPriority)
{
    if (mStarted) {
        return;
    }

    if (ubPriority > NN_NO15) {
        NN_LOG_WARN("UbPrioity " << ubPriority <<
            " is invalid, must be in range [0, 15], use default value");
        return;
    }
    mOptions.ubPriority = ubPriority;
}

void HcomServiceImp::SetMaxSendRecvDataCount(uint32_t maxSendRecvDataCount)
{
    mOptions.maxSendRecvDataCount = maxSendRecvDataCount;
}

SerResult HcomServiceImp::GenerateUuid(const std::string &ipInfo, uint64_t channelId, std::string &uuid)
{
    uint32_t ip = 0;
    SerResult ret = GetIpAddressByIpPort(ipInfo, ip);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Failed to get ip address " << ipInfo << ", channel id " << channelId);
        return SER_INVALID_PARAM;
    }

    SerUuid tmpUuid(ip, channelId);

    if (NN_UNLIKELY(!tmpUuid.ToString(uuid))) {
        NN_LOG_ERROR("Failed to generate uuid");
        return SER_ERROR;
    }
    NN_LOG_TRACE_INFO("###### uuid " << uuid << ", ip port " << ipInfo << ", ip " << ip << ", channel id " <<
        channelId);
    return SER_OK;
}

SerResult HcomServiceImp::GenerateUuid(uint32_t ip, uint64_t channelId, std::string &uuid)
{
    SerUuid tmpUuid(ip, channelId);
    if (NN_UNLIKELY(!tmpUuid.ToString(uuid))) {
        NN_LOG_ERROR("Failed to generate uuid");
        return SER_ERROR;
    }
    NN_LOG_TRACE_INFO("###### uuid " << uuid << ", ip " << ip << ", channel id " << channelId);
    return SER_OK;
}

SerResult HcomServiceImp::EmplaceNewEndpoint(const UBSHcomNetEndpointPtr &newEp, ConnectingEpInfoPtr &epInfo,
    SerConnInfo &connInfo, std::string &uuid)
{
    std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
    auto iter = mNewEpMap.find(uuid);
    if (iter == mNewEpMap.end()) {
        if (NN_UNLIKELY(!VALIDATE_PARAM(SerConnInfo, connInfo))) {
            NN_LOG_ERROR("UBSHcomService Failed to verify connection info");
            return SER_INVALID_PARAM;
        }

        epInfo = new (std::nothrow) HcomConnectingEpInfo(uuid, newEp, connInfo);
        if (NN_UNLIKELY(epInfo == nullptr)) {
            NN_LOG_ERROR("UBSHcomService Failed to new ep info");
            return SER_NEW_OBJECT_FAILED;
        }
        mNewEpMap.emplace(uuid, epInfo);
    } else {
        epInfo = iter->second;
        if (NN_UNLIKELY(epInfo == nullptr)) {
            NN_LOG_ERROR("NetService Failed as epInfo empty");
            return SER_INVALID_PARAM;
        }

        if (NN_UNLIKELY(!epInfo->Compare(connInfo))) {
            NN_LOG_ERROR("UBSHcomService Failed to validate connect info");
            return SER_INVALID_PARAM;
        }

        if (NN_UNLIKELY(!epInfo->AddEp(newEp))) {
            NN_LOG_ERROR("UBSHcomService Failed to add ep by broken");
            return SER_EP_BROKEN_DURING_CONNECTING;
        }
    }
    return SER_OK;
}

int32_t HcomServiceImp::ServiceHandleNewEndPoint(const std::string &ipPort, const UBSHcomNetEndpointPtr &newEp,
    const std::string &payload)
{
    if (NN_UNLIKELY(newEp == nullptr)) {
        NN_LOG_ERROR("Invalid newEp, newEp is nullptr");
        return SER_INVALID_PARAM;
    }

    SerConnInfo connInfo;
    std::string userPayLoad;
    if (NN_UNLIKELY(SerConnInfo::Deserialize(payload, connInfo, userPayLoad) != SER_OK)) {
        NN_LOG_ERROR("Failed to call ServiceHandlerNewEndPoint as deserialize conn info failed");
        return SER_INVALID_PARAM;
    }

    std::string uuid;
    if (NN_UNLIKELY(GenerateUuid(ipPort, connInfo.channelId, uuid) != SER_OK)) {
        NN_LOG_ERROR("Failed to generate uuid");
        return SER_INVALID_PARAM;
    }

    ConnectingEpInfoPtr epInfo = nullptr;
    if (NN_UNLIKELY(EmplaceNewEndpoint(newEp, epInfo, connInfo, uuid) != SER_OK)) {
        NN_LOG_ERROR("Failed to emplace new ep");
        return SER_INVALID_PARAM;
    }

    Ep2ChanUpCtx ctx(0, reinterpret_cast<uint64_t>(epInfo.Get()), connInfo.index);
    newEp->UpCtx(ctx.wholeUpCtx);

    if (epInfo->mEpVector.size() < connInfo.totalLinkCount) {
        // not last one
        return SER_OK;
    }
    // last one
    if (NN_UNLIKELY(!epInfo->mConnState.CAS(ConnectingEpState::NEW_EP, ConnectingEpState::NEW_CHANNEL))) {
        NN_LOG_ERROR("Failed to validate ep state, maybe some eps has broken");
        return SER_EP_BROKEN_DURING_CONNECTING;
    }
    auto result = ServiceNewChannel(ipPort, connInfo, userPayLoad, epInfo->mEpVector);

    std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
    mNewEpMap.erase(uuid);
    mSecInfoMap.erase(connInfo.channelId);
    return result;
}

int32_t HcomServiceImp::ServiceNewChannel(const std::string &ipPort, SerConnInfo &connInfo,
    const std::string &userPayLoad, std::vector<UBSHcomNetEndpointPtr> &ep)
{
    SerResult res = SER_OK;
    UBSHcomChannelPtr channel = new (std::nothrow)
            HcomChannelImp(connInfo.channelId, false, connInfo.options, Protocol(), mOptions.maxSendRecvDataSize);
    if (NN_UNLIKELY(channel == nullptr)) {
        NN_LOG_ERROR("Failed to new channel obj");
        return SER_NEW_OBJECT_FAILED;
    }
    channel->SetEnableMrCache(mEnableMrCache);
    if (NN_UNLIKELY(channel->Initialize(ep, reinterpret_cast<uintptr_t>(mContextMemPool.Get()),
        reinterpret_cast<uintptr_t>(mPeriodicMgr.Get()), reinterpret_cast<uintptr_t>(mPgtable.Get()),
        mOptions.ctxStoreCapacity))) {
        NN_LOG_ERROR("Failed to initialize channel");
        return SER_NEW_OBJECT_FAILED;
    }

    NN_LOG_INFO(channel->ToString());
    std::string uuid;
    if (NN_UNLIKELY(GenerateUuid(ipPort, channel->GetId(), uuid) != SER_OK)) {
        channel->UnInitialize();
        return SER_INVALID_PARAM;
    }

    channel->SetUuid(uuid);
    if (NN_UNLIKELY(EmplaceChannelUuid(channel) != SER_OK)) {
        NN_LOG_ERROR("Failed to emplace uuid ");
        channel->UnInitialize();
        return SER_CHANNEL_ID_DUP;
    }

    channel->SetBrokenInfo(static_cast<UBSHcomChannelBrokenPolicy>(connInfo.policy), mOptions.chBrokenHandler);
    if (NN_UNLIKELY(mOptions.chNewHandler == nullptr)) {
        NN_LOG_ERROR("Failed to invoke user cb as handler is nullptr");
        EraseChannel(reinterpret_cast<uintptr_t>(channel.Get()));
        channel->UnInitialize();
        return SER_INVALID_PARAM;
    }

    channel->SetPayload(userPayLoad);
    res = mOptions.chNewHandler(ipPort, channel, userPayLoad);
    if (NN_UNLIKELY(res != SER_OK)) {
        NN_LOG_ERROR("Failed to invoke user cb " << res);
        EraseChannel(reinterpret_cast<uintptr_t>(channel.Get()));
        channel->UnInitialize();
        return res;
    }

    return res;
}

SerResult HcomServiceImp::DelayEraseChannel(UBSHcomChannelPtr &ch, uint16_t delayTime)
{
    auto chPtr = reinterpret_cast<uintptr_t>(ch.Get());
    Callback *newCallback = UBSHcomNewCallback(&HcomServiceImp::EraseChannel, this, chPtr);
    if (newCallback == nullptr) {
        NN_LOG_ERROR("Failed to new callback obj.");
        return SER_NEW_OBJECT_FAILED;
    }
    HcomServiceCtxStore *ctxStore = ch->GetCtxStore();
    if (ctxStore == nullptr) {
        NN_LOG_ERROR("Failed to get ctx store.");
        delete newCallback;
        return SER_NEW_OBJECT_FAILED;
    }

    auto timerPtr = ctxStore->GetCtxObj<HcomServiceTimer>();
    if (NN_UNLIKELY(timerPtr == nullptr)) {
        NN_LOG_ERROR("Failed to get context object from memory pool.");
        delete newCallback;
        return SER_NEW_OBJECT_FAILED;
    }

    auto timer = new (timerPtr)HcomServiceTimer(ch.Get(), ctxStore, delayTime, reinterpret_cast<uintptr_t>(newCallback),
        HcomAsyncCBType::CBS_CHANNEL_BROKEN);
    uint32_t seqNo = 0;
    auto ret = ctxStore->PutAndGetSeqNo(timer, seqNo);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Failed to generate seqNo by context store pool.");
        ctxStore->Return(timerPtr);
        delete newCallback;
        return SER_NEW_OBJECT_FAILED;
    }

    timer->IncreaseRef();
    timer->SeqNo(seqNo);

    ret = mPeriodicMgr->AddTimer(timer);
    if (NN_UNLIKELY(ret != SER_OK)) {
        NN_LOG_ERROR("Failed to add timer in for timeout control.");
        timer->EraseSeqNo();
        ctxStore->Return(timerPtr);
        delete newCallback;
        return ret;
    }
    timer->IncreaseRef();
    return SER_OK;
}

void HcomServiceImp::EraseChannel(uintptr_t chPtr)
{
    UBSHcomChannelPtr channel = reinterpret_cast<UBSHcomChannel *>(chPtr);
    std::lock_guard<std::mutex> lockerChannel(mChannelMutex);
    mChannelMap.erase(channel->GetUuid());
}

void HcomServiceImp::ServiceEndPointBroken(const UBSHcomNetEndpointPtr &netEp)
{
    if (NN_UNLIKELY(netEp == nullptr)) {
        NN_LOG_ERROR("Failed to call ServiceEndPointBroken as netEp is null");
        return;
    }

    Ep2ChanUpCtx ctx(netEp->UpCtx());
    if (NN_UNLIKELY(ctx.wholeUpCtx == 0)) {
        NN_LOG_ERROR("Up ctx is nullptr, maybe some errors occurs during connecting");
        return;
    }

    if (ctx.connected == 0) {
        ConnectingEpInfoPtr epInfo = reinterpret_cast<HcomConnectingEpInfo *>(ctx.Ptr());
        if (NN_UNLIKELY(!epInfo->AllEPBroken(ctx.EpIdx()))) {
            return;
        }

        std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
        mNewEpMap.erase(epInfo->mUuid);
        mSecInfoMap.erase(epInfo->mConnInfo.channelId);
        return;
    }

    // channel already generate
    UBSHcomChannelPtr channel = ctx.Channel();
    if (NN_UNLIKELY(channel == nullptr)) {
        NN_LOG_ERROR("Up ctx channel is nullptr, maybe some errors occurs during connecting");
        return;
    }

    channel->SetEpBroken(ctx.EpIdx());
    if (!channel->AllEpBroken()) {
        NN_LOG_INFO("channel is not all broken");
        return;
    }

    if (!channel->NeedProcessBroken()) {
        return;
    }

    channel->SetChannelState(UBSHcomChannelState::CH_CLOSE);
    usleep(NN_NO100);
    channel->ProcessIoInBroken();
    channel->InvokeChannelBrokenCb(channel);
    NN_LOG_INFO("Channel broken, channel id " << channel->GetId());

    uint16_t delayEraseTime = channel->GetDelayEraseTime();
    // default: try delay erase channel
    if (NN_UNLIKELY(DelayEraseChannel(channel, delayEraseTime) == SER_OK)) {
        return;
    } else {
        NN_LOG_WARN("Failed to delay erase channel, now direct erase channel id  " << channel->GetId());
        EraseChannel(reinterpret_cast<uintptr_t>(channel.Get()));
    }
}

int32_t HcomServiceImp::ServiceRequestReceived(const UBSHcomRequestContext &ctx)
{
    Ep2ChanUpCtx epCtx(ctx.EndPoint()->UpCtx());
    auto ch = epCtx.Channel();
    if (NN_UNLIKELY(ch == nullptr)) {
        NN_LOG_ERROR("UBSHcomService Up context invalid, maybe broken then handle, ep Id " << ctx.EndPoint()->Id());
        return SER_ERROR;
    }
    HcomSeqNo netSeqNo(ctx.Header().seqNo);
    bool isResp = netSeqNo.IsResp();
    UBSHcomServiceContext context(ctx, ch);

    // 如果服务层消息存在头部信息...
    std::string msg;
    if (ctx.extHeaderType == UBSHcomExtHeaderType::RAW) {
        // 无服务层扩展头
    } else if (ctx.extHeaderType == UBSHcomExtHeaderType::FRAGMENT) {
        int error = 0;
        SpliceMessageResultType result = SpliceMessageResultType::INDETERMINATE;

        std::tie(result, error, msg) = ch->SpliceMessage(ctx, isResp);
        switch (result) {
            case SpliceMessageResultType::OK:
                context.mData = &msg[0];
                context.mDataLen = msg.size();
                break;

            case SpliceMessageResultType::INDETERMINATE:
            case SpliceMessageResultType::ERROR:
                return error;
        }
    }

    if (!isResp) {
        if (context.OpCode() == EXCHANGE_TIMESTAMP_OP) {
            return ServiceExchangeTimeStampHandle(context);
        }
        if (context.OpCode() == RNDV_CALL_OP_V2) {
            ServicePrivateOpHandle(context);
        }
        if (context.OpCode() < MAX_USER_OPCODE || ctx.OpType() == UBSHcomRequestContext::NN_RECEIVED_RAW) {
            auto &userHandler = mOptions.recvHandler;
            int ret = SER_OK;
            NetTrace::TraceBegin(SERVICE_CB_REQUEST_RECEIVED);
            ret = userHandler(context);
            NetTrace::TraceEnd(SERVICE_CB_REQUEST_RECEIVED, ret);
            return ret;
        } else {
            NN_LOG_ERROR("UBSHcomService Invalid op code " << context.OpCode() << ", ignore message");
            return SER_ERROR;
        }
    } else {
        uintptr_t *tmp = nullptr;
        auto ctxStorePtr = ch->GetCtxStore();
        if (NN_UNLIKELY(ctxStorePtr->GetSeqNoAndRemove(ctx.Header().seqNo, tmp) != SER_OK)) {
            HcomSeqNo dumpSeq(ctx.Header().seqNo);
            NN_LOG_ERROR("UBSHcomService Channel " << ch->GetId() << " fetch " << dumpSeq.ToString() <<
                " context failed");
            return SER_ERROR;
        }

        auto timer = reinterpret_cast<HcomServiceTimer *>(tmp);
        timer->RunCallBack(context);
        timer->MarkFinished();
        timer->DecreaseRef();
        return SER_OK;
    }
}

int32_t HcomServiceImp::ServicePrivateOpHandle(UBSHcomServiceContext &ctx)
{
    if (ctx.mDataLen != sizeof(HcomServiceRndvMessage)) {
        NN_LOG_ERROR(" Received RNDV data size is incorrect, actual size " << ctx.mDataLen << ", expected size " <<
            sizeof(UBSHcomRequest));
        return SER_ERROR;
    }

    // 将context opType设置成rndv context, 回调中用户根据opType判断是否是rndv消息
    ctx.mOpType = UBSHcomRequestContext::NN_OpType::NN_RNDV;
    HcomServiceRndvMessage *rndvMessage = static_cast<HcomServiceRndvMessage *>(ctx.mData);
    if (rndvMessage == nullptr) {
        NN_LOG_ERROR("Failed to get data in service privateOpHandle ");
        return SER_ERROR;
    }
    // opCode 设置成发送端的请求配置
    ctx.mOpCode = rndvMessage->request.opcode;
    ctx.mDataLen = rndvMessage->request.size;
    return SER_OK;
}

bool HcomServiceImp::RunRequestCallback(UBSHcomChannel *channel, const UBSHcomRequestContext &ctx,
    UBSHcomServiceContext &context)
{
    char *upCtx = nullptr;
    if (ctx.OpType() == UBSHcomRequestContext::NN_SENT || ctx.OpType() == UBSHcomRequestContext::NN_SENT_RAW ||
        ctx.OpType() == UBSHcomRequestContext::NN_READ|| ctx.OpType() == UBSHcomRequestContext::NN_WRITTEN) {
        upCtx = const_cast<char *>(ctx.OriginalRequest().upCtxData);
    } else if (ctx.OpType() == UBSHcomRequestContext::NN_SENT_RAW_SGL ||
        ctx.OpType() == UBSHcomRequestContext::NN_SGL_WRITTEN || ctx.OpType() == UBSHcomRequestContext::NN_SGL_READ) {
        upCtx = const_cast<char *>(ctx.OriginalSgeRequest().upCtxData);
    } else {
        NN_LOG_ERROR("Invalid op type " << ctx.OpType() << " for request posted");
        return false;
    }

    /* try to get callback from ctx, usually is response message type */
    Callback *done = GetServiceTransCb(upCtx);
    if (done != nullptr) {
        done->Run(context);
        return true;
    }

    uint32_t seqNo = GetServiceTransSeqNo(upCtx);
    uintptr_t *tmp = nullptr;
    auto ctxStorePtr = channel->GetCtxStore();
    if (NN_UNLIKELY(ctxStorePtr->GetSeqNoAndRemove(seqNo, tmp) != SER_OK)) {
        HcomSeqNo dumpSeq(seqNo);
        NN_LOG_ERROR("Channel " << channel->GetId() << " fetch " << dumpSeq.ToString() << " context failed");
        return false;
    }

    auto timer = reinterpret_cast<HcomServiceTimer *>(tmp);
    timer->RunCallBack(context);
    timer->MarkFinished();
    timer->DecreaseRef();
    return true;
}

int32_t HcomServiceImp::ServiceRequestPosted(const UBSHcomRequestContext &ctx)
{
    Ep2ChanUpCtx epCtx(ctx.EndPoint()->UpCtx());
    auto ch = epCtx.Channel();
    if (NN_UNLIKELY(ch == nullptr)) {
        NN_LOG_ERROR("Up context invalid, maybe broken then handle, ep Id " << ctx.EndPoint()->Id() << " result "
                                                                            << ctx.Result());
        return SER_ERROR;
    }
    UBSHcomServiceContext context(ctx, ch);

    if (ch->GetCallBackType() == UBSHcomChannelCallBackType::CHANNEL_FUNC_CB) {
        if (!IsNeedInvokeCallback(ctx)) {
            return SER_OK;
        }

        NetTrace::TraceBegin(SERVICE_CB_REQUEST_POSTED);
        if (NN_UNLIKELY(!RunRequestCallback(ch, ctx, context))) {
            NN_LOG_ERROR("Failed to get user callback for call request posted cb");
            NetTrace::TraceEnd(SERVICE_CB_REQUEST_POSTED, SER_ERROR);
            return SER_ERROR;
        }

        NetTrace::TraceEnd(SERVICE_CB_REQUEST_POSTED, SER_OK);
        return SER_OK;
    } else if (ch->GetCallBackType() == UBSHcomChannelCallBackType::CHANNEL_GLOBAL_CB) {
        if (mOptions.sendHandler == nullptr) {
            NN_LOG_ERROR("global callback channel is nullptr");
            return SER_ERROR;
        }
        return mOptions.sendHandler(context);
    } else {
        NN_LOG_ERROR("Invalid callback type " << static_cast<int32_t>(ch->GetCallBackType()) <<
            " for call request posted cb");
        return SER_ERROR;
    }
}

int32_t HcomServiceImp::ServiceOneSideDone(const UBSHcomRequestContext &ctx)
{
    Ep2ChanUpCtx epCtx(ctx.EndPoint()->UpCtx());
    auto ch = epCtx.Channel();
    if (NN_UNLIKELY(ch == nullptr)) {
        NN_LOG_ERROR("Default imp up context invalid, maybe broken then handle, ep Id " << ctx.EndPoint()->Id()
                                                                            << " result " << ctx.Result());
        return SER_ERROR;
    }

    UBSHcomServiceContext context(ctx, ch);

    if (ch->GetCallBackType() == UBSHcomChannelCallBackType::CHANNEL_FUNC_CB) {
        NetTrace::TraceBegin(SERVICE_CB_ONESIDE_DONE);
        if (NN_UNLIKELY(!RunRequestCallback(ch, ctx, context))) {
            NN_LOG_ERROR("Default imp failed to get user callback for call one side done cb");
            NetTrace::TraceEnd(SERVICE_CB_ONESIDE_DONE, SER_ERROR);
            return SER_ERROR;
        }

        NetTrace::TraceEnd(SERVICE_CB_ONESIDE_DONE, SER_OK);
        return SER_OK;
    } else if (ch->GetCallBackType() == UBSHcomChannelCallBackType::CHANNEL_GLOBAL_CB) {
        UBSHcomServiceOneSideDoneHandler &handler = mOptions.oneSideDoneHandler;
        if (handler == nullptr) {
            NN_LOG_ERROR("handle is null");
            return SER_ERROR;
        }
        return handler(context);
    } else {
        NN_LOG_ERROR("Default imp invalid callback type " << static_cast<int32_t>(ch->GetCallBackType()) <<
            " for call one side done cb");
        return SER_ERROR;
    }
}

int32_t HcomServiceImp::ServiceSecInfoProvider(uint64_t chId, int64_t &flag, UBSHcomNetDriverSecType &type,
    char *&output, uint32_t &outLen, bool &needAutoFree)
{
    bool infoExist = false;
    ConnectingSecInfo info {};
    {
        std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
        auto iter = mSecInfoMap.find(chId);
        if ((infoExist = (iter != mSecInfoMap.end()))) {
            info = iter->second;
        }
    }
    // not first call provider
    if (!info.firstCallProvider) {
        flag = info.flag;
        type = info.type;
        output = info.secContent;
        outLen = info.secContentLen;
        needAutoFree = info.needAutoFree;
        return 0;
    }
    if (NN_UNLIKELY(mOptions.connSecOption.provider == nullptr)) {
        NN_LOG_ERROR("Failed to provide secInfo as handler is nullptr");
        return SER_ERROR;
    }
    // first call provider
    auto result = mOptions.connSecOption.provider(chId, flag, type, output, outLen, needAutoFree);
    info.Initialize(flag, type, output, outLen, needAutoFree);

    std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
    if (!infoExist) {
        // case1: one-way or two-way case client first call provider, secInfo is not in map
        mSecInfoMap.emplace(chId, info);
        return result;
    }
    // case2: two-way case server first call provider, secInfo has already added to map when first call validator
    mSecInfoMap[chId] = info;
    return result;
}

int32_t HcomServiceImp::ServiceSecInfoValidator(uint64_t ctx, int64_t flag, const char *input, uint32_t inputLen)
{
    ConnectingSecInfo info {};
    bool infoExist = false;
    {
        std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
        auto iter = mSecInfoMap.find(ctx);
        if ((infoExist = (iter != mSecInfoMap.end()))) {
            info = iter->second;
        }
    }

    if (!info.firstCallValidator) {
        return 0;
    }
    if (NN_UNLIKELY(mOptions.connSecOption.validator == nullptr)) {
        NN_LOG_ERROR("Failed to validate secInfo as handler is nullptr");
        return SER_ERROR;
    }
    // first call validator
    auto result = mOptions.connSecOption.validator(ctx, flag, input, inputLen);
    info.firstCallValidator = false;

    std::lock_guard<std::mutex> lockerEp(mNewEpMutex);
    if (!infoExist) {
        // case1: one-way two-way case server first call validator, and add secInfo to map
        mSecInfoMap.emplace(ctx, info);
        return result;
    }
    // case2: two-way case client first call validator, secInfo has already added to map when first call provider
    mSecInfoMap[ctx] = info;
    return result;
}

std::string HcomServiceImp::GetFilteredDeviceIP(const std::string& ipMask)
{
    std::string res;
    std::vector<std::string> filterVec;
    NetFunc::NN_SplitStr(ipMask, ",", filterVec);
    if (filterVec.empty()) {
        NN_LOG_WARN("Invalid ip mask " << ipMask);
        return res;
    }

    std::vector<std::string> filteredIp;
    for (auto &mask : filterVec) {
        FilterIp(mask, filteredIp);
    }

    if (filteredIp.empty()) {
        NN_LOG_WARN("No matched ip found with " << ipMask);
        return res;
    }

    res = filteredIp[0];
    return res;
}

void HcomServiceImp::ConvertHcomSerImpOptsToHcomDriOpts(const HcomServiceImpOptions &serviceOpt,
    ock::hcom::UBSHcomNetDriverOptions &driverOpt)
{
    driverOpt.SetNetDeviceIpMask(serviceOpt.ipMasks);
    driverOpt.SetNetDeviceIpGroup(serviceOpt.ipGroups);
    driverOpt.enableTls = serviceOpt.tlsOption.enableTls;
    driverOpt.secType = serviceOpt.connSecOption.secType;
    driverOpt.cipherSuite = serviceOpt.tlsOption.netCipherSuite;
    driverOpt.tlsVersion = serviceOpt.tlsOption.tlsVersion;
    driverOpt.dontStartWorkers = serviceOpt.workerGroupInfos.empty();
    driverOpt.mode = serviceOpt.workerGroupMode;
    driverOpt.oobType = serviceOpt.oobType;
    driverOpt.lbPolicy = serviceOpt.lbPolicy;
    driverOpt.magic = serviceOpt.connSecOption.magic;
    driverOpt.version = serviceOpt.connSecOption.version;
    driverOpt.heartBeatIdleTime = serviceOpt.heartBeatOption.heartBeatIdleSec;
    driverOpt.heartBeatProbeTimes = serviceOpt.heartBeatOption.heartBeatProbeTimes;
    driverOpt.heartBeatProbeInterval = serviceOpt.heartBeatOption.heartBeatProbeIntervalSec;
    driverOpt.tcpUserTimeout = serviceOpt.tcpTimeOutSec;
    driverOpt.tcpSendZCopy = serviceOpt.tcpSendZCopy;

    driverOpt.mrSendReceiveSegSize = serviceOpt.maxSendRecvDataSize;
    driverOpt.completionQueueDepth = serviceOpt.completionQueueDepth;
    driverOpt.pollingBatchSize = serviceOpt.pollingBatchSize;
    driverOpt.eventPollingTimeout = serviceOpt.eventPollingTimeOutUs;
    driverOpt.qpSendQueueSize = serviceOpt.qpSendQueueSize;
    driverOpt.qpReceiveQueueSize = serviceOpt.qpRecvQueueSize;
    driverOpt.prePostReceiveSizePerQP = serviceOpt.qpPrePostSize;
    driverOpt.maxConnectionNum = serviceOpt.maxConnCount;
    driverOpt.enableMultiRail = serviceOpt.enableMultiRail;
    driverOpt.mrSendReceiveSegCount = serviceOpt.maxSendRecvDataCount;
    driverOpt.ubcMode = serviceOpt.ubcMode;
    driverOpt.ubPriority = serviceOpt.ubPriority;
}

SerResult HcomServiceImp::ExchangeTimestamp(UBSHcomChannel *channel)
{
    HcomChannelImp *ch = dynamic_cast<HcomChannelImp *>(channel);

    if (ch == nullptr) {
        NN_LOG_ERROR("Failed to exchange timestamp, ch is null ");
        return SER_ERROR;
    }

    HcomExchangeTimestamp reqTimestamp {};
    UBSHcomRequest req(&reqTimestamp, sizeof(reqTimestamp), EXCHANGE_TIMESTAMP_OP);
    HcomExchangeTimestamp rspTimestamp {};
    UBSHcomResponse rsp(&rspTimestamp, sizeof(rspTimestamp));

    reqTimestamp.deltaTimeStamp = NN_NO100;
    // deltaTimeStamp：预估的网络RTT，初始为100us，测算方式如下：
    // 首次不符合预期快速更新：delta time = call时间 * 1.2
    // 后续不符合预期指数退避：delta time = delta time * 2
    uint32_t i = 0;
    for (; i <= NN_NO16; i++) {
        reqTimestamp.timestamp = NetMonotonic::TimeUs();
        auto result = ch->SyncCallInner(req, rsp, NN_NO64);
        if (result == SER_OK) {
            uint64_t coastTime = NetMonotonic::TimeUs() - reqTimestamp.timestamp;
            if (reqTimestamp.deltaTimeStamp > coastTime) {
                break;
            }
            if (i == 0) {
                // 首次测算RTT失败，快速更新delta time
                reqTimestamp.deltaTimeStamp = coastTime + coastTime / NN_NO5;
            } else {
                reqTimestamp.deltaTimeStamp *= NN_NO2;
            }
            // if sync call operation which spend time more than delta time, try next delta time
            NN_LOG_TRACE_INFO("Delta time " << reqTimestamp.deltaTimeStamp << ", coast time " << coastTime);
            continue;
        } else {
            NN_LOG_ERROR("Failed to exchange timestamp " << result);
            return result;
        }
    }

    if (NN_UNLIKELY(i > NN_NO16)) {
        NN_LOG_ERROR("Failed to exchange timestamp");
        return SER_TIMEOUT;
    }

    ch->mConnectTimestamp.localTimeUs = reqTimestamp.timestamp;
    ch->mConnectTimestamp.remoteTimeUs = rspTimestamp.timestamp;
    ch->mConnectTimestamp.deltaTimeUs = reqTimestamp.deltaTimeStamp;
    NN_LOG_INFO("Exchange timestamp success, ch id " << ch->GetId() << ", local " << reqTimestamp.timestamp <<
        "us, remote " << rspTimestamp.timestamp << "us, delta " << reqTimestamp.deltaTimeStamp << "us");
    return SER_OK;
}

int HcomServiceImp::ServiceExchangeTimeStampHandle(UBSHcomServiceContext &ctx)
{
    if (NN_UNLIKELY(ctx.Result() != SER_OK)) {
        NN_LOG_ERROR("Exchange timestamp failed " << ctx.Result());
        return ctx.Result();
    }

    if (NN_UNLIKELY(ctx.MessageDataLen() != sizeof(HcomExchangeTimestamp))) {
        NN_LOG_ERROR("Exchange timestamp receive invalid message ");
        return SER_INVALID_PARAM;
    }

    auto timestamp = reinterpret_cast<HcomExchangeTimestamp *>(ctx.MessageData());
    if (NN_UNLIKELY(timestamp->deltaTimeStamp == NN_NO0)) {
        NN_LOG_ERROR("Exchange timestamp receive invalid delta " << timestamp->deltaTimeStamp);
        return SER_INVALID_PARAM;
    }

    if (ctx.Channel().Get() == nullptr) {
        NN_LOG_ERROR("Exchange timestamp receive invalid channel ");
        return SER_INVALID_PARAM;
    }

    HcomChannelImp *ch = dynamic_cast<HcomChannelImp *>(ctx.Channel().Get());
    if (ch == nullptr) {
        NN_LOG_ERROR("Fail to dynamic_cast channel ");
        return SER_ERROR;
    }

    ch->mConnectTimestamp.localTimeUs = NetMonotonic::TimeUs();
    ch->mConnectTimestamp.remoteTimeUs = timestamp->timestamp;
    ch->mConnectTimestamp.deltaTimeUs = timestamp->deltaTimeStamp;

    NN_LOG_INFO("Exchange timestamp success, ch id " << ch->GetId() << ", local " <<
        ch->mConnectTimestamp.localTimeUs << "us, remote " << ch->mConnectTimestamp.remoteTimeUs << "us, delta " <<
        ch->mConnectTimestamp.deltaTimeUs << "us");

    timestamp->timestamp = ch->mConnectTimestamp.localTimeUs;
    UBSHcomRequest req(timestamp, sizeof(HcomExchangeTimestamp), EXCHANGE_TIMESTAMP_OP);
    UBSHcomReplyContext replyCtx(ctx.RspCtx(), NN_NO0);
    return ctx.Channel()->Reply(replyCtx, req, HcomServiceGlobalObject::gEmptyCallback);
}
}
}

