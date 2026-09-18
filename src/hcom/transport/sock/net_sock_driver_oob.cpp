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
#include "net_sock_driver_oob.h"
#include "hcom_def.h"
#include "hcom_err.h"
#include "hcom_log.h"
#include "net_oob.h"
#include "net_oob_ssl.h"
#include "net_sock_sync_endpoint.h"
#include "net_sock_async_endpoint.h"
#include "net_sock_common.h"
#include "net_oob_secure.h"

namespace ock {
namespace hcom {
NResult NetDriverSockWithOOB::Initialize(const UBSHcomNetDriverOptions &option)
{
    std::lock_guard<std::mutex> guard(mInitMutex);
    if (mInited) {
        return NN_OK;
    }

    mOptions = option;

    NResult sockRes = NN_OK;
    if (NN_UNLIKELY((sockRes = mOptions.ValidateCommonOptions()) != NN_OK)) {
        return sockRes;
    }

    if (NN_UNLIKELY((sockRes = ValidateOptions()) != NN_OK)) {
        return sockRes;
    }

    if (NN_UNLIKELY(UBSHcomNetOutLogger::Instance() == nullptr)) {
        return NN_NOT_INITIALIZED;
    }

    if (option.enableTls) {
        if (HcomSsl::Load() != 0) {
            NN_LOG_ERROR("[Sock] Failed to load openssl API");
            return NN_NOT_INITIALIZED;
        }
    }
    mEnableTls = option.enableTls;
    NN_LOG_INFO("Try to initialize driver '" << mName << "' with " << mOptions.ToStringForSock());

    if ((sockRes = CreateWorkerResource()) != NN_OK) {
        NN_LOG_ERROR("[Sock] failed to create worker resource");
        UnInitializeInner();
        return sockRes;
    }

    /* create workers */
    if ((sockRes = CreateWorkers()) != NN_OK) {
        NN_LOG_ERROR("[Sock] failed to create workers");
        UnInitializeInner();
        return sockRes;
    }

    /* create lb for client */
    if ((sockRes = CreateClientLB()) != NN_OK) {
        NN_LOG_ERROR("[Sock] failed to create client lb");
        UnInitializeInner();
        return sockRes;
    }

    /* create oob */
    if (mStartOobSvr) {
        if ((sockRes = CreateListeners()) != NN_OK) {
            NN_LOG_ERROR("[Sock] failed to create listeners");
            UnInitializeInner();
            return sockRes;
        }
    }

    mMrChecker.Reserve(NN_NO128);
    mMrChecker.SetLockWhenOperates(false);

    mInited = true;
    return NN_OK;
}

void NetDriverSockWithOOB::UnInitialize()
{
    std::lock_guard<std::mutex> guard(mInitMutex);
    if (!mInited) {
        return;
    }
    if (mStarted) {
        NN_LOG_WARN("Unable to unInitialize sock driver" << " " << mName << " which is not stopped");
        return;
    }

    UnInitializeInner();
    mInited = false;
}

void NetDriverSockWithOOB::UnInitializeInner()
{
    if (mOpCtxMemPool != nullptr) {
        mOpCtxMemPool.Set(nullptr);
    }

    if (mSglCtxMemPool != nullptr) {
        mSglCtxMemPool.Set(nullptr);
    }

    if (mHeaderReqMemPool != nullptr) {
        mHeaderReqMemPool.Set(nullptr);
    }

    if (mSockDriverSendMR != nullptr) {
        mSockDriverSendMR->DecreaseRef();
        mSockDriverSendMR = nullptr;
    }

    for (auto oobServer : mOobServers) {
        oobServer->DecreaseRef();
    }
    mOobServers.clear();
    if (!mEndPoints.empty()) {
        mEndPoints.clear();
    }
    ClearWorkers();
    DestroyClientLB();
}

NResult NetDriverSockWithOOB::ValidateOptions()
{
    /* validate param related to device IpMask for RDMA and Sock */
    if (NN_UNLIKELY(!ValidateArrayOptions(mOptions.netDeviceIpMask, NN_NO256))) {
        NN_LOG_ERROR("Option 'netDeviceIpMask' is invalid, " << mOptions.netDeviceIpMask <<
            " is set in driver,the Array max length is 256.");
        return NN_INVALID_PARAM;
    }

    /* validate params related to tcp connection send and receive buffer size in kernel for Sock */
    if (NN_UNLIKELY(mOptions.tcpSendBufSize > NN_NO4096)) {
        NN_LOG_ERROR("Option 'tcpSendBufSize is invalid, " << mOptions.tcpSendBufSize <<
            " is set in driver, the valid value range is 0 ~ 4MB");
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(mOptions.tcpReceiveBufSize > NN_NO4096)) {
        NN_LOG_ERROR("Option 'tcpReceiveBufSize is invalid, " << mOptions.tcpReceiveBufSize <<
            " is set in driver, the valid value range is 0 ~ 4MB");
        return NN_INVALID_PARAM;
    }

    if (mSockType == SOCK_TCP || mSockType == SOCK_UDS_TCP) {
        std::vector<std::string> filters;
        NetFunc::NN_SplitStr(mOptions.NetDeviceIpMask(), ",", filters);
        if (filters.empty()) {
            NN_LOG_ERROR("Invalid ip mask '" << mOptions.netDeviceIpMask << "' is set, example '192.168.100.0/24'");
            return NN_INVALID_IP;
        }

        std::vector<std::string> matchIps;
        for (auto &mask : filters) {
            FilterIp(mask, matchIps);
        }

        if (matchIps.empty()) {
            NN_LOG_ERROR("No matched ip found with '" << mOptions.netDeviceIpMask << "', example '192.168.100.0/24'");
            return NN_INVALID_IP;
        }

        mFilteredIps.swap(matchIps);

        if (mStartOobSvr && mOobListenOptions.empty()) {
            NN_LOG_ERROR("No listening ip and port is set in driver " << mName);
            return NN_INVALID_PARAM;
        }
    }

    /* validate options */
    if (mOptions.mode == NET_BUSY_POLLING) {
        mOptions.mode = NET_EVENT_POLLING;
        NN_LOG_WARN("Busy polling is not supported in TCP/UDS driver, changed to event mode in driver " << mName);
    }

    if (NN_UNLIKELY(ValidateAndParseOobPortRange(mOptions.oobPortRange) != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(ValidateOptionsOobType() != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    return NN_OK;
}

NResult NetDriverSockWithOOB::CreateWorkers()
{
    NResult result = NN_OK;

    std::vector<uint16_t> workerGroups;
    std::vector<std::pair<uint8_t, uint8_t>> workerGroupCpus;
    std::vector<int16_t> flatWorkerCpus;
    std::vector<int16_t> workerThreadPriority;

    /* parse */
    if (!(NetFunc::NN_ParseWorkersGroups(mOptions.WorkGroups(), workerGroups)) ||
        !(NetFunc::NN_ParseWorkerGroupsCpus(mOptions.WorkerGroupCpus(), workerGroupCpus)) ||
        !(NetFunc::NN_FinalizeWorkerGroupCpus(workerGroups, workerGroupCpus, true, flatWorkerCpus)) ||
        !(NetFunc::NN_ParseWorkersGroupsThreadPriority(mOptions.WorkerGroupThreadPriority(),
        workerThreadPriority, workerGroups.size()))) {
            NN_LOG_ERROR("[Sock] Failed to parse worker or cpu groups");
        return NN_INVALID_PARAM;
    }

    SockWorkerOptions options;
    options.SetValue(mOptions, mStartOobSvr);
    if ((mOptions.workerThreadPriority != 0) && (!workerThreadPriority.empty())) {
        NN_LOG_WARN("Driver options 'workerThreadPriority' and 'workerGroupsThreadPriority' set all, preferential use "
            "'workerGroupsThreadPriority'");
    }
    /* create workers */
    mWorkers.reserve(flatWorkerCpus.size());
    uint32_t groupIndex = 0;
    uint16_t totalWorkerIndex = 0;
    UBSHcomNetWorkerIndex workerIndex {};
    for (auto item : workerGroups) {
        /* The left of mWorkerGroups is the index of each group's first worker in the mWorkers */
        mWorkerGroups.emplace_back(totalWorkerIndex, item);
        for (uint32_t i = 0; i < item; ++i) {
            options.cpuId = flatWorkerCpus.at(totalWorkerIndex++);
            if (!workerThreadPriority.empty()) {
                options.threadPriority = workerThreadPriority[groupIndex];
            }
            auto *worker = new (std::nothrow)
                SockWorker(mSockType, mName, workerIndex, mOpCtxMemPool, mSglCtxMemPool, mHeaderReqMemPool, options);
            if (NN_UNLIKELY(worker == nullptr)) {
                NN_LOG_ERROR("Failed to create sock worker in driver " << mName << ", probably out of memory");
                return NN_NEW_OBJECT_FAILED;
            }

            workerIndex.Set(i, groupIndex, mIndex);
            worker->SetIndex(workerIndex);
            if (NN_UNLIKELY((result = worker->Initialize()) != NN_OK)) {
                delete worker;
                NN_LOG_ERROR("Failed to initialize sock worker in driver " << mName << ", result " << result);
                return NN_NEW_OBJECT_FAILED;
            }

            worker->IncreaseRef();
            mWorkers.push_back(worker);
        }
        ++groupIndex;
    }

    return NN_OK;
}

NResult NetDriverSockWithOOB::CreateWorkerResource()
{
    NResult result;
    if (((result = CreateOpCtxMemPool()) != NN_OK)) {
        NN_LOG_ERROR("Sock failed to create op ctx memory pool");
        return result;
    }

    if (((result = CreateSglCtxMemPool()) != NN_OK)) {
        NN_LOG_ERROR("Sock failed to create Sgl ctx memory pool");
        return result;
    }

    if (mOptions.tcpSendZCopy) {
        if (((result = CreateHeaderReqMemPool()) != NN_OK)) {
            NN_LOG_ERROR("Sock failed to create header request memory pool");
            return result;
        }
    } else {
        if (((result = CreateSendMr()) != NN_OK)) {
            NN_LOG_ERROR("Sock falied to create send mr");
            return result;
        }
    }
    return NN_OK;
}

NResult NetDriverSockWithOOB::CreateOpCtxMemPool()
{
    NetMemPoolFixedOptions options = {};
    options.superBlkSizeMB = NN_NO1;
    options.minBlkSize = sizeof(SockOpContextInfo);
    options.tcExpandBlkCnt = NN_NO64;

    mOpCtxMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mOpCtxMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for sock op context pool " << mName << ", probably out of memory");
        return NN_INVALID_PARAM;
    }

    auto result = mOpCtxMemPool->Initialize();
    if (result != NN_OK) {
        mOpCtxMemPool.Set(nullptr);
        NN_LOG_ERROR("Failed to initialize memory pool for sock op context pool " << mName <<
            ", probably out of memory");
        return result;
    }

    return NN_OK;
}

NResult NetDriverSockWithOOB::CreateSglCtxMemPool()
{
    NetMemPoolFixedOptions options = {};
    options.superBlkSizeMB = NN_NO4;
    options.minBlkSize = NN_NextPower2(sizeof(SockSglContextInfo));
    options.tcExpandBlkCnt = NN_NO64;
    mSglCtxMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mSglCtxMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for sgl op context in driver " << mName <<
            ", probably out of memory");
        return NN_INVALID_PARAM;
    }

    auto result = mSglCtxMemPool->Initialize();
    if (result != NN_OK) {
        mSglCtxMemPool.Set(nullptr);
        NN_LOG_ERROR("Failed to initialize memory pool for sgl op context in driver " << mName <<
            ", probably out of memory");
        return result;
    }

    return NN_OK;
}

NResult NetDriverSockWithOOB::CreateHeaderReqMemPool()
{
    NetMemPoolFixedOptions options = {};
    options.superBlkSizeMB = NN_NO1;
    options.minBlkSize = NN_NextPower2(sizeof(SockHeaderReqInfo));
    options.tcExpandBlkCnt = NN_NO64;
    mHeaderReqMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mHeaderReqMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for header request context in driver " << mName <<
            ", probably out of memory");
        return NN_INVALID_PARAM;
    }

    auto result = mHeaderReqMemPool->Initialize();
    if (result != NN_OK) {
        mHeaderReqMemPool.Set(nullptr);
        NN_LOG_ERROR("Failed to initialize memory pool for header request context in driver " << mName <<
            ", probably out of memory");
        return result;
    }

    return NN_OK;
}

NResult NetDriverSockWithOOB::CreateSendMr()
{
    NResult result = NN_OK;
    // create mr pool for send/receive and initialize
    if (NN_UNLIKELY((result = NormalMemoryRegionFixedBuffer::Create(mName, mOptions.mrSendReceiveSegSize,
        mOptions.mrSendReceiveSegCount, mSockDriverSendMR)) != NN_OK)) {
        NN_LOG_ERROR("Failed to create mr for send/receive in NetDriverSock " << mName << ", result " << result);
        return result;
    }
    mSockDriverSendMR->IncreaseRef();

    if (NN_UNLIKELY((result = mSockDriverSendMR->Initialize()) != NN_OK)) {
        NN_LOG_ERROR("Failed to initialize mr for send/receive in NetDriverSock " << mName << ", result " << result);
        mSockDriverSendMR->DecreaseRef();
        return result;
    }

    return NN_OK;
}

void NetDriverSockWithOOB::ClearWorkers()
{
    mWorkerGroups.clear();
    for (auto worker : mWorkers) {
        worker->Stop();
        worker->DecreaseRef();
    }
    mWorkers.clear();
}

NResult NetDriverSockWithOOB::Start()
{
    std::lock_guard<std::mutex> guard(mInitMutex);
    if (!mInited) {
        NN_LOG_ERROR("Failed to start driver " << mName << " as it is not initialized");
        return NN_ERROR;
    }

    if (mOptions.dontStartWorkers) {
        mStarted = true;
        return NN_OK;
    }

    if (mStarted) {
        return NN_OK;
    }

    NResult result = NN_OK;
    if (NN_UNLIKELY(result = ValidateHandlesCheck()) != NN_OK) {
        ClearWorkers();
        return result;
    }
    for (auto &item : mWorkers) {
        if (NN_UNLIKELY(item == nullptr)) {
            NN_LOG_ERROR("[Sock] Failed to start worker " << mName << " as it is null");
            ClearWorkers();
            return result;
        }

        item->RegisterNewReqHandler(std::bind(&NetDriverSockWithOOB::HandleNewRequest, this, std::placeholders::_1));
        item->RegisterReqPostedHandler(std::bind(&NetDriverSockWithOOB::HandleReqPosted, this, std::placeholders::_1));
        item->RegisterOneSideHandler(std::bind(&NetDriverSockWithOOB::OneSideDone, this, std::placeholders::_1));
        item->RegisterEpCloseHandler(std::bind(&NetDriverSockWithOOB::HandleEpClose, this, std::placeholders::_1));
        if (mIdleHandler) {
            item->RegisterIdleHandler(mIdleHandler);
        }

        if ((result = item->Start()) != NN_OK) {
            NN_LOG_ERROR("Failed to start worker " << mName << ", result " << result);
            ClearWorkers();
            return result;
        }
    }

    if (mStartOobSvr) {
        if (mNewEndPointHandler == nullptr) {
            NN_LOG_ERROR("Sock failed to do start in Driver " << mName << ", as newEndPointerHandler is null");
            ClearWorkers();
            return NN_INVALID_PARAM;
        }
        for (auto &oobServer : mOobServers) {
            oobServer->SetNewConnCB(std::bind(&NetDriverSockWithOOB::HandleNewOobConn, this, std::placeholders::_1));
        }

        /* start oob server */
        if ((result = StartListeners()) != NN_OK) {
            ClearWorkers();
            return result;
        }
    }

    mStarted = true;
    return NN_OK;
}

void NetDriverSockWithOOB::Stop()
{
    std::lock_guard<std::mutex> guard(mInitMutex);
    if (!mStarted) {
        return;
    }

    for (auto worker : mWorkers) {
        worker->Stop();
    }

    StopListeners();

    mStarted = false;
}

NResult NetDriverSockWithOOB::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (NN_UNLIKELY(size == 0 || size > NN_NO107374182400)) {
        NN_LOG_ERROR("Sock Failed to create mem region as size is 0 or greater than 100 GB");
        return NN_INVALID_PARAM;
    }

    if (!mInited) {
        NN_LOG_ERROR("Sock Failed to create memory region in driver " << mName << ", as not initialized");
        return NN_NOT_INITIALIZED;
    }

    NormalMemoryRegion *tmp = nullptr;
    auto result = NormalMemoryRegion::Create(mName, size, tmp);
    if (NN_UNLIKELY(result != NN_OK)) {
        NN_LOG_ERROR("Sock Failed to create memory region in driver " << mName << ", probably out of memory");
        return result;
    }

    if ((result = tmp->Initialize()) != NN_OK) {
        delete tmp;
        return result;
    }

    if ((result = mMrChecker.Register(tmp->GetLKey(), tmp->GetAddress(), size)) != NN_OK) {
        NN_LOG_INFO("Sock Failed to add memory region to range checker in driver" << mName << " for duplicate keys");
        delete tmp;
        return result;
    }

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));

    return NN_OK;
}
NResult NetDriverSockWithOOB::CreateMemoryRegion(uintptr_t address, uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (!mInited) {
        NN_LOG_ERROR("Failed to create memory region in driver " << mName << ", as not initialized");
        return NN_NOT_INITIALIZED;
    }

    if (address == 0) {
        NN_LOG_ERROR("Failed to create memory region in driver " << mName << ", as address is 0");
        return NN_INVALID_PARAM;
    }

    NormalMemoryRegion *tmp = nullptr;
    auto res = NormalMemoryRegion::Create(mName, address, size, tmp);
    if (NN_UNLIKELY(res != NN_OK)) {
        NN_LOG_ERROR("Failed to create memory region in driver " << mName << ", probably out of memory");
        return res;
    }

    if ((res = tmp->Initialize()) != NN_OK) {
        delete tmp;
        return res;
    }

    if ((res = mMrChecker.Register(tmp->GetLKey(), tmp->GetAddress(), size)) != NN_OK) {
        NN_LOG_ERROR("Failed to add memory region to range checker in driver" << mName << " for duplicate keys");
        delete tmp;
        return res;
    }

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));

    return NN_OK;
}

NResult NetDriverSockWithOOB::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr, unsigned long memid)
{
    NN_LOG_ERROR("operation is not supported in tcp");
    return NN_ERROR;
}

void NetDriverSockWithOOB::DestroyMemoryRegion(UBSHcomNetMemoryRegionPtr &mr)
{
    if (mr.Get() == nullptr) {
        NN_LOG_WARN("Try to destroy null memory region in sock driver " << mName);
        return;
    }

    if (!mMrChecker.Contains(mr->GetLKey())) {
        NN_LOG_WARN("Try to destroy unowned memory region in driver " << mName);
        return;
    }
    mMrChecker.UnRegister(mr->GetLKey());

    auto tmp = mr.ToChild<NormalMemoryRegion>();
    if (NN_UNLIKELY(tmp == nullptr))  {
        NN_LOG_WARN("Invalid operation to dynamic cast");
        return;
    }
    tmp->UnInitialize();
}

NResult NetDriverSockWithOOB::Connect(const std::string &payload, UBSHcomNetEndpointPtr &ep, uint32_t flags,
    uint8_t serverGrpNo, uint8_t clientGrpNo)
{
    if (mOptions.oobType == NET_OOB_TCP) {
        return Connect(mOobIp, mOobPort, payload, ep, flags, serverGrpNo, clientGrpNo, 0);
    } else if (mOptions.oobType == NET_OOB_UDS) {
        return Connect(mUdsName, 0, payload, ep, flags, serverGrpNo, clientGrpNo, 0);
    }
    return NN_ERROR;
}

NResult NetDriverSockWithOOB::Connect(const std::string &serverUrl, const std::string &payload,
    UBSHcomNetEndpointPtr &ep, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
    if (NN_UNLIKELY(!mInited.load())) {
        NN_LOG_ERROR("[Sock] Driver " << mName << " is not initialized");
        return NN_NOT_INITIALIZED;
    }

    if (NN_UNLIKELY(!mStarted)) {
        NN_LOG_ERROR("[Sock] Failed to connect on driver " << mName << " as it is not started");
        return NN_ERROR;
    }

    if (payload.size() > NN_NO1024) {
        NN_LOG_ERROR("[Sock] Failed to connect server as payload size " << payload.size() << " over limit");
        return NN_INVALID_PARAM;
    }

    NetDriverOobType type;
    std::string ip;
    uint16_t port = 0;
    if (NN_UNLIKELY(NetFunc::NN_ValidateUrl(serverUrl) != NN_OK)) {
        NN_LOG_ERROR("Invalid url");
        return NN_PARAM_INVALID;
    }
    if (NN_UNLIKELY(ParseUrl(serverUrl, type, ip, port) != NN_OK)) {
        NN_LOG_ERROR("Invalid url, url:" << serverUrl);
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(!mInited.load() || clientGrpNo >= mWorkerGroups.size())) {
        NN_LOG_ERROR("Invalid clientGrpNo " << clientGrpNo << ", or driver " << mName << " is not initialized");
        return NN_ERROR;
    }

    OOBTCPClientPtr clt;
    if (mEnableTls) {
        auto oobSSLClient = new (std::nothrow) OOBSSLClient(type, ip, port,
            mTlsPrivateKeyCB, mTlsCertCB, mTlsCaCallback);
        NN_ASSERT_LOG_RETURN(oobSSLClient != nullptr, NN_NEW_OBJECT_FAILED)
        oobSSLClient->SetTlsOptions(mOptions);
        oobSSLClient->SetPSKCallback(mPskFindSessionCb, mPskUseSessionCb);
        clt = oobSSLClient;
    } else {
        clt = new (std::nothrow) OOBTCPClient(type, ip, port);
        NN_ASSERT_LOG_RETURN(clt.Get() != nullptr, NN_NEW_OBJECT_FAILED)
    }

    if (flags & NET_EP_SELF_POLLING) {
        return ConnectSyncEp(clt, payload, ep, serverGrpNo, ctx);
    }
    return Connect(clt, payload, ep, serverGrpNo, clientGrpNo, ctx);
}

NResult NetDriverSockWithOOB::Connect(const std::string &oobIp, uint16_t oobPort, const std::string &payload,
    UBSHcomNetEndpointPtr &ep, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
    if (NN_UNLIKELY(!mInited.load())) {
        NN_LOG_ERROR("Sock Driver " << mName << " is not initialized");
        return NN_NOT_INITIALIZED;
    }

    if (NN_UNLIKELY(!mStarted)) {
        NN_LOG_ERROR("Sock Failed to connect on driver " << mName << " as it is not started");
        return NN_ERROR;
    }

    if (payload.size() > NN_NO1024) {
        NN_LOG_ERROR("Sock Failed to connect server via payload size " << payload.size() << " over limit");
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(!mInited || clientGrpNo >= mWorkerGroups.size())) {
        NN_LOG_ERROR("Invalid clientGrpNo " << clientGrpNo << ", or driver " << mName << " is not initialized");
        return NN_ERROR;
    }

    OOBTCPClientPtr clt;
    if (mEnableTls) {
        auto oobSSLClient = new (std::nothrow) OOBSSLClient(mOptions.oobType, oobIp, oobPort, mTlsPrivateKeyCB,
            mTlsCertCB, mTlsCaCallback);
        NN_ASSERT_LOG_RETURN(oobSSLClient != nullptr, NN_NEW_OBJECT_FAILED)
        oobSSLClient->SetTlsOptions(mOptions);
        oobSSLClient->SetPSKCallback(mPskFindSessionCb, mPskUseSessionCb);
        clt = oobSSLClient;
    } else {
        clt = new (std::nothrow) OOBTCPClient(mOptions.oobType, oobIp, oobPort);
        NN_ASSERT_LOG_RETURN(clt.Get() != nullptr, NN_NEW_OBJECT_FAILED)
    }

    if (flags & NET_EP_SELF_POLLING) {
        return ConnectSyncEp(clt, payload, ep, serverGrpNo, ctx);
    }
    return Connect(clt, payload, ep, serverGrpNo, clientGrpNo, ctx);
}

NResult NetDriverSockWithOOB::Connect(const OOBTCPClientPtr &client, const std::string &payload,
    UBSHcomNetEndpointPtr &outEp, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
     /* try to connect to oob server */
    OOBTCPConnection *conn = nullptr;
    NResult result = NN_OK;
    if ((result = client->Connect(conn)) != 0) {
        NN_LOG_ERROR("Sock Failed to connect server via oob, result " << result);
        return result;
    }

    NetLocalAutoDecreasePtr<OOBTCPConnection> autoDecPtr(conn);
    if (client->GetOobType() == NET_OOB_TCP) {
        conn->SetIpAndPort(client->GetServerIp(), client->GetServerPort());
    } else {
        conn->SetIpAndPort(client->GetServerUdsName(), 0);
    }

    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBClient(mSecInfoProvider, mSecInfoValidator, conn, mName, ctx,
        mOptions.secType))) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    /* send connection header */
    ConnectHeader header {};
    SetConnHeader(header, mOptions.magic, mOptions.version, serverGrpNo, Protocol(), mMajorVersion,
                  mMinorVersion, mOptions.tlsVersion);
    if (NN_UNLIKELY((result = conn->Send(&header, sizeof(ConnectHeader))) != NN_OK)) {
        NN_LOG_ERROR("Sock Failed to send conn header to oob server " << client->GetServerIp() << ":" <<\
            client->GetServerPort() << " in driver " << mName);
        return NN_ERROR;
    }

    /* receive connect response and peer sock id */
    ConnRespWithUId respWithUId {};
    void *tmpBuff = &respWithUId;
    if (NN_UNLIKELY((result = conn->Receive(tmpBuff, sizeof(ConnRespWithUId))) != NN_OK)) {
        return result;
    }

    /* connect response */
    auto resp = respWithUId.connResp;
    switch (resp) {
        case MAGIC_MISMATCH:
            NN_LOG_ERROR("Sock Failed to pass server magic validation " << mName << ", result " << NN_CONNECT_REFUSED);
            return NN_CONNECT_REFUSED;
        case PROTOCOL_MISMATCH:
            NN_LOG_ERROR("Sock Failed to pass server protocol validation " << mName << ", result " <<
                NN_CONNECT_PROTOCOL_MISMATCH);
            return NN_CONNECT_PROTOCOL_MISMATCH;
        case SERVER_INTERNAL_ERROR:
            NN_LOG_ERROR("Sock Server error happened, connection refused " << mName << ", result " << resp);
            return NN_ERROR;
        case VERSION_MISMATCH:
            NN_LOG_ERROR("Sock Failed to pass server version validation " << mName << ", result " <<
                NN_CONNECT_REFUSED);
            return NN_CONNECT_REFUSED;
        case TLS_VERSION_MISMATCH:
            NN_LOG_ERROR("Sock Failed to pass server tls version validation " << mName << ", result " <<
                NN_CONNECT_REFUSED);
            return NN_CONNECT_REFUSED;
        case OK:
        case OK_PROTOCOL_TCP:
        case OK_PROTOCOL_UDS:
            break;
        default:
            NN_LOG_ERROR("Sock Server error happened, connection refused " << mName << ", result: " << resp);
            return NN_ERROR;
    }

    /* peer ep id */
    auto newSockId = respWithUId.epId;
    NN_LOG_TRACE_INFO("Sock new ep id will be set as" << " " << newSockId << " in driver " << mName);

    /* choose worker */
    uint16_t workerIndex = 0;
    if (NN_UNLIKELY(!mClientLb->ChooseWorker(clientGrpNo, std::to_string(newSockId), workerIndex)) ||
        workerIndex >= mWorkers.size()) {
        NN_LOG_ERROR("Sock Failed to choose worker during connect in driver " << mName);
        return NN_ERROR;
    }

    NN_LOG_TRACE_INFO("Worker " << workerIndex << " is chosen in driver " << mName);

    SockWorker *worker = mWorkers[workerIndex];
    NN_ASSERT_LOG_RETURN(worker != nullptr, NN_ERROR);

    /* create sock and initialize */
    SockOptions options {};
    options.sendQueueSize = mOptions.qpSendQueueSize;
    Sock *sock;
    int fdConn = conn->TransferFd();
    if (mEnableTls) {
        sock = new (std::nothrow) Sock(mSockType, mName, newSockId, fdConn, options, conn);
    } else {
        sock = new (std::nothrow) Sock(mSockType, mName, newSockId, fdConn, options);
    }
    if (NN_UNLIKELY(sock == nullptr)) {
        NN_LOG_ERROR("Failed to new async sock in driver " << mName << ", probably out of memory");
        NetFunc::NN_SafeCloseFd(fdConn);
        return NN_NEW_OBJECT_FAILED;
    }

    sock->PeerIpPort(conn->GetIpAndPort());
    NetLocalAutoDecreasePtr<Sock> autoDecSock(sock);

    if (NN_UNLIKELY((result = sock->Initialize(worker->Options())))) {
        NN_LOG_ERROR("Failed to initialize sock " << sock->Id() << " in driver " << mName << ", result " << result);
        return NN_NEW_OBJECT_FAILED;
    }

    /* send real head and payload */
    UBSHcomNetTransHeader workerFirstReq {};
    workerFirstReq.flags = NTH_TWO_SIDE;
    workerFirstReq.opCode = SockExchangeOp::REAL_CONNECT;
    workerFirstReq.dataLength = payload.length();
    workerFirstReq.seqNo = header.wholeHeader[0]; /* use reqNo */
    /* finally fill header crc */
    workerFirstReq.headerCrc = NetFunc::CalcHeaderCrc32(workerFirstReq);
    if (NN_UNLIKELY((result = sock->SendRealConnHeader(fdConn, &workerFirstReq,
        sizeof(UBSHcomNetTransHeader))) != NN_OK)) {
        NN_LOG_ERROR("Failed to send payload header to peer at " << conn->GetIpAndPort() << " in driver " << mName);
        return result;
    }

    if (!payload.empty()) {
        if ((result = sock->Send(payload.c_str(), payload.length())) != NN_OK) {
            NN_LOG_ERROR("Failed to send payload to peer at " << conn->GetIpAndPort() << " in driver " << mName <<
                ", errno " << result);
            return result;
        }
    }

    /* added worker as up context */
    sock->UpContext1(reinterpret_cast<uint64_t>(worker));

    /* create ep */
    UBSHcomNetEndpointPtr newEp = new (std::nothrow) NetAsyncEndpointSock(sock->Id(), sock, this, worker->Index());
    if (NN_UNLIKELY(newEp.Get() == nullptr)) {
        NN_LOG_ERROR("Failed to new async sock ep in driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }
    if (mEnableTls) {
        auto childEp = newEp.ToChild<NetAsyncEndpointSock>();
        auto tmp = dynamic_cast<OOBSSLConnection *>(conn);
        if (NN_UNLIKELY(childEp == nullptr || tmp == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        childEp->EnableEncrypt(mOptions);
        childEp->SetSecrets(tmp->Secret());
    }
    if (mOptions.tcpSendZCopy) {
        auto childEp = newEp.ToChild<NetAsyncEndpointSock>();
        if (NN_UNLIKELY(childEp == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_ERROR;
        }
        childEp->EnableSendZCopy();
    }
    /* set ep as sock up context and add ep into map */
    sock->UpContext(reinterpret_cast<uint64_t>(newEp.Get()));

    /* if non-blocking set postedHandler and ctxInfoPool to sock, used in sock func ProcessQueueReq */
    sock->SetSockPostedHandler(worker->GetSockPostedHandler());
    sock->SetSockOneSideHandler(worker->GetSockOneSideHandler());
    sock->SetSockOpContextInfoPool(worker->GetSockOpContextInfoPool());
    sock->SetSockSglContextInfoPool(worker->GetSockSglContextInfoPool());
    sock->SetSockHeaderReqInfoPool(worker->GetSockHeaderReqInfoPool());
    sock->SetSockDriverSendMR(mSockDriverSendMR);
    sock->SetMrChecker(&mMrChecker);

    NN_LOG_TRACE_INFO("Sock created " << sock->ToString() << " in driver " << mName);
    newEp->StoreConnInfo(NetFunc::GetIpByFd(fdConn), conn->ListenPort(), header.version, payload);

    // receive server ready signal
    int8_t ready = -1;
    tmpBuff = static_cast<void *>(&ready);
    result = sock->Receive(tmpBuff, sizeof(int8_t));
    if (result != 0 || ready != 1) {
        NN_LOG_ERROR("Sock Failed to connect to server as server not responses or return not ready, result " << result);
        return NN_ERROR;
    }

    if (sock->SetNonBlockingIo() != SS_OK) {
        NN_LOG_ERROR("Failed to set sock " << sock->Name() << " nonblocking io mode.");
        return NN_ERROR;
    }

    AddEp(newEp);

    /* add to worker epoll */
    if (NN_UNLIKELY(worker->AddToEpoll(sock, EPOLLIN) != SS_OK)) {
        NN_LOG_ERROR("Failed to add sock " << sock->Name() << " to the epoll handle.");
        return NN_ERROR;
    }

    newEp->State().Set(NEP_ESTABLISHED);
    outEp.Set(newEp.Get());

    NN_LOG_INFO("New connection to " << client->GetServerIp() << ":" << client->GetServerPort() <<
        " established, async ep id " << outEp->Id() << " worker info " << worker->DetailName());
    return NN_OK;
}

NResult NetDriverSockWithOOB::ConnectSyncEp(const OOBTCPClientPtr &client, const std::string &payload,
    UBSHcomNetEndpointPtr &outEp, uint8_t serverGrpNo, uint64_t ctx)
{
    if (NN_UNLIKELY(!mInited)) {
        NN_LOG_ERROR("Driver " << mName << " is not initialized");
        return NN_ERROR;
    }

    /* try to connect to oob server */
    OOBTCPConnection *conn = nullptr;
    NResult result = NN_OK;
    if ((result = client->Connect(conn)) != 0) {
        NN_LOG_ERROR("Sock Failed to connect server via oob,result " << result);
        return result;
    }

    NetLocalAutoDecreasePtr<OOBTCPConnection> autoDecPtr(conn);
    if (client->GetOobType() == NET_OOB_TCP) {
        conn->SetIpAndPort(client->GetServerIp(), client->GetServerPort());
    } else {
        conn->SetIpAndPort(client->GetServerUdsName(), 0);
    }

    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBClient(mSecInfoProvider, mSecInfoValidator, conn, mName, ctx,
        mOptions.secType))) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }
    /* send connection header */
    ConnectHeader header {};

    SetConnHeader(header, mOptions.magic, mOptions.version, serverGrpNo, Protocol(), mMajorVersion, mMinorVersion,
        mOptions.tlsVersion);
    if (NN_UNLIKELY((result = conn->Send(&header, sizeof(ConnectHeader))) != NN_OK)) {
        NN_LOG_ERROR("Sock Failed to send conn header to oob server " << client->GetServerIp() << ":"
            << client->GetServerPort() << " in Driver " << mName);
        return NN_ERROR;
    }

    /* receive connect response and peer ep id */
    ConnRespWithUId respWithUId {};
    void *tmpBuf = &respWithUId;
    if (NN_UNLIKELY((result = conn->Receive(tmpBuf, sizeof(ConnRespWithUId))) != NN_OK)) {
        return result;
    }

    /* connect response */
    auto resp = respWithUId.connResp;
    switch (resp) {
        case MAGIC_MISMATCH:
            NN_LOG_ERROR("Failed to pass server magic validation " << mName << ", result " << NN_CONNECT_REFUSED);
            return NN_CONNECT_REFUSED;
        case PROTOCOL_MISMATCH:
            NN_LOG_ERROR("Failed to pass server magic validation " << mName << ", result " << NN_CONNECT_REFUSED);
            return NN_CONNECT_PROTOCOL_MISMATCH;
        case SERVER_INTERNAL_ERROR:
            NN_LOG_ERROR("Server error happened, connection refused " << mName << ", result " << resp);
            return NN_ERROR;
        case VERSION_MISMATCH:
            NN_LOG_ERROR("Failed to pass server version validation " << mName << ", result " << NN_CONNECT_REFUSED);
            return NN_CONNECT_REFUSED;
        case TLS_VERSION_MISMATCH:
            NN_LOG_ERROR("Failed to pass server tls version validation " << mName << ", result " << NN_CONNECT_REFUSED);
            return NN_CONNECT_REFUSED;
        case OK:
        case OK_PROTOCOL_TCP:
        case OK_PROTOCOL_UDS:
            break;
        default:
            NN_LOG_ERROR("Sock Server error happened, connection refused " << mName << ", result " << resp);
            return NN_ERROR;
    }

    /* peer ep id */
    auto newSockId = respWithUId.epId;
    NN_LOG_TRACE_INFO("new ep id will be set as " << newSockId << " in driver " << mName);

    int fdConn = conn->TransferFd();

    /* create sock and initialize */
    SockOptions option {};
    option.sendQueueSize = mOptions.qpSendQueueSize;
    Sock *sock;
    if (mEnableTls) {
        sock = new (std::nothrow) Sock(mSockType, mName, newSockId, fdConn, option, conn);
    } else {
        sock = new (std::nothrow) Sock(mSockType, mName, newSockId, fdConn, option);
    }
    if (NN_UNLIKELY(sock == nullptr)) {
        NN_LOG_ERROR("Failed to new async sock in driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    sock->PeerIpPort(conn->GetIpAndPort());
    NetLocalAutoDecreasePtr<Sock> autoDecSock(sock);

    SockWorkerOptions options;
    options.SetValue(mOptions, mStartOobSvr);

    if (NN_UNLIKELY((result = sock->Initialize(options)))) {
        NN_LOG_ERROR("Failed to initialize sock " << sock->Id() << " in driver " << mName << " result " << result);
        return NN_NEW_OBJECT_FAILED;
    }

    /* send real head and payload */
    UBSHcomNetTransHeader workerFirstReq {};
    workerFirstReq.opCode = SockExchangeOp::REAL_CONNECT;
    workerFirstReq.flags = NTH_TWO_SIDE;
    workerFirstReq.dataLength = payload.length();
    workerFirstReq.seqNo = header.wholeHeader[0]; /* use reqNo */

    /* finally fill header crc */
    workerFirstReq.headerCrc = NetFunc::CalcHeaderCrc32(workerFirstReq);

    if (NN_UNLIKELY((result = sock->SendRealConnHeader(fdConn, &workerFirstReq,
        sizeof(UBSHcomNetTransHeader))) != NN_OK)) {
        NN_LOG_ERROR("Failed to send payload header to peer at " << conn->GetIpAndPort() << " in driver " << mName);
        NetFunc::NN_SafeCloseFd(fdConn);
        return result;
    }

    if (!payload.empty()) {
        if ((result = sock->Send(payload.c_str(), payload.length())) != NN_OK) {
            NN_LOG_ERROR("Failed to send payload to peer at " << conn->GetIpAndPort() << " in driver " << mName <<
                ", errno " << result);
            NetFunc::NN_SafeCloseFd(fdConn);
            return result;
        }
    }

    /* create ep */
    const UBSHcomNetWorkerIndex netWorkerIndex {};
    UBSHcomNetEndpointPtr newEp = new (std::nothrow) NetSyncEndpointSock(sock->Id(), sock, this, netWorkerIndex);
    if (NN_UNLIKELY(newEp.Get() == nullptr)) {
        NN_LOG_ERROR("Failed to new sync sock ep in driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }
    if (mEnableTls) {
        auto childEp = newEp.ToChild<NetSyncEndpointSock>();
        auto tmp = dynamic_cast<OOBSSLConnection *>(conn);
        if (NN_UNLIKELY(childEp == nullptr || tmp == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        childEp->EnableEncrypt(mOptions);
        childEp->SetSecrets(tmp->Secret());
    }
    /* set ep as sock up context and add ep into map */
    sock->UpContext(reinterpret_cast<uint64_t>(newEp.Get()));
    sock->SetMrChecker(&mMrChecker);
    NN_LOG_TRACE_INFO("Sock created " << sock->ToString() << " in driver " << mName);

    newEp->StoreConnInfo(NetFunc::GetIpByFd(fdConn), conn->ListenPort(), header.version, payload);

    // receive server ready signal
    int8_t ready = -1;
    tmpBuf = static_cast<void *>(&ready);
    result = sock->Receive(tmpBuf, sizeof(int8_t));
    if (result != 0 || ready != 1) {
        NN_LOG_ERROR("Failed to connect to server as server not responses or return not ready, result " << result);
        // do later: handle pre post-ed mr
        return NN_ERROR;
    }

    AddEp(newEp);

    newEp->State().Set(NEP_ESTABLISHED);
    outEp.Set(newEp.Get());

    NN_LOG_INFO("New connect to " << client->GetServerIp() << ":" << client->GetServerPort() <<
        " established, sync ep id " << outEp->Id());
    return NN_OK;
}

void NetDriverSockWithOOB::DestroyEndpoint(UBSHcomNetEndpointPtr &ep)
{
    if (NN_UNLIKELY(ep.Get() == nullptr)) {
        NN_LOG_WARN("The sock ep is null already.");
        return;
    }

    NN_LOG_INFO("Destroy endpoint id " << ep->Id());
    if (!Remove(ep->Id())) {
        NN_LOG_WARN("Unable to destroy sock endpoint as ep " << ep->Id() << " doesn't exist, maybe cleaned already");
        return;
    }

    ep.Set(nullptr);
}

void NetDriverSockWithOOB::DestroyEndpointById(uint64_t id)
{
    std::lock_guard<std::mutex> guard(mEndPointsMutex);
    auto it = mEndPoints.find(id);
    if (NN_UNLIKELY(it == mEndPoints.end())) {
        NN_LOG_WARN("the id is not in the ep map");
        return;
    }

    NN_LOG_INFO("Destroy endpoint id " << id);
    if (NN_UNLIKELY(mEndPoints.erase(id) <= 0)) {
        NN_LOG_WARN("Unable to destroy sock endpoint as ep " << id << " doesn't exist, maybe cleaned already");
        return;
    }

    mEndPoints[id].Set(nullptr);
}

NResult NetDriverSockWithOOB::HandleNewOobConn(OOBTCPConnection &conn)
{
    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBServer(mSecInfoProvider, mSecInfoValidator, conn, mName,
        mOptions.secType)) != NN_OK) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    uint32_t ip = NetFunc::GetIpByFd(conn.GetFd());
    if (NN_UNLIKELY(OOBSecureProcess::SecProcessCompareEpNum(ip, conn.ListenPort(), conn.GetIpAndPort(),
        mOobServers)) != NN_OK) {
        NN_LOG_ERROR("Sock connection num exceeds maximum");
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    NResult result = 0;
    /* receive header and verify */
    ConnectHeader header {};
    void *headerBuf = &header;
    if (NN_UNLIKELY((result = conn.Receive(headerBuf, sizeof(ConnectHeader))) != 0)) {
        NN_LOG_ERROR("Failed to read header from " << conn.GetIpAndPort() << " for driver " << mName << ", result " <<
            result);
        return result;
    }

    ConnRespWithUId respWithUId{ OK, 0 };
    result = OOBSecureProcess::SecCheckConnectionHeader(header, mOptions, mEnableTls, Protocol(), mMajorVersion,
        mMinorVersion, respWithUId);
    if (result != NN_OK) {
        conn.Send(&respWithUId, sizeof(ConnRespWithUId));
        return NN_ERROR;
    }

    /* choose worker */
    const NetWorkerLBPtr &lb = conn.LoadBalancer();
    NN_ASSERT_LOG_RETURN(lb.Get() != nullptr, NN_ERROR)
    uint16_t workerIndex = 0;
    if (NN_UNLIKELY(!lb->ChooseWorker(header.groupIndex, conn.GetIpAndPort(), workerIndex)) ||
        workerIndex >= mWorkers.size()) {
        NN_LOG_ERROR("Failed to choose worker during connect in driver " << mName);
        return NN_ERROR;
    }

    ConnectResp resp = GetConnResp(mSockType);
    uint64_t newSockId = NetUuid::GenerateUuid();
    {
        std::lock_guard<std::mutex> guard(mEndPointsMutex);
        while (mEndPoints.count(newSockId) != 0) {
            NN_LOG_WARN("Duplicate generate ep id " << newSockId << " for connection to "
                << conn.GetIpAndPort() << " for driver " << mName << ", regenereate");
            newSockId = NetUuid::GenerateUuid();
        }
    }

    NN_LOG_TRACE_INFO("new sock id will be set as " << newSockId << " in driver " << mName);

    respWithUId.connResp = resp;
    respWithUId.epId = newSockId;
    if (NN_UNLIKELY((result = conn.Send(&respWithUId, sizeof(ConnRespWithUId))) != NN_OK)) {
        NN_LOG_ERROR("Failed to send connect response to " << conn.GetIpAndPort() << " for driver " << mName);
        return NN_ERROR;
    }

    NN_LOG_TRACE_INFO("Worker " << workerIndex << " is chosen in driver " << mName);
    SockWorker *worker = mWorkers[workerIndex];
    NN_ASSERT_LOG_RETURN(worker != nullptr, NN_ERROR);
    /* send worker exchange info to oob client */
    if (mSockType == SOCK_TCP || mSockType == SOCK_UDS) {
        int fdConn = conn.TransferFd();

        /* create sock and initialize */
        SockOptions options {};
        Sock *sock;
        if (mEnableTls) {
            sock = new (std::nothrow) Sock(mSockType, mName, newSockId, fdConn, options, &conn);
        } else {
            sock = new (std::nothrow) Sock(mSockType, mName, newSockId, fdConn, options);
        }

        if (NN_UNLIKELY(sock == nullptr)) {
            NN_LOG_ERROR("Failed to new sock in driver " << mName << ", probably out of memory");
            return NN_NEW_OBJECT_FAILED;
        }

        NetLocalAutoDecreasePtr<Sock> autoDecSock(sock);

        if (mEnableTls) {
            auto tmp = dynamic_cast<OOBSSLConnection *>(&conn);
            if (NN_UNLIKELY(tmp == nullptr)) {
                NN_LOG_ERROR("dynamic cast error");
                return NN_OOB_SEC_PROCESS_ERROR;
            }
            sock->Secret(tmp->Secret());
        }

        if (NN_UNLIKELY((result = sock->Initialize(worker->Options())))) {
            NN_LOG_ERROR("Failed to initialize sock " << sock->Id() << " in driver " << mName << " result " << result);
            return NN_NEW_OBJECT_FAILED;
        }

        sock->SetSockPostedHandler(worker->GetSockPostedHandler());
        sock->SetSockOneSideHandler(worker->GetSockOneSideHandler());
        sock->SetSockOpContextInfoPool(worker->GetSockOpContextInfoPool());
        sock->SetSockSglContextInfoPool(worker->GetSockSglContextInfoPool());
        sock->SetSockHeaderReqInfoPool(worker->GetSockHeaderReqInfoPool());
        sock->SetSockDriverSendMR(mSockDriverSendMR);

        sock->PeerIpPort(conn.GetIpAndPort());
        sock->StoreConnInfo(NetFunc::GetIpByFd(fdConn), conn.ListenPort(), header.version);

        /* added worker as up context */
        sock->UpContext1(reinterpret_cast<uint64_t>(worker));

        /* add to worker epoll */
        if (NN_UNLIKELY(worker->AddToEpoll(sock, EPOLLIN) != NN_OK)) {
            NN_LOG_ERROR("Failed to add sock " << sock->Name() << " to the epoll handle.");
            return NN_ERROR;
        }
    } else {
        NN_ASSERT_LOG_RETURN(false, NN_ERROR);
    }

    OOBSecureProcess::SecProcessAddEpNum(ip, conn.ListenPort(), conn.GetIpAndPort(), mOobServers);

    return NN_OK;
}

NResult NetDriverSockWithOOB::HandleSockError(Sock *sock)
{
    UBSHcomNetEndpointPtr brokenEp = reinterpret_cast<NetAsyncEndpointSock *>(sock->UpContext());
    // Worker 线程与心跳线程只会有一个成功
    bool process = false;
    if (brokenEp.Get() && NN_UNLIKELY(!brokenEp->EPBrokenProcessed().compare_exchange_strong(process, true))) {
        NN_LOG_WARN("Ep id " << brokenEp->Id() << " broken handled by other thread");
        return NN_EP_CLOSE;
    }

    /* sock is failure and close sock */
    NN_LOG_TRACE_INFO("Sock error " << (sock)->ToString());

    /* remove fd */
    auto worker = reinterpret_cast<SockWorker *>(sock->UpContext1());
    NN_ASSERT_LOG_RETURN(worker != nullptr, NN_ERROR);

    /* sock will DecreaseRef at worker RemoveFromEpoll, if in real connect process it will be destroyed,
     * so sock IncreaseRef here to make sure destroyed after get UpContext */
    sock->IncreaseRef();
    worker->RemoveFromEpoll(sock);
    sock->DealCbWithFailure();
    sock->Close();
    OOBSecureProcess::SecProcessDelEpNum(sock->mLocalIp, sock->mListenPort, sock->PeerIpPort(),
        mOobServers);
    /* remove ep */
    sock->DecreaseRef();
    NN_ASSERT_LOG_RETURN(brokenEp.Get() != nullptr, NN_ERROR);
    brokenEp->mState.Set(NEP_BROKEN);
    /* call upper function */
    mEndPointBrokenHandler(brokenEp);
    DestroyEndpoint(brokenEp);
    return NN_EP_CLOSE;
}

NResult NetDriverSockWithOOB::HandleSockRealConnect(SockOpContextInfo &ctx)
{
    {
        std::lock_guard<std::mutex> guard(mEndPointsMutex);
        if (mEndPoints.count(ctx.sock->Id())) {
            NN_LOG_WARN("Duplicate real connect for driver " << mName << " sock id " << ctx.sock->Id());
            return NN_ERROR;
        }
    }

    NetLocalAutoDecreasePtr<Sock> autoDecSock((ctx).sock);
    NN_ASSERT_LOG_RETURN(ctx.sock->UpContext1() != 0, NN_ERROR)
    ConnectHeader header {};
    SockWorker *worker = nullptr;
    UBSHcomNetEndpointPtr ep = nullptr;
    static thread_local std::string payload;
    NResult result = NN_EP_CLOSE;

    worker = reinterpret_cast<SockWorker *>((ctx).sock->UpContext1());
    if (NN_UNLIKELY(worker == nullptr)) {
        ctx.sock->Close();
        OOBSecureProcess::SecProcessDelEpNum(ctx.sock->mLocalIp, ctx.sock->mListenPort, ctx.sock->PeerIpPort(),
            mOobServers);
        NN_LOG_ERROR("Invalid worker for driver " << mName);
        return NN_EP_CLOSE;
    }
    /* handle real connection */
    header.wholeHeader[0] = (ctx).header->seqNo;
    do {
        if (NN_UNLIKELY(header.magic != mOptions.magic)) {
            NN_LOG_ERROR("Invalid client request for driver " << mName << ", wrong mgc");
            break;
        }

        /* create ep */
        ep = new (std::nothrow) NetAsyncEndpointSock(ctx.sock->Id(), ctx.sock, this, worker->Index());
        if (NN_UNLIKELY(ep == nullptr)) {
            NN_LOG_ERROR("Failed to new async sock ep in driver " << mName << ", probably out of memory");
            break;
        }

        if (ctx.sock->mType == SOCK_UDS) {
            struct ucred remoteIds {};
            socklen_t len = static_cast<socklen_t>(sizeof(struct ucred));
            if (NN_UNLIKELY(getsockopt(ctx.sock->FD(), SOL_SOCKET, SO_PEERCRED, &remoteIds, &len) != 0)) {
                char errBuf[NET_STR_ERROR_BUF_SIZE] = {0};
                NN_LOG_ERROR("Failed to get uds ids in driver " << mName << ", errno:" << errno <<
                " error:" << NetFunc::NN_GetStrError(errno, errBuf, NET_STR_ERROR_BUF_SIZE));
                break;
            }
            ep->RemoteUdsIdInfo(remoteIds.pid, remoteIds.uid, remoteIds.gid);
        }

        auto childEp = ep.ToChild<NetAsyncEndpointSock>();
        if (NN_UNLIKELY(childEp == nullptr)) {
            NN_LOG_ERROR("ToChild failed");
            break;
        }
        if (mEnableTls) {
            childEp->EnableEncrypt(mOptions);
            childEp->SetSecrets((ctx).sock->mSecret);
        }
        if (mOptions.tcpSendZCopy) {
            childEp->EnableSendZCopy();
        }
        /* set payload */
        uint32_t payloadLen = ctx.header->dataLength;
        if (payloadLen == 0 || payloadLen > NN_NO1024) {
            NN_LOG_ERROR("Invalid payload length " << payloadLen << ", it should be 1 ~ 1024");
            break;
        }

        if (payloadLen > 0) {
            payload.resize(ctx.header->dataLength + NN_NO1);
            payload = { reinterpret_cast<char *>(ctx.dataAddress), ctx.header->dataLength };
            payload[ctx.header->dataLength] = '\0';
        } else {
            payload.clear();
        }
        ep->Payload(payload);
        ep->StoreConnInfo(ctx.sock->mLocalIp, ctx.sock->mListenPort, ctx.sock->mVersion, payload);
        ctx.sock->SetMrChecker(&mMrChecker);
        /* do callback */
        if (NN_UNLIKELY((result = mNewEndPointHandler(ctx.sock->PeerIpPort(), ep, payload)) != NN_OK)) {
            NN_LOG_ERROR("Got " << result << " from new ep callback, this new connection from " <<
                ctx.sock->PeerIpPort() << " will be dropped");
            break;
        }
        int8_t ready = 1;
        if ((result = ctx.sock->Send(&ready, sizeof(int8_t))) != NN_OK) {
            NN_LOG_ERROR("Failed to send ready signal to client, result " << result);
            break;
        }
        if (ctx.sock->SetNonBlockingIo() != SS_OK) {
            NN_LOG_WARN("Unable to set sock " << ctx.sock->Name() << " nonblocking io mode.");
            break;
        }
        /* set to established */
        ep->State().Set(NEP_ESTABLISHED);
        /* set ep as sock up context and add ep into map */
        ctx.sock->UpContext(reinterpret_cast<uint64_t>(ep.Get()));
        AddEp(ep);
        result = NN_OK;
        NN_LOG_INFO("New connection from " << ctx.sock->PeerIpPort() << " established, async ep id " <<
            ep->Id() << " worker info " << worker->DetailName());
    } while (0);

    if (result != NN_OK) {
        worker->RemoveFromEpoll(ctx.sock);
        ctx.sock->Close();
        OOBSecureProcess::SecProcessDelEpNum(ctx.sock->mLocalIp, ctx.sock->mListenPort, ctx.sock->PeerIpPort(),
            mOobServers);
        result = NN_EP_CLOSE;
    }

    return result;
}

NResult NetDriverSockWithOOB::HandleNewRequest(SockOpContextInfo &ctx)
{
    NN_ASSERT_LOG_RETURN(ctx.sock != nullptr, NN_ERROR)
    NResult result = NN_OK;

    if (NN_UNLIKELY(ctx.errType != SockOpContextInfo::SS_NO_ERROR)) {
        NN_LOG_WARN("sock " << ctx.sock->mName << " received an incorrect request and it is causing ep destroy");
        return HandleSockError(ctx.sock);
    }

    NN_ASSERT_LOG_RETURN(ctx.header != nullptr, NN_ERROR);
    /* user op code */
    if (NN_LIKELY(ctx.header->opCode >= 0)) {
        static thread_local UBSHcomNetRequestContext netCtx {};
        static thread_local UBSHcomNetMessage netMsg {};

        /* set net context */
        NN_ASSERT_LOG_RETURN(ctx.sock->UpContext() != 0, NN_ERROR)
        netCtx.mEp.Set(reinterpret_cast<NetAsyncEndpointSock *>(ctx.sock->UpContext()));
        netCtx.mHeader = *(ctx.header);
        netCtx.mOpType = UBSHcomNetRequestContext::NN_RECEIVED;
        netCtx.extHeaderType = ctx.header->extHeaderType;
        if (ctx.header->immData != NN_NO0) {
            netCtx.mOpType = UBSHcomNetRequestContext::NN_RECEIVED_RAW;
        }
        netCtx.mMessage = &netMsg;

        netMsg.mBuf = ctx.sock->ReceiveData().Data();
        netMsg.mDataLen = ctx.sock->ReceiveData().ActualDataSize();

        /* call upper handler */
        result = mReceivedRequestHandler(netCtx);
        netCtx.mEp.Set(nullptr);
        netMsg.mBuf = nullptr;
        return result;
    } else if (ctx.header->opCode == SockExchangeOp::REAL_CONNECT) {
        return HandleSockRealConnect(ctx);
    }

    return NN_OK;
}

NResult NetDriverSockWithOOB::HandleSendRawSglReqPosted(SockOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx)
{
    NResult result = NN_OK;
    auto sglCtx = ctx->sendCtx;

    // set context
    netCtx.mOpType = UBSHcomNetRequestContext::NN_SENT_RAW_SGL;
    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->sock->UpContext()));
    netCtx.mResult = SockOpContextInfo::GetNResult(ctx->errType);
    netCtx.mHeader.Invalid();
    netCtx.mMessage = nullptr;
    if (NN_UNLIKELY(memcpy_s(netCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, sglCtx->iov,
        sizeof(UBSHcomNetTransSgeIov) * sglCtx->iovCount) != NN_OK)) {
        NN_LOG_ERROR("Failed to copy req to sglCtx");
        result = NN_INVALID_PARAM;
    }

    netCtx.mOriginalSglReq.iov = netCtx.iov;
    netCtx.mOriginalSglReq.upCtxSize = ctx->upCtxSize;
    netCtx.mOriginalSglReq.iovCount = sglCtx->iovCount;
    if (netCtx.mOriginalSglReq.upCtxSize > 0 &&
        netCtx.mOriginalSglReq.upCtxSize <= sizeof(UBSHcomNetTransSglRequest::upCtxData)) {
        if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalSglReq.upCtxData, NN_NO16, ctx->upCtx, ctx->upCtxSize) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy ctx to netCtx");
            result = NN_INVALID_PARAM;
        }
    }

    // call to callback
    if (result == NN_OK && NN_UNLIKELY((result = mRequestPostedHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call requestPostedHandler in Driver " << mName <<
            " return non-zero for receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " <<
            netCtx.mHeader.dataLength << "]");
    }
    netCtx.mEp.Set(nullptr);
    ctx->sock->mSglCtxInfoPool.Return(ctx->sendCtx);
    ctx->sendCtx = nullptr;

    return result;
}

NResult NetDriverSockWithOOB::HandleReqPosted(SockOpContextInfo *ctx)
{
    NN_ASSERT_LOG_RETURN(ctx != nullptr, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx->sock != nullptr, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx->sock->UpContext() != 0, NN_ERROR)
    NResult result = NN_OK;

    static thread_local UBSHcomNetRequestContext netCtx {};
    if (ctx->opType == SockOpContextInfo::SS_SEND || ctx->opType == SockOpContextInfo::SS_SEND_RAW) {
        if (ctx->opType == SockOpContextInfo::SS_SEND) {
            if (mOptions.tcpSendZCopy) {
                if (NN_UNLIKELY(memcpy_s(&(netCtx.mHeader), sizeof(UBSHcomNetTransHeader),
                    &ctx->headerRequest->sendHeader, sizeof(UBSHcomNetTransHeader)) != NN_OK)) {
                    NN_LOG_ERROR("Failed to copy req to sglCtx");
                    result = NN_INVALID_PARAM;
                }
            } else {
                if (NN_UNLIKELY(memcpy_s(&(netCtx.mHeader), sizeof(UBSHcomNetTransHeader),
                    reinterpret_cast<UBSHcomNetTransHeader *>(ctx->sendBuff),
                    sizeof(UBSHcomNetTransHeader)) != NN_OK)) {
                    NN_LOG_ERROR("Failed to copy req to sglCtx");
                    result = NN_INVALID_PARAM;
                }
            }
        } else {
            netCtx.mHeader.Invalid();
        }

        netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->sock->UpContext()));
        netCtx.mResult = SockOpContextInfo::GetNResult(ctx->errType);
        netCtx.mMessage = nullptr;
        netCtx.mOpType =
            ctx->opType == SockOpContextInfo::SS_SEND ? UBSHcomNetRequestContext::NN_SENT :
            UBSHcomNetRequestContext::NN_SENT_RAW;

        netCtx.mOriginalReq = {};
        netCtx.mOriginalReq.upCtxSize = ctx->upCtxSize;

        if (netCtx.mOriginalReq.upCtxSize > 0 &&
            netCtx.mOriginalReq.upCtxSize <= sizeof(UBSHcomNetTransRequest::upCtxData)) {
            if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalReq.upCtxData, NN_NO16, ctx->upCtx, ctx->upCtxSize) != NN_OK)) {
                NN_LOG_ERROR("Failed to copy ctx to netCtx");
                result = NN_INVALID_PARAM;
            }
        }

        // call to callback
        if (result == NN_OK && NN_UNLIKELY((result = mRequestPostedHandler(netCtx)) != NN_OK)) {
            NN_LOG_ERROR("Call requestPostedHandler in Driver " << mName <<
                " return non-zero for receive message [opCode: " << netCtx.mHeader.opCode
                << ", dataSize " << netCtx.mHeader.dataLength << "]");
        }
        netCtx.mEp.Set(nullptr);
        if (!mOptions.tcpSendZCopy && ctx->sendBuff != nullptr) {
            ctx->sock->mSockDriverSendMR->ReturnBuffer(reinterpret_cast<uintptr_t>(ctx->sendBuff));
        }
    } else if (ctx->opType == SockOpContextInfo::SS_SEND_RAW_SGL) {
        return HandleSendRawSglReqPosted(ctx, netCtx);
    } else {
        NN_LOG_WARN("Unreachable path");
    }
    if (mOptions.tcpSendZCopy) {
        ctx->sock->mHeaderReqInfoPool.Return(ctx->headerRequest);
        ctx->headerRequest = nullptr;
    }
    ctx = nullptr;
    return result;
}

NResult NetDriverSockWithOOB::OneSideDone(SockOpContextInfo *ctx)
{
    NN_ASSERT_LOG_RETURN(ctx != nullptr, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx->sock != nullptr, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx->sock->UpContext() != 0, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx->sock->UpContext1() != 0, NN_ERROR)
    NResult result = NN_OK;

    auto worker = reinterpret_cast<SockWorker *>(ctx->sock->UpContext1());
    static thread_local UBSHcomNetRequestContext netCtx {};
    if (ctx->opType == SockOpContextInfo::SS_WRITE || ctx->opType == SockOpContextInfo::SS_READ) {
        // set context
        netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->sock->UpContext()));
        netCtx.mResult = SockOpContextInfo::GetNResult(ctx->errType);
        netCtx.mOpType =
            ctx->opType == SockOpContextInfo::SS_WRITE ? UBSHcomNetRequestContext::NN_WRITTEN :
            UBSHcomNetRequestContext::NN_READ;
        netCtx.mHeader.Invalid();
        netCtx.mMessage = nullptr;
        netCtx.mOriginalReq.lAddress = ctx->sendCtx->iov[0].lAddress;
        netCtx.mOriginalReq.lKey = ctx->sendCtx->iov[0].lKey;
        netCtx.mOriginalReq.size = ctx->sendCtx->iov[0].size;
        netCtx.mOriginalReq.upCtxSize = ctx->upCtxSize;

        if (netCtx.mOriginalReq.upCtxSize > 0 &&
            netCtx.mOriginalReq.upCtxSize <= sizeof(UBSHcomNetTransRequest::upCtxData)) {
            if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalReq.upCtxData, NN_NO16, ctx->upCtx, ctx->upCtxSize) != NN_OK)) {
                NN_LOG_ERROR("failed to copy ctx to upCtxData");
                result = NN_INVALID_PARAM;
            }
        }

        // return context to worker and ctx is not usable anymore
        worker->ReturnSglContextInfo(ctx->sendCtx);
        worker->ReturnOpContextInfo(ctx);

        // called to callback
        if (result == NN_OK && NN_UNLIKELY((result = mOneSideDoneHandler(netCtx)) != NN_OK)) {
            NN_LOG_ERROR("Call oneSideDoneHandler in Driver " << mName << " return non-zero for buff done");
        }
        netCtx.mEp.Set(nullptr);
    } else if (ctx->opType == SockOpContextInfo::SS_SGL_WRITE || ctx->opType == SockOpContextInfo::SS_SGL_READ) {
        auto sglCtx = ctx->sendCtx;
        // set context
        netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->sock->UpContext()));
        netCtx.mResult = SockOpContextInfo::GetNResult(ctx->errType);
        netCtx.mOpType = ctx->opType == SockOpContextInfo::SS_SGL_WRITE ? UBSHcomNetRequestContext::NN_SGL_WRITTEN :
                                                                          UBSHcomNetRequestContext::NN_SGL_READ;
        netCtx.mHeader.Invalid();
        netCtx.mMessage = nullptr;
        if (NN_UNLIKELY(memcpy_s(netCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV,
            sglCtx->iov, sizeof(UBSHcomNetTransSgeIov) * sglCtx->iovCount) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            result = NN_INVALID_PARAM;
        }
        netCtx.mOriginalSglReq.iov = netCtx.iov;
        netCtx.mOriginalSglReq.iovCount = sglCtx->iovCount;
        netCtx.mOriginalSglReq.upCtxSize = ctx->upCtxSize;
        if (netCtx.mOriginalSglReq.upCtxSize > 0 &&
            netCtx.mOriginalSglReq.upCtxSize <= sizeof(UBSHcomNetTransSglRequest::upCtxData)) {
            if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalSglReq.upCtxData, NN_NO16, ctx->upCtx, ctx->upCtxSize) != NN_OK)) {
                NN_LOG_ERROR("Failed to copy ctx to netCtx");
                result = NN_INVALID_PARAM;
            }
        }
        worker->ReturnSglContextInfo(sglCtx);
        worker->ReturnOpContextInfo(ctx);
        // called to callback
        if (result == NN_OK && NN_UNLIKELY((result = mOneSideDoneHandler(netCtx)) != NN_OK)) {
            NN_LOG_ERROR("Call oneSideDoneHandler in Driver " << mName << " return non-zero for sgl type done");
        }
        netCtx.mEp.Set(nullptr);
    } else {
        NN_LOG_WARN("Unreachable path");
    }

    return result;
}

NResult NetDriverSockWithOOB::HandleEpClose(Sock *sock)
{
    NN_ASSERT_LOG_RETURN(sock != nullptr, NN_ERROR);

    NN_LOG_WARN("sock " << sock->mName << " received the incorrect event and it is causing ep destroy.");
    return HandleSockError(sock);
}

NResult NetDriverSockWithOOB::MultiRailNewConnection(OOBTCPConnection &conn)
{
    NN_LOG_ERROR("Invalid operation, TCP is not supported by MultiRail");
    return NN_ERROR;
}
}
}
