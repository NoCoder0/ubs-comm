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
#include "hcom_def.h"
#ifdef RDMA_BUILD_ENABLED
#include "net_rdma_driver.h"
#include "net_rdma_sync_endpoint.h"
#include "net_rdma_async_endpoint.h"
#include "openssl_api_wrapper.h"
#include "rdma_common.h"
#include "rdma_mr_dm_buf.h"
#include "rdma_mr_fixed_buf.h"

namespace ock {
namespace hcom {
NResult NetDriverRDMA::Initialize(const UBSHcomNetDriverOptions &option)
{
    std::lock_guard<std::mutex> lock(mInitMutex);
    if (mInited) {
        return NN_OK;
    }

    mOptions = option;

    if (NN_UNLIKELY(UBSHcomNetOutLogger::Instance() == nullptr)) {
        return NN_NOT_INITIALIZED;
    }

    NResult verbsRes = NN_OK;
    if (NN_UNLIKELY((verbsRes = mOptions.ValidateCommonOptions()) != NN_OK)) {
        return verbsRes;
    }

    if (NN_UNLIKELY((verbsRes = ValidateOptions()) != NN_OK)) {
        return verbsRes;
    }

    NN_LOG_INFO("RDMA driver try to initialize with " << mOptions.ToString());

    if (option.enableTls) {
        if (HcomSsl::Load() != 0) {
            NN_LOG_ERROR("Failed to load openssl API");
            return NN_NOT_INITIALIZED;
        }
    }
    mEnableTls = option.enableTls;
    mHeartBeatIdleTime = mOptions.heartBeatIdleTime;
    mHeartBeatProbeInterval = mOptions.heartBeatProbeInterval;

    // create context and initialize
    if (((verbsRes = CreateContext()) != NN_OK)) {
        NN_LOG_ERROR("RDMA failed to create ctx");
        UnInitializeInner();
        return verbsRes;
    }

    if (((verbsRes = mContext->Initialize()) != NN_OK)) {
        NN_LOG_ERROR("RDMA failed to initialize ctx");
        UnInitializeInner();
        return verbsRes;
    }

    if ((verbsRes = CreateWorkerResource()) != NN_OK) {
        NN_LOG_ERROR("RDMA failed to create worker resource");
        UnInitializeInner();
        return verbsRes;
    }

    if ((verbsRes = CreateWorkers()) != NN_OK) {
        NN_LOG_ERROR("RDMA failed to create workers");
        UnInitializeInner();
        return verbsRes;
    }

    /* create lb for client */
    if ((verbsRes = CreateClientLB()) != NN_OK) {
        NN_LOG_ERROR("RDMA failed to create client lb");
        UnInitializeInner();
        return verbsRes;
    }

    if ((verbsRes = DoInitialize()) != NN_OK) {
        NN_LOG_ERROR("RDMA failed to do Initialize");
        UnInitializeInner();
        return verbsRes;
    }

    mMrChecker.Reserve(NN_NO128);
    mMrChecker.SetLockWhenOperates(false);

    mInited = true;
    return NN_OK;
}

NResult NetDriverRDMA::ValidateOptions()
{
    /* validate param related to device IpMask for RDMA and Sock */
    if (NN_UNLIKELY(!ValidateArrayOptions(mOptions.netDeviceIpMask, NN_NO256))) {
        NN_LOG_ERROR("Option 'netDeviceIpMask' is invalid, " << mOptions.netDeviceIpMask <<
            " is set in driver,the Array max length is 256.");
        return NN_INVALID_PARAM;
    }

    if (mOptions.prePostReceiveSizePerQP == 0) {
        NN_LOG_ERROR("Invalid option prePostReceiveSizePerQP " << mOptions.prePostReceiveSizePerQP <<
            ", should not be zero");
        return NN_INVALID_PARAM;
    }

    if (mOptions.prePostReceiveSizePerQP > NN_NO2048) {
        NN_LOG_WARN("Invalid option prePostReceiveSizePerQP " << mOptions.prePostReceiveSizePerQP <<
            ", should be <= " << NN_NO2048 << ", set to " << NN_NO2048);
        mOptions.prePostReceiveSizePerQP = NN_NO2048;
    }

    if (mOptions.maxPostSendCountPerQP == 0) {
        NN_LOG_ERROR("Invalid option maxPostSendCountPerQP " << mOptions.maxPostSendCountPerQP <<
            ", should not be zero");
        return NN_INVALID_PARAM;
    }

    if (mOptions.maxPostSendCountPerQP > NN_NO1024) {
        NN_LOG_WARN("Invalid option maxPostSendCountPerQP " << mOptions.maxPostSendCountPerQP << ", should be <= " <<
            NN_NO1024 << ", set to " << NN_NO1024);
        mOptions.maxPostSendCountPerQP = NN_NO1024;
    }

    if (mOptions.maxPostSendCountPerQP > mOptions.prePostReceiveSizePerQP) {
        NN_LOG_WARN("Invalid option maxPostSendCountPerQP " << mOptions.maxPostSendCountPerQP <<
            ", more than prePostReceiveSizePerQP " << mOptions.prePostReceiveSizePerQP << " , change to equal");
        mOptions.maxPostSendCountPerQP = mOptions.prePostReceiveSizePerQP;
    }

    if (mOptions.qpBatchRePostSize == 0 || mOptions.qpBatchRePostSize > QP_MAX_BATCH_RETURN_WR_SIZE) {
        NN_LOG_ERROR("Invalid option qpBatchRePostSize " << mOptions.qpBatchRePostSize
        << ", should not be zero or more than " << QP_MAX_BATCH_RETURN_WR_SIZE);
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(ValidateAndParseOobPortRange(mOptions.oobPortRange) != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(ValidateOptionsOobType() != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    return NN_OK;
}

NResult NetDriverRDMA::CreateContext()
{
    if (mContext != nullptr) {
        return NN_OK;
    }
    int result = 0;
    if (mOptions.enableMultiRail) {
        uint16_t enableCount = 0;
        std::vector<std::string> enableIps;
        result = RDMADeviceHelper::GetEnableDeviceCount(mOptions.NetDeviceIpMask(), enableCount, enableIps,
            mOptions.NetDeviceIpGroup());
        if (result != NN_OK) {
            return result;
        }
        mMatchIp = enableIps[mDevIndex];
    } else {
        // filter ip by mask
        std::vector<std::string> matchIps;
        if ((result = MatchIpByMask(matchIps)) != 0) {
            return result;
        }
        // init RoCE devices
        if ((result = RDMADeviceHelper::Initialize()) != 0) {
            NN_LOG_ERROR("Failed to init devices");
            return result;
        }

        NN_LOG_INFO(RDMADeviceHelper::DeviceInfo());

        // choose the first matched ip
        mMatchIp = matchIps[0];
    }
    RDMAGId tmpGid {};
    if ((result = RDMADeviceHelper::GetDeviceByIp(mMatchIp, tmpGid)) != 0) {
        RDMADeviceHelper::UnInitialize();
        NN_LOG_ERROR("Failed to get device by ip");
        return result;
    }

    NN_LOG_DEBUG("gid found devIndex " << tmpGid.devIndex << ", gidIndex " << tmpGid.gid << ", RoCEVersion " <<
        RDMADeviceHelper::RoCEVersionToStr(tmpGid.RoCEVersion));
    mBandWidth = tmpGid.bandWidth;
    // create context
    if ((result = RDMAContext::Create(mName, false, tmpGid, mContext)) != 0) {
        RDMADeviceHelper::UnInitialize();
        NN_LOG_ERROR("Failed to new ctx, result " << result);
        return result;
    }

    NN_ASSERT_LOG_RETURN(mContext != nullptr, NN_ERROR);
    mContext->IncreaseRef();

    return NN_OK;
}

NResult NetDriverRDMA::MatchIpByMask(std::vector<std::string> &matchIps)
{
    std::vector<std::string> filters;
    NetFunc::NN_SplitStr(mOptions.NetDeviceIpMask(), ",", filters);
    if (filters.empty()) {
        NN_LOG_ERROR("Invalid ip mask '" << mOptions.netDeviceIpMask << "' by set, example '192.168.0.0/24'");
        return NN_INVALID_IP;
    }

    for (auto &mask : filters) {
        FilterIp(mask, matchIps);
    }

    if (matchIps.empty()) {
        NN_LOG_ERROR("No matched ip found with '" << mOptions.netDeviceIpMask << "', example '192.168.0.0/24'");
        return NN_INVALID_IP;
    }
    return NN_OK;
}

NResult NetDriverRDMA::CreateSendMr()
{
    int result = 0;
    // create mr pool for send/receive and initialize
    if ((result = RDMAMemoryRegionFixedBuffer::Create(mName, mContext, mOptions.mrSendReceiveSegSize,
        mOptions.mrSendReceiveSegCount, mDriverSendMR)) != 0) {
        NN_LOG_ERROR("Failed to create mr for send/receive in NetDriverRDMA " << mName << ", result " << result);
        return result;
    }
    mDriverSendMR->IncreaseRef();
    if ((result = mDriverSendMR->Initialize()) != 0) {
        NN_LOG_ERROR("Failed to initialize mr for send/receive in NetDriverRDMA " << mName << ", result " << result);
        return result;
    }

    return NN_OK;
}

NResult NetDriverRDMA::CreateOpCtxMemPool()
{
    NetMemPoolFixedOptions options = {};
    options.superBlkSizeMB = NN_NO1;
    options.minBlkSize = NN_NextPower2(sizeof(RDMAOpContextInfo));
    options.tcExpandBlkCnt = NN_NO64;
    mOpCtxMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mOpCtxMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for rdma op context pool " << mName << ", probably out of memory");
        return NN_INVALID_PARAM;
    }

    auto result = mOpCtxMemPool->Initialize();
    if (result != NN_OK) {
        mOpCtxMemPool.Set(nullptr);
        NN_LOG_ERROR("Failed to initialize memory pool for rdma op context pool " << mName <<
            ", probably out of memory");
        return result;
    }

    return NN_OK;
}

NResult NetDriverRDMA::CreateSglCtxMemPool()
{
    NetMemPoolFixedOptions options = {};
    /* sgl ctx 里含 iov[NET_SGE_MAX_IOV] 数组，块尺寸随 NET_SGE_MAX_IOV 增长；
       池校验要求 superBlkSizeMB >= minBlkSize * tcExpandBlkCnt * 16，1MB 在 iov=30 时不够 */
    options.superBlkSizeMB = NN_NO4;
    options.minBlkSize = NN_NextPower2(sizeof(RDMASglContextInfo));
    options.tcExpandBlkCnt = NN_NO64;
    mSglCtxMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mSglCtxMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for rdma sgl op context in driver " << mName <<
            ", probably out of memory");
        return NN_INVALID_PARAM;
    }

    auto result = mSglCtxMemPool->Initialize();
    if (result != NN_OK) {
        mSglCtxMemPool.Set(nullptr);
        NN_LOG_ERROR("Failed to initialize memory pool for rdma sgl op context in driver " << mName <<
            ", probably out of memory");
        return result;
    }

    return NN_OK;
}

NResult NetDriverRDMA::CreateWorkerResource()
{
    auto result = CreateSendMr();
    if (result != NN_OK) {
        NN_LOG_ERROR("RDMA falied to create send mr");
        return result;
    }

    result = CreateOpCtxMemPool();
    if (result != NN_OK) {
        NN_LOG_ERROR("RDMA failed to create op ctx memory pool");
        return result;
    }

    result = CreateSglCtxMemPool();
    if (result != NN_OK) {
        NN_LOG_ERROR("RDMA failed to create Sgl ctx memory pool");
        return result;
    }

    return NN_OK;
}

void NetDriverRDMA::ClearWorkers()
{
    mWorkerGroups.clear();
    for (auto worker : mWorkers) {
        worker->DecreaseRef();
    }
    mWorkers.clear();
}

void NetDriverRDMA::DestroyEndpoint(UBSHcomNetEndpointPtr &ep)
{
    if (ep.Get() == nullptr) {
        NN_LOG_WARN("The verbs ep is null already.");
        return;
    }

    NN_LOG_INFO("Verbs Destroy endpoint id " << ep->Id());
    mEndPointsMutex.lock();
    auto result = mEndPoints.erase(ep->Id());
    mEndPointsMutex.unlock();

    if (result == 0) {
        NN_LOG_WARN("Verbs unable to destroy endpoint as ep " << ep->Id() << " doesn't exist, maybe cleaned already");
        return;
    }

    ep.Set(nullptr);
}

NResult NetDriverRDMA::CreateWorkers()
{
    NResult result = NN_OK;

    std::vector<uint16_t> workerGroups;
    std::vector<int16_t> flatWorkerCpus;
    std::vector<int16_t> workerThreadPriority;
    std::vector<std::pair<uint8_t, uint8_t>> workerGroupCpus;

    /* parse */
    if (!(NetFunc::NN_ParseWorkersGroups(mOptions.WorkGroups(), workerGroups)) ||
        !(NetFunc::NN_ParseWorkerGroupsCpus(mOptions.WorkerGroupCpus(), workerGroupCpus)) ||
        !(NetFunc::NN_FinalizeWorkerGroupCpus(workerGroups, workerGroupCpus, mOptions.mode != NET_BUSY_POLLING,
        flatWorkerCpus)) ||
        !(NetFunc::NN_ParseWorkersGroupsThreadPriority(mOptions.WorkerGroupThreadPriority(), workerThreadPriority,
        workerGroups.size()))) {
        NN_LOG_ERROR("Failed to parse worker or cpu groups");
        return NN_INVALID_PARAM;
    }

    RDMAWorkerOptions options;
    options.SetValue(mOptions);
    if ((mOptions.workerThreadPriority != 0) && (!workerThreadPriority.empty())) {
        NN_LOG_WARN("Driver options 'workerThreadPriority' and 'workerGroupsThreadPriority' set all, preferential use "
            "'workerGroupsThreadPriority'.");
    }

    /* create workers */
    mWorkers.reserve(flatWorkerCpus.size());
    uint32_t groupIndex = 0;
    UBSHcomNetWorkerIndex workerIndex{};
    uint16_t totalWorkerIndex = 0;
    for (auto item : workerGroups) {
        NN_LOG_TRACE_INFO("Add worker " << groupIndex << ", item " << item);
        /* The left of mWorkerGroups is the index of each group's first worker in the mWorkers */
        mWorkerGroups.emplace_back(totalWorkerIndex, item);
        for (uint16_t i = 0; i < item; ++i) {
            options.cpuId = flatWorkerCpus.at(totalWorkerIndex++);
            if (!workerThreadPriority.empty()) {
                options.threadPriority = workerThreadPriority[groupIndex];
            }
            RDMAWorker *worker = nullptr;
            if (NN_UNLIKELY(
                (result = RDMAWorker::Create(mName, mContext, options, mOpCtxMemPool, mSglCtxMemPool, worker)) != 0)) {
                return result;
            }

            workerIndex.Set(i, groupIndex, mIndex);
            worker->SetIndex(workerIndex);

            if (NN_UNLIKELY((result = worker->Initialize()) != NN_OK)) {
                delete worker;
                NN_LOG_ERROR("Failed to initialize rdma worker in driver " << mName << ", result " << result);
                return NN_NEW_OBJECT_FAILED;
            }

            worker->IncreaseRef();
            mWorkers.push_back(worker);
        }
        ++groupIndex;
    }

    std::ostringstream groupInfo;
    groupInfo << "Worker group info : ";
    for (auto item : mWorkerGroups) {
        groupInfo << "[" << item.first << " : " << item.second << "] ";
    }
    NN_LOG_TRACE_INFO(groupInfo.str());
    return NN_OK;
}

void NetDriverRDMA::UnInitialize()
{
    std::lock_guard<std::mutex> locker(mInitMutex);
    if (!mInited) {
        return;
    }
    if (mStarted) {
        NN_LOG_WARN("Invalid to UnInitialize driver " << mName << " which is not stopped");
        return;
    }

    DoUnInitialize();

    UnInitializeInner();
    mInited = false;
}

void NetDriverRDMA::UnInitializeInner()
{
    if (mContext != nullptr) {
        mContext->DecreaseRef();
        mContext = nullptr;
    }

    if (mDriverSendMR != nullptr) {
        mDriverSendMR->DecreaseRef();
        mDriverSendMR = nullptr;
    }

    if (mOpCtxMemPool != nullptr) {
        mOpCtxMemPool.Set(nullptr);
    }

    DestroyClientLB();
    ClearWorkers();
}

NResult NetDriverRDMA::Start()
{
    std::lock_guard<std::mutex> locker(mInitMutex);
    if (mStarted) {
        return NN_OK;
    }

    if (!mInited) {
        NN_LOG_ERROR("Failed to start NetDriverRDMA " << mName << ", as isn't initialized");
        return NN_ERROR;
    }

    NResult result = NN_OK;
    if (!mOptions.dontStartWorkers) {
        if (NN_UNLIKELY(result = ValidateHandlesCheck()) != NN_OK) {
            return result;
        }
        for (uint64_t i = 0; i < mWorkers.size(); i++) {
            if (NN_LIKELY((result = mWorkers[i]->Start()) == NN_OK)) {
                continue;
            }
            NN_LOG_ERROR("Failed to start RDMA driver " << mName << " as failed to start worker");
            for (uint64_t j = 0; j < i; j++) {
                mWorkers[j]->Stop();
            }
            return result;
        }
    } else {
        NN_LOG_INFO("Workers in driver " << mName << " will not be started as option dontStartWorkers is true");
    }

    if (NN_UNLIKELY(result = DoStart()) != NN_OK) {
        NN_LOG_ERROR("Failed to do start NetDriverRDMA " << mName << ", result " << result);
        for (auto worker : mWorkers) {
            worker->Stop();
        }
        return result;
    }
    mStarted = true;
    return NN_OK;
}

void NetDriverRDMA::Stop()
{
    std::lock_guard<std::mutex> locker(mInitMutex);
    if (!mStarted) {
        return;
    }

    DoStop();

    for (auto worker : mWorkers) {
        worker->Stop();
    }

    mStarted = false;
}

NResult NetDriverRDMA::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (NN_UNLIKELY(size == 0 || size > NN_NO107374182400)) {
        NN_LOG_ERROR("Failed to create mem region as size is 0 or greater than 100 GB");
        return NN_INVALID_PARAM;
    }

    if (!mInited) {
        NN_LOG_ERROR("Failed to create Memory region in NetDriverRDMA " << mName << ", as not initialized");
        return NN_EP_NOT_INITIALIZED;
    }

    RDMAMemoryRegion *tmp = nullptr;
    auto result = RDMAMemoryRegion::Create(mName, mContext, size, tmp);
    if (NN_UNLIKELY(result != RR_OK)) {
        NN_LOG_ERROR("Failed to create Memory region in NetDriverRDMA " << mName << ", probably out of memory");
        return result;
    }

    if ((result = tmp->Initialize()) != RR_OK) {
        delete tmp;
        return result;
    }

    if ((result = mMrChecker.Register(tmp->GetLKey(), tmp->GetAddress(), size)) != NN_OK) {
        NN_LOG_ERROR("Failed to add rdma memory region to range checker in driver" << mName << " for duplicate keys");
        delete tmp;
        return result;
    }

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));

    return NN_OK;
}

NResult NetDriverRDMA::CreateMemoryRegion(uintptr_t address, uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (NN_UNLIKELY(size == 0 || size > NN_NO1099511627776)) {
        NN_LOG_ERROR("RDMA Failed to create mem region as size is 0 or greater than 1 TB");
        return NN_INVALID_PARAM;
    }

    if (!mInited) {
        NN_LOG_ERROR("Failed to create Memory region with ptr in NetDriverRDMA " << mName << ", as not initialized");
        return NN_EP_NOT_INITIALIZED;
    }

    if (address == 0) {
        NN_LOG_ERROR("Failed to create Memory region with ptr in NetDriverRDMA " << mName << ", as address is 0");
        return NN_INVALID_PARAM;
    }

    RDMAMemoryRegion *tmp = nullptr;
    auto result = RDMAMemoryRegion::Create(mName, mContext, address, size, tmp);
    if (NN_UNLIKELY(result != RR_OK)) {
        NN_LOG_ERROR("Failed to create Memory region with ptr in NetDriverRDMA " << mName <<
            ", probably out of memory");
        return result;
    }

    if ((result = tmp->Initialize()) != RR_OK) {
        delete tmp;
        return result;
    }

    if ((result = mMrChecker.Register(tmp->GetLKey(), tmp->GetAddress(), size)) != NN_OK) {
        NN_LOG_ERROR("Failed to add memory region with ptr to range checker in driver" << mName <<
            " for duplicate keys");
        delete tmp;
        return result;
    }

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));

    return NN_OK;
}

NResult NetDriverRDMA::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr, unsigned long memid)
{
    NN_LOG_ERROR("operation is not supported in rdma");
    return NN_ERROR;
}

void NetDriverRDMA::DestroyMemoryRegion(UBSHcomNetMemoryRegionPtr &mr)
{
    if (mr.Get() == nullptr) {
        NN_LOG_WARN("Try to destroy null memory region in rdma driver " << mName);
        return;
    }
    if (!mMrChecker.Contains(mr->GetLKey())) {
        NN_LOG_WARN("Try to destroy unowned memory region in rdma driver " << mName);
        return;
    }
    mMrChecker.UnRegister(mr->GetLKey());
    mr->UnInitialize();
}
} // namespace hcom
}
#endif