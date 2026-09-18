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
#ifdef UB_BUILD_ENABLED

#include "hcom_def.h"
#include "net_ub_driver.h"
#include "net_ub_endpoint.h"
#include "openssl_api_wrapper.h"
#include "ub_common.h"
#include "ub_mr_fixed_buf.h"
#include "ub_worker.h"
#include "net_common.h"

namespace ock {
namespace hcom {
NResult NetDriverUB::Initialize(const UBSHcomNetDriverOptions &option)
{
    std::lock_guard<std::mutex> lock(mInitMutex);
    if (mInited) {
        return NN_OK;
    }

    mOptions = option;

    if (NN_UNLIKELY(UBSHcomNetOutLogger::Instance() == nullptr)) {
        return NN_NOT_INITIALIZED;
    }

    NResult result = NN_OK;
    if (NN_UNLIKELY((result = mOptions.ValidateCommonOptions()) != NN_OK)) {
        return result;
    }

    if (NN_UNLIKELY((result = ValidateOptions()) != NN_OK)) {
        return result;
    }

    NN_LOG_INFO("Try to initialize with " << mOptions.ToString());

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
    if (((result = CreateContext()) != NN_OK)) {
        NN_LOG_ERROR("UB failed to create ctx");
        UnInitializeInner();
        return result;
    }

    if ((result = ValidaQpQueueSizeOptions()) != NN_OK) {
        NN_LOG_ERROR("UB failed to validate qp queue size options");
        UnInitializeInner();
        return result;
    }

    if ((result = CreateWorkerResource()) != NN_OK) {
        NN_LOG_ERROR("UB failed to create worker resource");
        UnInitializeInner();
        return result;
    }

    if ((result = CreateWorkers()) != NN_OK) {
        NN_LOG_ERROR("UB failed to create workers");
        UnInitializeInner();
        return result;
    }

    /* create lb for client */
    if ((result = CreateClientLB()) != NN_OK) {
        NN_LOG_ERROR("UB failed to create client lb");
        UnInitializeInner();
        return result;
    }

    if ((result = DoInitialize()) != NN_OK) {
        NN_LOG_ERROR("UB failed to do initialize");
        UnInitializeInner();
        return result;
    }

    mMrChecker.Reserve(NN_NO128);
    mMrChecker.SetLockWhenOperates(false);

    mInited = true;
    return NN_OK;
}

NResult NetDriverUB::ValidateOptions()
{
    /* validate param related to device IpMask for UB and Sock */
    if (NN_UNLIKELY(!ValidateArrayOptions(mOptions.netDeviceIpMask, NN_NO256))) {
        NN_LOG_ERROR("Option 'netDeviceIpMask' is invalid, " << mOptions.netDeviceIpMask <<
            " is set in driver,the Array max length is 256.");
        return NN_INVALID_PARAM;
    }

    uint64_t sendRecvMrSize = static_cast<uint64_t>(mOptions.mrSendReceiveSegCount) * mOptions.mrSendReceiveSegSize;

    if (mOptions.prePostReceiveSizePerQP == 0) {
        NN_LOG_ERROR("Invalid option prePostReceiveSizePerQP " << mOptions.prePostReceiveSizePerQP <<
            ", should not be zero");
        return NN_INVALID_PARAM;
    }

    // 32K 为硬件 max_jfr_depth 上限
    if (mOptions.prePostReceiveSizePerQP > NN_NO32768) {
        NN_LOG_WARN("Invalid option prePostReceiveSizePerQP " << mOptions.prePostReceiveSizePerQP <<
            ", should be <= " << NN_NO32768 << ", set to " << NN_NO32768);
        mOptions.prePostReceiveSizePerQP = NN_NO32768;
    }

    if (mOptions.maxPostSendCountPerQP == 0) {
        NN_LOG_ERROR("Invalid option maxPostSendCountPerQP " << mOptions.maxPostSendCountPerQP <<
            ", should not be zero");
        return NN_INVALID_PARAM;
    }

    if (mOptions.maxPostSendCountPerQP > NN_NO32768) {
        NN_LOG_WARN("Invalid option maxPostSendCountPerQP " << mOptions.maxPostSendCountPerQP << ", should be <= " <<
            NN_NO32768 << ", set to " << NN_NO32768);
        mOptions.maxPostSendCountPerQP = NN_NO32768;
    }

    if (mOptions.maxPostSendCountPerQP > mOptions.prePostReceiveSizePerQP) {
        NN_LOG_WARN("Invalid option maxPostSendCountPerQP " << mOptions.maxPostSendCountPerQP <<
            ", over than prePostReceiveSizePerQP " << mOptions.prePostReceiveSizePerQP << " , change to equal");
        mOptions.maxPostSendCountPerQP = mOptions.prePostReceiveSizePerQP;
    }

    if (NN_UNLIKELY(ValidateAndParseOobPortRange(mOptions.oobPortRange) != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(ValidateOptionsOobType() != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    return NN_OK;
}

NResult NetDriverUB::ValidaQpQueueSizeOptions()
{
    if (mContext == nullptr) {
        NN_LOG_WARN("Unable to get system max jfs and max jfr, cannot compare with Option 'qpSendQueueSize' and "
            "'qpReceiveQueueSize'.");
        return NN_OK;
    }
    uint32_t maxJfs = mContext->GetMaxJfs();
    uint32_t maxJfr = mContext->GetMaxJfr();
    if (NN_UNLIKELY(maxJfs < NN_NO8 || maxJfr < NN_NO8)) {
        NN_LOG_ERROR("Urma max Jfs and max jfr less than or equal to 8. ");
        return NN_ERROR;
    }
    uint32_t needJfs = maxJfs - NN_NO8;
    uint32_t needJfr = maxJfr - NN_NO8;
    if (mOptions.qpSendQueueSize > needJfs) {
        NN_LOG_WARN("Urma max Jfs is " << maxJfs << " , urma option 'qpSendQueueSize' range is 16~" << needJfs <<
            " ,change 'qpSendQueueSize' to " << needJfs);
        mOptions.qpSendQueueSize = needJfs;
    }
    if (mOptions.qpReceiveQueueSize > needJfr) {
        NN_LOG_WARN("Urma max Jfr is " << maxJfr << " , urma option 'qpReceiveQueueSize' range is 16~" << needJfr <<
            " ,change 'qpReceiveQueueSize' to " << needJfr);
        mOptions.qpReceiveQueueSize = needJfr;
    }
    return NN_OK;
}

NResult NetDriverUB::CreateContext()
{
    if (mContext != nullptr) {
        return NN_OK;
    }

    int result = 0;
    // create context
    UBContext *tmpCtx = nullptr;
    if ((result = UBContext::Create(mName, tmpCtx)) != 0) {
        NN_LOG_ERROR("Failed to new ctx, result " << result);
        return result;
    }

    NN_ASSERT_LOG_RETURN(tmpCtx != nullptr, NN_ERROR);

    tmpCtx->IncreaseRef();
    tmpCtx->protocol = Protocol();

    if (((result = tmpCtx->Initialize(mBandWidth, mOptions.ubPriority, mOptions.ubcMode)) != 0)) {
        NN_LOG_ERROR("UB failed to initialize ctx");
        tmpCtx->DecreaseRef();
        tmpCtx = nullptr;
        return result;
    }
    mContext = tmpCtx;

    uvs_eid_t eid{};
    std::string strEid;
    (void)memcpy(&eid, &tmpCtx->mBestEid.urmaEid, sizeof(urma_eid_t));
    NetFunc::NN_EidToStr(eid, strEid);
    mEid = strEid;
    NN_LOG_DEBUG("UBContext created with best eid: " << mEid);
    return NN_OK;
}

NResult NetDriverUB::CreateSendMr(uint8_t slave)
{
    int result = 0;
    // create mr pool for send/receive and initialize
    if ((result = UBMemoryRegionFixedBuffer::Create(mName, mContext, mOptions.mrSendReceiveSegSize,
        mOptions.mrSendReceiveSegCount, slave, mDriverSendMR)) != 0) {
        NN_LOG_ERROR("Failed to create mr for send/receive in NetDriverUB " << mName << ", result " << result);
        return result;
    }
    mDriverSendMR->IncreaseRef();
    if ((result = mDriverSendMR->Initialize()) != 0) {
        NN_LOG_ERROR("Failed to initialize mr for send/receive in NetDriverUB " << mName << ", result " << result);
        return result;
    }

    return NN_OK;
}

NResult NetDriverUB::CreateOpCtxMemPool()
{
    NetMemPoolFixedOptions options = {};
    options.superBlkSizeMB = NN_NO1;
    options.minBlkSize = NN_NextPower2(sizeof(UBOpContextInfo));
    options.tcExpandBlkCnt = NN_NO64;
    mOpCtxMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mOpCtxMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for UB op context pool " << mName << ", probably out of memory");
        return NN_INVALID_PARAM;
    }

    auto result = mOpCtxMemPool->Initialize();
    if (result != NN_OK) {
        mOpCtxMemPool.Set(nullptr);
        NN_LOG_ERROR("Failed to initialize memory pool for UB op context pool " << mName << ", probably out of memory");
        return result;
    }

    return NN_OK;
}

NResult NetDriverUB::CreateSglCtxMemPool()
{
    NetMemPoolFixedOptions options = {};
    // Match the enlarged SGL context and the pool's 64 * 16 block minimum.
    options.superBlkSizeMB = NN_NO4;
    options.minBlkSize = NN_NextPower2(sizeof(UBSglContextInfo));
    options.tcExpandBlkCnt = NN_NO64;
    mSglCtxMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mSglCtxMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for UB sgl op context in driver " << mName <<
            ", probably out of memory");
        return NN_INVALID_PARAM;
    }

    auto result = mSglCtxMemPool->Initialize();
    if (result != NN_OK) {
        mSglCtxMemPool.Set(nullptr);
        NN_LOG_ERROR("Failed to initialize memory pool for UB sgl op context in driver " << mName <<
            ", probably out of memory");
        return result;
    }

    return NN_OK;
}

NResult NetDriverUB::CreateWorkerResource()
{
    auto result = CreateSendMr(mOptions.slave);
    if (result != NN_OK) {
        NN_LOG_ERROR("UB falied to create send mr");
        return result;
    }

    result = CreateOpCtxMemPool();
    if (result != NN_OK) {
        NN_LOG_ERROR("UB Failed to create op ctx memory pool");
        return result;
    }

    result = CreateSglCtxMemPool();
    if (NN_UNLIKELY(result != NN_OK)) {
        NN_LOG_ERROR("UB failed to create Sgl ctx memory pool");
    }

    return NN_OK;
}

void NetDriverUB::ClearWorkers()
{
    mWorkerGroups.clear();
    for (auto worker : mWorkers) {
        worker->DecreaseRef();
    }
    mWorkers.clear();
}

void NetDriverUB::DestroyEndpoint(UBSHcomNetEndpointPtr &ep)
{
    if (ep.Get() == nullptr) {
        NN_LOG_WARN("The ub ep is null already.");
        return;
    }

    NN_LOG_INFO("Destroy endpoint id " << ep->Id());
    mEndPointsMutex.lock();
    auto result = mEndPoints.erase(ep->Id());
    mEndPointsMutex.unlock();

    if (result == 0) {
        NN_LOG_WARN("Unable to destroy ub endpoint as ep " << ep->Id() << " doesn't exist, maybe cleaned already");
        return;
    }

    ep.Set(nullptr);
}

NResult NetDriverUB::CreateWorkers()
{
    NResult result = NN_OK;

    std::vector<uint16_t> workerGroups;
    std::vector<std::pair<uint8_t, uint8_t>> workerGroupCpus;
    std::vector<int16_t> flatWorkerCpus;
    std::vector<int16_t> workerThreadPriority;

    /* parse */
    if (!(NetFunc::NN_ParseWorkersGroups(mOptions.WorkGroups(), workerGroups)) ||
        !(NetFunc::NN_ParseWorkerGroupsCpus(mOptions.WorkerGroupCpus(), workerGroupCpus)) ||
        !(NetFunc::NN_FinalizeWorkerGroupCpus(workerGroups, workerGroupCpus, mOptions.mode != NET_BUSY_POLLING,
        flatWorkerCpus)) ||
        !(NetFunc::NN_ParseWorkersGroupsThreadPriority(mOptions.WorkerGroupThreadPriority(),
        workerThreadPriority, workerGroups.size()))) {
        NN_LOG_ERROR("Failed to parse worker or cpu groups");
        return NN_INVALID_PARAM;
    }

    UBWorkerOptions options;
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
        NN_LOG_TRACE_INFO("add worker " << groupIndex << ", item " << item);
        /* The left of mWorkerGroups is the index of each group's first worker in the mWorkers */
        mWorkerGroups.emplace_back(totalWorkerIndex, item);
        for (uint16_t i = 0; i < item; ++i) {
            options.cpuId = flatWorkerCpus.at(totalWorkerIndex++);
            if (!workerThreadPriority.empty()) {
                options.threadPriority = workerThreadPriority[groupIndex];
            }
            UBWorker *worker = nullptr;
            if (NN_UNLIKELY(
                (result = UBWorker::Create(mName, mContext, options, mOpCtxMemPool, mSglCtxMemPool, worker)) != 0)) {
                return result;
            }

            workerIndex.Set(i, groupIndex, mIndex);
            worker->SetIndex(workerIndex);

            if (NN_UNLIKELY((result = worker->Initialize()) != NN_OK)) {
                delete worker;
                NN_LOG_ERROR("Failed to initialize UB worker in driver " << mName << ", result " << result);
                return NN_NEW_OBJECT_FAILED;
            }

            worker->IncreaseRef();
            mWorkers.push_back(worker);
        }
        ++groupIndex;
    }

    std::ostringstream groupInfo;
    groupInfo << "Worker group info :";
    for (auto item : mWorkerGroups) {
        groupInfo << " [" << item.first << " : " << item.second << "] ";
    }
    NN_LOG_TRACE_INFO(groupInfo.str());
    return NN_OK;
}

void NetDriverUB::UnInitialize()
{
    std::lock_guard<std::mutex> locker(mInitMutex);
    if (!mInited) {
        return;
    }
    if (mStarted) {
        NN_LOG_WARN("Unable to unInitialize ub driver " << mName << " which is not stopped");
        return;
    }

    DoUnInitialize();

    UnInitializeInner();
    mInited = false;
}

void NetDriverUB::UnInitializeInner()
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

#define DRIVER_CHECK_HANDLES()                                                                               \
    do {                                                                                                     \
        if (mReceivedRequestHandler == nullptr) {                                                            \
            NN_LOG_ERROR("Failed to do start in Driver " << mName << ", as receivedRequestHandler is null"); \
            return NN_INVALID_PARAM;                                                                         \
        }                                                                                                    \
                                                                                                             \
        if (mRequestPostedHandler == nullptr) {                                                              \
            NN_LOG_ERROR("Failed to do start in Driver " << mName << ", as requestPostedHandler is null");   \
            return NN_INVALID_PARAM;                                                                         \
        }                                                                                                    \
                                                                                                             \
        if (mOneSideDoneHandler == nullptr) {                                                                \
            NN_LOG_ERROR("Failed to do start in Driver " << mName << ", as oneSideDoneHandler is null");     \
            return NN_INVALID_PARAM;                                                                         \
        }                                                                                                    \
                                                                                                             \
        if (mEndPointBrokenHandler == nullptr) {                                                             \
            NN_LOG_ERROR("Failed to do start in Driver " << mName << ", as endPointBrokenHandler is null");  \
            return NN_INVALID_PARAM;                                                                         \
        }                                                                                                    \
    } while (0)

NResult NetDriverUB::Start()
{
    std::lock_guard<std::mutex> locker(mInitMutex);
    if (mStarted) {
        return NN_OK;
    }

    if (!mInited) {
        NN_LOG_ERROR("Failed to start NetDriverUB " << mName << ", as isn't initialized");
        return NN_ERROR;
    }

    NResult result = NN_OK;
    if (!mOptions.dontStartWorkers) {
        DRIVER_CHECK_HANDLES();
        for (uint64_t i = 0; i < mWorkers.size(); i++) {
            if (NN_LIKELY((result = mWorkers[i]->Start()) == NN_OK)) {
                continue;
            }
            NN_LOG_ERROR("Failed to start driver " << mName << " as failed to start worker");
            for (uint64_t j = 0; j < i; j++) {
                mWorkers[j]->Stop();
            }
            return result;
        }
    } else {
        NN_LOG_INFO("Workers in driver " << mName << " will not be started as dontStartWorkers is true");
    }

    if (NN_UNLIKELY(result = DoStart()) != NN_OK) {
        NN_LOG_ERROR("Failed to do start NetDriverUB " << mName << ", result " << result);
        for (auto worker : mWorkers) {
            worker->Stop();
        }
        return result;
    }
    mStarted = true;
    return NN_OK;
}

void NetDriverUB::Stop()
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

NResult NetDriverUB::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (NN_UNLIKELY(size == 0 || size > NN_NO107374182400)) {
        NN_LOG_ERROR("Failed to create mem region as size is 0 or greater than 100 GB");
        return NN_INVALID_PARAM;
    }

    if (!mInited) {
        NN_LOG_ERROR("Failed to create Memory region in NetDriverUB " << mName << ", as not initialized");
        return NN_EP_NOT_INITIALIZED;
    }

    UBMemoryRegion *tmp = nullptr;
    auto res = UBMemoryRegion::Create(mName, mContext, size, tmp);
    if (NN_UNLIKELY(res != UB_OK)) {
        NN_LOG_ERROR("Failed to create Memory region in NetDriverUB " << mName << ", probably out of memory");
        return res;
    }

    if ((res = tmp->InitializeForOneSide()) != UB_OK) {
        delete tmp;
        return res;
    }

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));
    std::lock_guard<std::mutex> locker(mLockTseg);
    mMapTseg.emplace(mr->GetLKey(), static_cast<urma_target_seg_t *>(tmp->GetMemorySeg()));

    return NN_OK;
}

NResult NetDriverUB::CreateMemoryRegion(uintptr_t address, uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (!mInited) {
        NN_LOG_ERROR("Failed to create Memory region with ptr in NetDriverUB " << mName << ", as not initialized");
        return NN_EP_NOT_INITIALIZED;
    }

    if (address == 0) {
        NN_LOG_ERROR("Failed to create Memory region with ptr in NetDriverUB " << mName << ", as address is 0");
        return NN_INVALID_PARAM;
    }

    UBMemoryRegion *tmp = nullptr;
    auto result = UBMemoryRegion::Create(mName, mContext, address, size, tmp);
    if (NN_UNLIKELY(result != UB_OK)) {
        NN_LOG_ERROR("Failed to create Memory region with ptr in NetDriverUB " << mName << ", probably out of memory");
        return result;
    }

    if ((result = tmp->InitializeForOneSide()) != UB_OK) {
        delete tmp;
        return result;
    }

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));
    std::lock_guard<std::mutex> locker(mLockTseg);
    mMapTseg.emplace(mr->GetLKey(), static_cast<urma_target_seg_t *>(tmp->GetMemorySeg()));

    return NN_OK;
}

NResult NetDriverUB::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr, unsigned long memid)
{
    NN_LOG_ERROR("operation not supported in non-hccs NetDriverUB ");
    return NN_ERROR;
}

void NetDriverUB::DestroyMemoryRegion(UBSHcomNetMemoryRegionPtr &mr)
{
    if (mr.Get() == nullptr) {
        NN_LOG_WARN("Try to destroy null memory region in UB driver " << mName);
        return;
    }

    std::lock_guard<std::mutex> locker(mLockTseg);
    auto result = mMapTseg.erase(mr->GetLKey());
    if (result == 0) {
        NN_LOG_WARN("Unable to erase mr from driver as " << mr->GetLKey() << " doesn't exist, maybe cleaned already");
    }

    mr->UnInitialize();
}

inline urma_target_seg_t *NetDriverUB::ImportSeg(uintptr_t addr, uint32_t bufSize, uint64_t token, urma_eid_t eid)
{
    uint32_t tokenId = static_cast<uint32_t>(token);
    urma_token_t tokenValue = {static_cast<uint32_t>(token >> NN_NO32)};
    urma_seg_t remoteSeg{};
    remoteSeg.len = bufSize;
    remoteSeg.ubva.va = addr;
    remoteSeg.token_id = tokenId;
    remoteSeg.ubva.eid = eid;
    remoteSeg.attr.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
 
    urma_import_seg_flag_t flag{};
    flag.bs.cacheable = URMA_NON_CACHEABLE;
    flag.bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE;
    flag.bs.mapping = URMA_SEG_NOMAP;
 
    return HcomUrma::ImportSeg(mContext->mUrmaContext, &remoteSeg, &tokenValue, 0, flag);
}
 
NResult NetDriverUB::ImportUrmaSeg(uintptr_t address, uint64_t size, uint64_t key, void **tSeg, uint8_t *eid,
    uint32_t eidLen)
{
    NN_LOG_INFO("ImportUrmaSeg, size: " << size << ", key :" << key);
    urma_eid_t urmaEid{};
    if (eid == nullptr || eidLen == 0) {
        NN_LOG_ERROR("eid is null");
        return NN_ERROR;
    }
    auto ret = memcpy_s(urmaEid.raw, sizeof(urma_eid_t), eid, eidLen);
    if (ret != 0) {
        NN_LOG_ERROR("eid is null");
        return NN_ERROR;
    }

    urma_target_seg_t *dstSeg = ImportSeg(address, size, key, urmaEid);
    if (dstSeg == nullptr) {
        NN_LOG_ERROR("ImportSeg failed");
        return NN_ERROR;
    }
    *tSeg = static_cast<void *>(dstSeg);
    return NN_OK;
}
 
}
}
#endif
