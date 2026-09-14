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
#include <dirent.h>
#include <iostream>

#include "hcom_def.h"
#include "hcom_log.h"
#include "net_shm_sync_endpoint.h"
#include "net_shm_async_endpoint.h"
#include "net_oob_secure.h"
#include "net_oob_ssl.h"
#include "shm_composed_endpoint.h"
#include "shm_validation.h"
#include "shm_handle_fds.h"
#include "net_shm_driver_oob.h"

namespace ock {
namespace hcom {
constexpr const char *CHANNEL_KEEPER_NAME = "channel_keeper";
constexpr const char *DELAY_RELEASE_TIMER_NAME = "delay_release_timer";
constexpr const char *SHM_FILE_DIR_PATH = "/dev/shm";
constexpr const char *SHM_FILE_PREFIX = "hcom-";

NResult NetDriverShmWithOOB::Initialize(const UBSHcomNetDriverOptions &option)
{
    std::lock_guard<std::mutex> guard(mInitMutex);
    if (mInited) {
        return NN_OK;
    }

    mOptions = option;

    NResult shmRes = NN_OK;
    if (NN_UNLIKELY((shmRes = mOptions.ValidateCommonOptions()) != NN_OK)) {
        return shmRes;
    }

    if (NN_UNLIKELY(ValidateOptions() != NN_OK)) {
        return shmRes;
    }

    if (NN_UNLIKELY(UBSHcomNetOutLogger::Instance() == nullptr)) {
        return NN_NOT_INITIALIZED;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
    std::thread clearThread(&NetDriverShmWithOOB::ClearShmLeftFile, this);
    mClearThread = std::move(clearThread);
    std::string treadName = "clearShmFile" + std::to_string(mIndex);
    if (pthread_setname_np(mClearThread.native_handle(), treadName.c_str()) != 0) {
        NN_LOG_WARN("Unable to set name of NetDriverShmWithOOB clearThread working thread to " << treadName);
    }

    while (!mClearThreadStarted.load()) {
        usleep(NN_NO10);
    }
#endif

    if (option.enableTls) {
        if (HcomSsl::Load() != 0) {
            NN_LOG_ERROR("Failed to load openssl API");
            return NN_NOT_INITIALIZED;
        }
    }
    mEnableTls = option.enableTls;
    NN_LOG_INFO("Try to initialize driver '" << mName << "' with " << mOptions.ToString());

    if ((shmRes = CreateWorkerResource()) != NN_OK) {
        NN_LOG_ERROR("Shm failed to create worker resource");
        UnInitializeInner();
        return shmRes;
    }

    /* create workers */
    if ((shmRes = CreateWorkers()) != NN_OK) {
        NN_LOG_ERROR("Shm failed to create workers");
        UnInitializeInner();
        return shmRes;
    }

    /* create lb for client */
    if ((shmRes = CreateClientLB()) != NN_OK) {
        NN_LOG_ERROR("Shm failed to create client lb");
        UnInitializeInner();
        return shmRes;
    }

    /* create oob */
    if (mStartOobSvr) {
        if ((shmRes = CreateListeners()) != NN_OK) {
            NN_LOG_ERROR("Shm failed to create listeners");
            UnInitializeInner();
            return shmRes;
        }
    }

    auto channelKeeper = new (std::nothrow) ShmChannelKeeper(CHANNEL_KEEPER_NAME, mIndex);
    if (NN_UNLIKELY(channelKeeper == nullptr)) {
        NN_LOG_ERROR("Failed to create shm channel keeper in Driver " << mName);
        UnInitializeInner();
        return NN_ERROR;
    }
    mChannelKeeper.Set(channelKeeper);

    auto delayReleaseTimer = new (std::nothrow) NetDelayReleaseTimer(DELAY_RELEASE_TIMER_NAME, mIndex);
    if (NN_UNLIKELY(delayReleaseTimer == nullptr)) {
        NN_LOG_ERROR("Failed to create shm channel delayReleaseTimer in Driver " << mName);
        UnInitializeInner();
        return NN_ERROR;
    }
    mDelayReleaseTimer.Set(delayReleaseTimer);

    mInited = true;
    return NN_OK;
}

void NetDriverShmWithOOB::UnInitialize()
{
    std::lock_guard<std::mutex> guard(mInitMutex);
    if (!mInited) {
        return;
    }

    if (mStarted) {
        NN_LOG_WARN("Unable to unInitialize shm driver " << mName << " which is not stopped");
        return;
    }

    UnInitializeInner();
    mInited = false;
}

NResult NetDriverShmWithOOB::ValidateOptions()
{
    if (NN_UNLIKELY(ValidateAndParseOobPortRange(mOptions.oobPortRange) != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(ValidateOptionsOobType() != NN_OK)) {
        return NN_INVALID_PARAM;
    }

    return NN_OK; // do later
}

void NetDriverShmWithOOB::UnInitializeInner()
{
    ClearWorkers();
    DestroyClientLB();

    if (mChannelKeeper != nullptr) {
        mChannelKeeper.Set(nullptr);
    }

    if (mDelayReleaseTimer != nullptr) {
        mDelayReleaseTimer.Set(nullptr);
    }

    if (!mOobServers.empty()) {
        mOobServers.clear();
    }

    if (mClearThread.native_handle()) {
        mClearThread.join();
    }

    mOpCtxMemPool = nullptr;
    mOpCompMemPool = nullptr;
    mSglCompMemPool = nullptr;

    std::lock_guard<std::mutex> guard(mEndPointsMutex);
    if (!mEndPoints.empty()) {
        mEndPoints.clear();
    }
}

NResult NetDriverShmWithOOB::CreateWorkerResource()
{
    NetMemPoolFixedOptions options = {};
    options.superBlkSizeMB = NN_NO1;
    options.minBlkSize = NN_NextPower2(sizeof(ShmOpCompInfo));
    options.tcExpandBlkCnt = NN_NO64;
    mOpCompMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mOpCompMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for op completion info pool in driver " << mName <<
            ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    auto result = mOpCompMemPool->Initialize();
    if (result != NN_OK) {
        NN_LOG_ERROR("Failed to initialize memory pool for op completion info in driver " << mName << ", result " <<
            result);
        return result;
    }

    mOpCtxMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mOpCtxMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for op ctx info pool in driver " << mName <<
            ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    result = mOpCtxMemPool->Initialize();
    if (result != NN_OK) {
        NN_LOG_ERROR("Failed to initialize memory pool for op ctx info in driver " << mName << ", result " << result);
        return result;
    }

    options = {};
    options.superBlkSizeMB = NN_NO1;
    options.minBlkSize = NN_NO512; // the sgl context is 448, not power of 2, set to the closest num 512
    options.tcExpandBlkCnt = NN_NO64;
    mSglCompMemPool = new (std::nothrow) NetMemPoolFixed(mName, options);
    if (mSglCompMemPool.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create memory pool for sgl op context in driver " << mName <<
            ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    result = mSglCompMemPool->Initialize();
    if (result != NN_OK) {
        NN_LOG_ERROR("Failed to initialize memory pool for sgl op context in driver " << mName << ", result " <<
            result);
        return result;
    }

    return NN_OK;
}

NResult NetDriverShmWithOOB::CreateWorkers()
{
    NResult result = NN_OK;

    std::vector<uint16_t> workerGroups;
    std::vector<std::pair<uint32_t, uint32_t>> workerGroupCpus;
    std::vector<int16_t> flatWorkerCpus;
    std::vector<int16_t> workerThreadPriority;

    /* parse */
    if (!(NetFunc::NN_ParseWorkersGroups(mOptions.WorkGroups(), workerGroups)) ||
        !(NetFunc::NN_ParseWorkerGroupsCpus(mOptions.WorkerGroupCpus(), workerGroupCpus)) ||
        !(NetFunc::NN_FinalizeWorkerGroupCpus(workerGroups, workerGroupCpus, true, flatWorkerCpus)) ||
        !(NetFunc::NN_ParseWorkersGroupsThreadPriority(mOptions.WorkerGroupThreadPriority(),
        workerThreadPriority, workerGroups.size()))) {
            NN_LOG_ERROR("[SHM] Failed to parse worker or cpu groups");
        return NN_INVALID_PARAM;
    }

    ShmWorkerOptions options;
    options.mode = mOptions.mode == NET_EVENT_POLLING ? SHM_EVENT_POLLING : SHM_BUSY_POLLING;
    options.eventQueueLength = mOptions.completionQueueDepth;
    options.pollingTimeoutMs = mOptions.eventPollingTimeout;
    options.pollingBatchSize = mOptions.pollingBatchSize;
    options.threadPriority = mOptions.workerThreadPriority;
    if ((mOptions.workerThreadPriority != 0) && (!workerThreadPriority.empty())) {
        NN_LOG_WARN("Driver options 'workerThreadPriority' and 'workerGroupsThreadPriority' set all, preferential use "
            "'workerGroupsThreadPriority'.");
    }

    /* create workers */
    mWorkers.reserve(flatWorkerCpus.size());
    uint32_t groupIndex = 0;
    UBSHcomNetWorkerIndex workerIndex {};
    uint16_t totalWorkerIndex = 0;
    for (auto item : workerGroups) {
        /* The left of mWorkerGroups is the index of each group's first worker in the mWorkers */
        mWorkerGroups.emplace_back(totalWorkerIndex, item);
        for (uint32_t i = 0; i < item; ++i) {
            options.cpuId = flatWorkerCpus.at(totalWorkerIndex++);
            if (!workerThreadPriority.empty()) {
                options.threadPriority = workerThreadPriority[groupIndex];
            }
            workerIndex.Set(i, groupIndex, mIndex);
            auto *worker = new (std::nothrow)
                ShmWorker(mName, workerIndex, options, mOpCompMemPool, mOpCtxMemPool, mSglCompMemPool);
            if (NN_UNLIKELY(worker == nullptr)) {
                NN_LOG_ERROR("Failed to create shm worker in driver " << mName << ", probably out of memory");
                return NN_NEW_OBJECT_FAILED;
            }

            if (NN_UNLIKELY((result = worker->Initialize()) != NN_OK)) {
                delete worker;
                NN_LOG_ERROR("Failed to initialize shm worker in driver " << mName << ", result " << result);
                return result;
            }

            worker->IncreaseRef();
            mWorkers.push_back(worker);
        }
        ++groupIndex;
    }

    return NN_OK;
}

void NetDriverShmWithOOB::ClearWorkers()
{
    mWorkerGroups.clear();
    for (auto worker : mWorkers) {
        worker->DecreaseRef();
    }
    mWorkers.clear();
}

NResult NetDriverShmWithOOB::Start()
{
    std::lock_guard<std::mutex> guard(mInitMutex);
    if (!mInited) {
        NN_LOG_ERROR("Failed to start driver " << mName << " as it is not initialized");
        return NN_ERROR;
    }

    if (NN_UNLIKELY(mChannelKeeper == nullptr)) {
        NN_LOG_ERROR("Failed to start driver " << mName << " as mChannelKeeper is null");
        return NN_ERROR;
    }

    if (NN_UNLIKELY(mDelayReleaseTimer == nullptr)) {
        NN_LOG_ERROR("Failed to start driver " << mName << " as mDelayReleaseTimer is null");
        return NN_ERROR;
    }

    NResult result = NN_OK;
    if (mOptions.dontStartWorkers) {
        // self polling should register channel keeper and start
        mChannelKeeper->RegisterMsgHandler(
            std::bind(&NetDriverShmWithOOB::HandleChanelKeeperMsg, this, std::placeholders::_1, std::placeholders::_2));
        if ((result = mChannelKeeper->Start()) != NN_OK) {
            return result;
        }
        mStarted = true;
    }

    if (mStarted) {
        return NN_OK;
    }
    if (NN_UNLIKELY(result = ValidateHandlesCheck()) != NN_OK) {
        ClearWorkers();
        return result;
    }
    for (auto &item : mWorkers) {
        if (NN_UNLIKELY(item == nullptr)) {
            NN_LOG_ERROR("[SHM] Failed to start worker " << mName << " as it is null");
            ClearWorkers();
            return result;
        }

        item->RegisterNewReqHandler(
            std::bind(&NetDriverShmWithOOB::HandleNewRequest, this, std::placeholders::_1, std::placeholders::_2));
        item->RegisterReqPostedHandler(std::bind(&NetDriverShmWithOOB::HandleReqPosted, this, std::placeholders::_1));
        item->RegisterOneSideHandler(std::bind(&NetDriverShmWithOOB::OneSideDone, this, std::placeholders::_1));
        if (mIdleHandler != nullptr) {
            item->RegisterIdleHandler(mIdleHandler);
        }

        if ((result = item->Start()) != NN_OK) {
            NN_LOG_ERROR("Failed to start worker " << item->Name() << " in driver " << mName << ", result " << result);
            ClearWorkers();
            return result;
        }
    }

    if (mStartOobSvr) {
        if (mNewEndPointHandler == nullptr) {
            NN_LOG_ERROR("SHM failed to do start in Driver " << mName << ", as newEndPointerHandler is null");
            return NN_INVALID_PARAM;
        }
        for (auto &oobServer : mOobServers) {
            oobServer->SetNewConnCB(std::bind(&NetDriverShmWithOOB::HandleNewOobConn, this, std::placeholders::_1));
        }

        /* start oob server */
        if ((result = StartListeners()) != NN_OK) {
            ClearWorkers();
            return result;
        }
    }

    mChannelKeeper->RegisterMsgHandler(
        std::bind(&NetDriverShmWithOOB::HandleChanelKeeperMsg, this, std::placeholders::_1, std::placeholders::_2));
    if ((result = mChannelKeeper->Start()) != NN_OK) {
        ClearWorkers();
        return result;
    }

    if ((result = mDelayReleaseTimer->Start()) != NN_OK) {
        ClearWorkers();
        mChannelKeeper->Stop();
        return result;
    }

    mStarted = true;
    return NN_OK;
}

void NetDriverShmWithOOB::ClearShmLeftFile()
{
    mClearThreadStarted.store(true);
    NN_LOG_INFO("NetDriverShmWithOOB clearThread " << mName << "  working thread started");
    DIR *dir = nullptr;
    struct dirent *ent = nullptr;
    // do later consider open dir/file and delete dir/file secure problems
    if (NN_UNLIKELY((dir = opendir(SHM_FILE_DIR_PATH)) == nullptr)) {
        NN_LOG_TRACE_INFO("Failed to open directory SHM_FILE_DIR_PATH");
        return;
    }

    while ((ent = readdir(dir)) != nullptr) {
        if (strncmp(ent->d_name, SHM_FILE_PREFIX, strlen(SHM_FILE_PREFIX)) != 0) {
            continue;
        }

        auto tmpFd = shm_open(ent->d_name, O_CREAT | O_RDWR, NN_NO400);
        if (NN_UNLIKELY(tmpFd < 0)) {
            continue;
        }
        if (flock(tmpFd, LOCK_EX | LOCK_NB) == 0) {
            if (NN_UNLIKELY(shm_unlink(ent->d_name) != 0)) {
                char buf[NET_STR_ERROR_BUF_SIZE] = {0};
                NN_LOG_TRACE_INFO("Failed to remove file:" << ent->d_name << " reason "
                        << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
                (void)buf;
                NetFunc::NN_SafeCloseFd(tmpFd);
                continue;
            }
            NN_LOG_TRACE_INFO("Success to delete shm file:" << ent->d_name <<
                " which is not used now, may be left last time");
        }
        NetFunc::NN_SafeCloseFd(tmpFd);
    }
    closedir(dir);
    NN_LOG_INFO("NetDriverShmWithOOB clearThread " << mName << "  working thread exit");
}

void NetDriverShmWithOOB::Stop()
{
    std::lock_guard<std::mutex> locker(mInitMutex);
    if (!mStarted) {
        return;
    }

    StopInner();

    mStarted = false;
}

void NetDriverShmWithOOB::StopInner()
{
    for (auto worker : mWorkers) {
        worker->Stop();
    }

    if (NN_LIKELY(mChannelKeeper != nullptr)) {
        mChannelKeeper->Stop();
    }

    if (NN_LIKELY(mDelayReleaseTimer != nullptr)) {
        mDelayReleaseTimer->Stop();
    }

    StopListeners(true);
}

NResult NetDriverShmWithOOB::HandleNewRequest(ShmOpContextInfo &ctx, uint32_t immData)
{
    NN_ASSERT_LOG_RETURN(ctx.channel != nullptr, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx.channel->UpContext() != 0, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx.dataAddress != 0, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx.dataSize <= NET_SGE_MAX_SIZE, NN_ERROR)
    NResult result = NN_OK;

    if (NN_UNLIKELY(ctx.channel->State().Compare(CH_BROKEN))) {
        NN_LOG_WARN("Got invalid ctx in new request handler, as channel " << ctx.channel->Id() << " is broken drop it");
        return result;
    }

    static thread_local UBSHcomNetRequestContext netCtx {};
    static thread_local UBSHcomNetMessage netMsg {};
    if (ctx.opType == ShmOpContextInfo::ShmOpType::SH_RECEIVE && immData == 0) {
        /* get header */
        netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx.channel->UpContext()));
        auto asyncEp = netCtx.mEp.ToChild<NetAsyncEndpointShm>();
        if (NN_UNLIKELY(asyncEp == nullptr)) {
            NN_LOG_ERROR("dynamic cast failed");
            ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
            return NN_PARAM_INVALID;
        }
        auto header = reinterpret_cast<UBSHcomNetTransHeader *>(ctx.dataAddress);

        result = NetFunc::ValidateHeaderWithDataSize(*header, ctx.dataSize);
        if (NN_UNLIKELY(result != NN_OK)) {
            NN_LOG_ERROR("Failed to validate received header param, ep " << asyncEp->Id());
            ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
            return result;
        }

        netCtx.mHeader = *header;
        netCtx.mOpType = UBSHcomNetRequestContext::NN_RECEIVED;
        netCtx.mMessage = &netMsg;

        size_t realDataSize = 0;
        if (asyncEp->mIsNeedEncrypt) {
            const void *cipherData = reinterpret_cast<const void *>(ctx.dataAddress + sizeof(UBSHcomNetTransHeader));
            auto aesLen = header->dataLength;
            realDataSize = asyncEp->mAes.GetRawLen(aesLen);
            uint32_t decryptLen = 0;
            bool messageReady = netMsg.AllocateIfNeed(realDataSize);
            if (NN_UNLIKELY(!messageReady)) {
                NN_LOG_ERROR("Failed to allocate memory for response size " << realDataSize <<
                    ", probably out of memory");
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                return NN_MALLOC_FAILED;
            }

            if (!asyncEp->mAes.Decrypt(asyncEp->mSecrets, cipherData, aesLen, netMsg.mBuf, decryptLen)) {
                NN_LOG_ERROR("Failed to decrypt data");
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                return NN_DECRYPT_FAILED;
            }
            VALIDATE_DECRYPT_LENGTH(decryptLen, realDataSize, ctx)
        } else {
            realDataSize = ctx.dataSize - sizeof(UBSHcomNetTransHeader);
            bool messageReady = netMsg.AllocateIfNeed(realDataSize);
            if (NN_UNLIKELY(!messageReady)) {
                NN_LOG_ERROR("Failed to allocate net msg buffer failed");
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                return NN_MALLOC_FAILED;
            }
            if (NN_UNLIKELY(memcpy_s(netMsg.mBuf, netMsg.GetBufLen(), reinterpret_cast<void *>(ctx.dataAddress +
                sizeof(UBSHcomNetTransHeader)), realDataSize) != NN_OK)) {
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                NN_LOG_ERROR("Failed to copy ctx to netMsg");
                return NN_INVALID_PARAM;
            }
        }

        netMsg.mDataLen = realDataSize;
        netCtx.mHeader.dataLength = realDataSize;

        /* call upper handler */
        result = mReceivedRequestHandler(netCtx);

        /* mark buck free */
        ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
        netCtx.mEp.Set(nullptr);

        return result;
    } else if (ctx.opType == ShmOpContextInfo::ShmOpType::SH_RECEIVE && immData != 0) {
        netCtx.mEp.Set(reinterpret_cast<NetAsyncEndpointShm *>(ctx.channel->UpContext()));
        netCtx.mOpType = UBSHcomNetRequestContext::NN_RECEIVED_RAW;
        netCtx.mMessage = &netMsg;

        auto asyncEp = netCtx.mEp.ToChild<NetAsyncEndpointShm>();
        if (NN_UNLIKELY(asyncEp == nullptr)) {
            NN_LOG_ERROR("dynamic cast failed");
            ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
            return NN_PARAM_INVALID;
        }
        if (asyncEp->mIsNeedEncrypt) {
            const void *cipherData = reinterpret_cast<const void *>(ctx.dataAddress);
            auto aesLen = ctx.dataSize;
            size_t decryptRawLen = asyncEp->mAes.GetRawLen(aesLen);
            uint32_t decryptLen = 0;
            bool messageReady = netMsg.AllocateIfNeed(decryptRawLen);
            if (NN_UNLIKELY(!messageReady)) {
                NN_LOG_ERROR("Failed to allocate net msg buffer failed");
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                return NN_MALLOC_FAILED;
            }

            if (!asyncEp->mAes.Decrypt(asyncEp->mSecrets, cipherData, aesLen, netMsg.mBuf, decryptLen)) {
                NN_LOG_ERROR("Failed to decrypt data");
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                return NN_DECRYPT_FAILED;
            }
            NN_ASSERT_LOG_RETURN(decryptLen == decryptRawLen, NN_DECRYPT_FAILED)
            netMsg.mDataLen = decryptRawLen;
        } else {
            netMsg.mDataLen = ctx.dataSize;
            bool messageReady = netMsg.AllocateIfNeed(ctx.dataSize);
            if (NN_UNLIKELY(!messageReady)) {
                NN_LOG_ERROR("Failed to allocate net msg buffer failed");
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                return NN_MALLOC_FAILED;
            }
            if (NN_UNLIKELY(memcpy_s(netMsg.mBuf, netMsg.GetBufLen(), reinterpret_cast<void *>(ctx.dataAddress),
                ctx.dataSize) != NN_OK)) {
                ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
                NN_LOG_ERROR("Failed to copy dataAddress to netMsg");
                return NN_INVALID_PARAM;
            }
        }

        netCtx.mHeader.Invalid();
        netCtx.mHeader.dataLength = netMsg.mDataLen;
        netCtx.mHeader.seqNo = immData;
        /* call upper handler */
        result = mReceivedRequestHandler(netCtx);

        /* mark buck free */
        ctx.channel->DCMarkPeerBuckFree(ctx.dataAddress);
        netCtx.mEp.Set(nullptr);

        return result;
    } else {
        NN_LOG_WARN("Un-reachable path");
        return NN_OK;
    }
}

NResult NetDriverShmWithOOB::HandleReqPosted(ShmOpCompInfo &ctx)
{
    NN_ASSERT_LOG_RETURN(ctx.channel != nullptr, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx.channel->UpContext() != 0, NN_ERROR)
    NN_ASSERT_LOG_RETURN(ctx.channel->UpContext1() != 0, NN_ERROR)
    NResult result = NN_OK;

    static thread_local UBSHcomNetRequestContext netCtx {};

    netCtx.mResult = NN_OK;
    netCtx.mEp.Set(reinterpret_cast<NetAsyncEndpointShm *>(ctx.channel->UpContext()));
    netCtx.mOriginalReq = ctx.request;
    netCtx.mMessage = nullptr;

    auto shmWorker = reinterpret_cast<ShmWorker *>(ctx.channel->UpContext1());
    auto sgeCtx = reinterpret_cast<ShmSglOpCompInfo *>(ctx.upCtx);
    auto sglCtx = sgeCtx->ctx;

    switch (ctx.opType) {
        case ShmOpContextInfo::SH_SEND:
            netCtx.mHeader = ctx.header;
            netCtx.mOpType = UBSHcomNetRequestContext::NN_SENT;
            shmWorker->ReturnOpCompInfo(&ctx);
            break;
        case ShmOpContextInfo::SH_SEND_RAW:
            netCtx.mHeader.Invalid();
            netCtx.mOpType = UBSHcomNetRequestContext::NN_SENT_RAW;
            shmWorker->ReturnOpCompInfo(&ctx);
            break;
        case ShmOpContextInfo::SH_SEND_RAW_SGL:
            netCtx.mHeader.Invalid();
            netCtx.mOpType = UBSHcomNetRequestContext::NN_SENT_RAW_SGL;
            if (sglCtx->iovCount <= NET_SGE_MAX_IOV) {
                if (NN_UNLIKELY(memcpy_s(netCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, sglCtx->iov,
                    sizeof(UBSHcomNetTransSgeIov) * sglCtx->iovCount) != NN_OK)) {
                    NN_LOG_ERROR("Failed to copy req to sglCtx");
                    result = NN_INVALID_PARAM;
                }
            }
            netCtx.mOriginalSglReq.iov = netCtx.iov;
            netCtx.mOriginalSglReq.iovCount = sglCtx->iovCount;
            netCtx.mOriginalSglReq.upCtxSize = sglCtx->upCtxSize;
            if (netCtx.mOriginalSglReq.upCtxSize > 0 &&
                netCtx.mOriginalSglReq.upCtxSize <= sizeof(UBSHcomNetTransSglRequest::upCtxData)) {
                if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalSglReq.upCtxData, NN_NO16, sglCtx->upCtx, sglCtx->upCtxSize) !=
                    NN_OK)) {
                    NN_LOG_ERROR("Failed to copy request to sglCtx");
                    result = NN_INVALID_PARAM;
                }
            }
            shmWorker->ReturnOpCompInfo(&ctx);
            shmWorker->ReturnSglContextInfo(sglCtx);
            break;
        default:
            NN_LOG_WARN("Un-reachable path");
            break;
    }

    /* call upper handler */
    if (result == NN_OK && NN_UNLIKELY((result = mRequestPostedHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call requestPostedHandler in Driver " << mName << " return non-zero for type " << ctx.opType <<
            " done");
    }
    netCtx.mEp.Set(nullptr);
    return result;
}

NResult NetDriverShmWithOOB::RWOneSideDone(ShmOpContextInfo *ctxIn, UBSHcomNetRequestContext &netCtx, ShmWorker *worker)
{
    NResult result = NN_OK;
    ShmOpContextInfo ctx = *ctxIn;
    // set context
    netCtx.mResult = ShmOpContextInfo::GetNResult(ctx.errType);
    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx.channel->UpContext()));
    netCtx.mOpType =
        ctx.opType == ShmOpContextInfo::SH_WRITE ? UBSHcomNetRequestContext::NN_WRITTEN :
        UBSHcomNetRequestContext::NN_READ;
    netCtx.mHeader.Invalid();
    netCtx.mMessage = nullptr;
    netCtx.mOriginalReq.lAddress = ctx.mrMemAddr;
    netCtx.mOriginalReq.lKey = ctx.lKey;
    netCtx.mOriginalReq.size = ctx.dataSize;
    netCtx.mOriginalReq.upCtxSize = ctx.upCtxSize;

    if (ctx.upCtxSize > 0 && ctx.upCtxSize <= sizeof(UBSHcomNetTransRequest::upCtxData)) {
        if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalReq.upCtxData, NN_NO16, ctx.upCtx, ctx.upCtxSize) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            result = NN_INVALID_PARAM;
        }
    }

    // called to callback
    if (result == NN_OK && NN_UNLIKELY((result = mOneSideDoneHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call oneSideDoneHandler in Driver " << mName << " return non-zero for type " << ctx.opType <<
            " done");
    }
    worker->ReturnOpContextInfo(ctxIn);
    netCtx.mEp.Set(nullptr);

    return result;
}

NResult NetDriverShmWithOOB::OneSideDone(ShmOpContextInfo *ctxIn)
{
    NN_ASSERT_LOG_RETURN(ctxIn != nullptr, NN_ERROR)
    ShmOpContextInfo ctx = *ctxIn;
    if (NN_UNLIKELY(ctx.channel == nullptr || ctx.channel->UpContext1() == 0 || ctx.channel->UpContext() == 0)) {
        NN_LOG_ERROR("Ctx or channel is null of OneSideDone in Driver " << mName);
        return NN_ERROR;
    }

    int result = 0;
    auto worker = reinterpret_cast<ShmWorker *>(ctx.channel->UpContext1());
    static thread_local UBSHcomNetRequestContext netCtx {};

    if (ctx.opType == ShmOpContextInfo::SH_WRITE || ctx.opType == ShmOpContextInfo::SH_READ) {
        return RWOneSideDone(ctxIn, netCtx, worker);
    } else if (ctx.opType == ShmOpContextInfo::SH_SGL_WRITE || ctx.opType == ShmOpContextInfo::SH_SGL_READ) {
        auto upCtx = reinterpret_cast<ShmSglOpCompInfo *>(ctx.upCtx);
        auto sglCtx = upCtx->ctx;

        netCtx.mResult = ShmOpContextInfo::GetNResult(ctx.errType);
        netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx.channel->UpContext()));
        netCtx.mOpType = ctx.opType == ShmOpContextInfo::SH_SGL_WRITE ? UBSHcomNetRequestContext::NN_SGL_WRITTEN :
                                                                        UBSHcomNetRequestContext::NN_SGL_READ;
        netCtx.mHeader.Invalid();
        netCtx.mMessage = nullptr;
        if (sglCtx->iovCount <= NET_SGE_MAX_IOV) {
            if (NN_UNLIKELY(memcpy_s(netCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, sglCtx->iov,
                sizeof(UBSHcomNetTransSgeIov) * sglCtx->iovCount) != NN_OK)) {
                NN_LOG_ERROR("Failed to copy req to sglCtx");
                result = NN_INVALID_PARAM;
            }
        }
        netCtx.mOriginalSglReq.iov = netCtx.iov;
        netCtx.mOriginalSglReq.iovCount = sglCtx->iovCount;
        netCtx.mOriginalSglReq.upCtxSize = sglCtx->upCtxSize;
        if (netCtx.mOriginalSglReq.upCtxSize > 0 &&
            netCtx.mOriginalSglReq.upCtxSize <= sizeof(UBSHcomNetTransSglRequest::upCtxData)) {
            if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalSglReq.upCtxData, NN_NO16, sglCtx->upCtx, sglCtx->upCtxSize) !=
                NN_OK)) {
                NN_LOG_ERROR("Failed to copy req to sglCtx");
                result = NN_INVALID_PARAM;
            }
        }

        // called to callback
        if (result == NN_OK && NN_UNLIKELY((result = mOneSideDoneHandler(netCtx)) != NN_OK)) {
            NN_LOG_ERROR("Call oneSideDoneHandler in Driver " << mName << " return non-zero for type " << ctx.opType <<
                " done");
        }
        worker->ReturnOpContextInfo(ctxIn);
        worker->ReturnSglContextInfo(sglCtx);
        netCtx.mEp.Set(nullptr);
    } else {
        NN_LOG_WARN("Unreachable path");
    }

    return result;
}

inline void NetDriverShmWithOOB::HandleChanelKeeperMsg(const ShmChKeeperMsgHeader &header,
    const ShmChannelPtr &channelPtr)
{
    if (NN_UNLIKELY(channelPtr == nullptr)) {
        return;
    }
    if (header.msgType == ShmChKeeperMsgType::RESET_BY_PEER) {
        channelPtr->Close();
        if (NN_UNLIKELY(!channelPtr->State().CAS(CH_NEW, CH_BROKEN))) {
            NN_LOG_ERROR("Channel id " << channelPtr->Id() << " failed set state " << CH_BROKEN);
        }
        ProcessEpError(channelPtr);
    } else if (header.msgType == ShmChKeeperMsgType::GET_MR_FD) {
        HandleKeeperMsgGetMrFd(header, channelPtr);
    }
}

void NetDriverShmWithOOB::HandleKeeperMsgGetMrFd(const ShmChKeeperMsgHeader &header, const ShmChannelPtr &channelPtr)
{
    uint32_t lKey = -1;
    if (NN_UNLIKELY(header.dataSize != sizeof(uint32_t))) {
        NN_LOG_ERROR("Failed to receive lkey from peer, as dataSize in header is invalid");
        return;
    }
    ssize_t result = ::recv(channelPtr->UdsFD(), &lKey, header.dataSize, 0);
    if (NN_UNLIKELY(result <= 0)) {
        char errBuf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to receive data from peer as errno:" << errno << " error:" <<
            NetFunc::NN_GetStrError(errno, errBuf, NET_STR_ERROR_BUF_SIZE));
        return;
    }

    ShmHandlePtr shmHandle = ShmMRHandleMap::GetInstance().GetFromLocalMap(lKey);
    if (shmHandle.Get() == nullptr) {
        NN_LOG_ERROR("Get shmHandle from local map failed");
        return;
    }
    int mrFd = shmHandle->Fd();
    if (NN_UNLIKELY(mrFd <= 0)) {
        NN_LOG_ERROR("Get Fd from local map failed");
        return;
    }

    std::lock_guard<std::mutex> guard(channelPtr->mFdMutex);
    ShmChKeeperMsgHeader exchangeHeader{};
    exchangeHeader.msgType = ShmChKeeperMsgType::SEND_MR_FD;
    exchangeHeader.dataSize = sizeof(int);
    if (NN_UNLIKELY(::send(channelPtr->UdsFD(), &exchangeHeader, sizeof(ShmChKeeperMsgHeader), MSG_NOSIGNAL) <= 0)) {
        char errBuf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to send header info of exchanging user fd to peer, errno:" << errno << " error:" <<
            NetFunc::NN_GetStrError(errno, errBuf, NET_STR_ERROR_BUF_SIZE));
        return;
    }

    int fds[NN_NO4] = {0};
    fds[0] = mrFd;
    if (NN_UNLIKELY(ShmHandleFds::SendMsgFds(channelPtr->UdsFD(), fds, NN_NO4) != NN_OK)) {
        NN_LOG_ERROR("Failed to send mr to peer");
        return;
    }
}

void NetDriverShmWithOOB::ProcessEpError(const ShmChannelPtr &channelPtr)
{
    UBSHcomNetEndpointPtr epPtr = reinterpret_cast<NetAsyncEndpointShm *>(channelPtr->UpContext());
    if (NN_UNLIKELY(epPtr == nullptr)) {
        return;
    }

    bool process = false;
    if (NN_UNLIKELY(!epPtr->EPBrokenProcessed().compare_exchange_strong(process, true))) {
        NN_LOG_WARN("Ep id " << epPtr->Id() << " broken handled by other thread");
        return;
    }

    if (epPtr->State().Compare(NEP_ESTABLISHED)) {
        epPtr->State().Set(NEP_BROKEN);
    }

    // two side remaining
    ShmOpCompInfo *remainingCompCtx = nullptr;
    ShmOpCompInfo *nextCompCtx = nullptr;
    channelPtr->GetCompPosted(remainingCompCtx);
    while (remainingCompCtx != nullptr) {
        nextCompCtx = remainingCompCtx->next;
        remainingCompCtx->errType = ShmOpContextInfo::ShmErrorType::SH_RESET_BY_PEER;
        (void)HandleReqPosted(*remainingCompCtx);
        remainingCompCtx = nextCompCtx;
    }

    // one side remaining
    ShmOpContextInfo *remainingOpCtx = nullptr;
    ShmOpContextInfo *nextOpCtx = nullptr;
    channelPtr->GetCtxPosted(remainingOpCtx);
    while (remainingOpCtx != nullptr) {
        nextOpCtx = remainingOpCtx->next;
        remainingOpCtx->errType = ShmOpContextInfo::ShmErrorType::SH_RESET_BY_PEER;
        (void)OneSideDone(remainingOpCtx);
        remainingOpCtx = nextOpCtx;
    }

    NN_LOG_WARN("Handle Ep state " << UBSHcomNEPStateToString(epPtr->State().Get()) << ", Ep id " << epPtr->Id() <<
        " , try call Ep broken handle");

    OOBSecureProcess::SecProcessDelEpNum(epPtr->UdsName(), epPtr->PeerIpAndPort(),
        mOobServers);

    if (mEndPointBrokenHandler != nullptr) {
        // self polling mode not register ep handler
        mEndPointBrokenHandler(epPtr);
    }
    DestroyEndpoint(epPtr);
}

NResult NetDriverShmWithOOB::ConnectSyncEp(const std::string &oobIp, uint16_t oobPort, const std::string &payload,
    UBSHcomNetEndpointPtr &outEp, uint8_t serverGrpNo, uint64_t ctx)
{
    NResult result = NN_OK;
    auto eventQueueLength = mOptions.completionQueueDepth;
    ShmPollingMode pollMode = (mOptions.mode == NET_EVENT_POLLING) ? SHM_EVENT_POLLING : SHM_BUSY_POLLING;

    ShmSyncEndpointPtr shmEp;
    if ((result = ShmSyncEndpoint::Create(mName, eventQueueLength, pollMode, shmEp)) != 0) {
        NN_LOG_ERROR("Failed to create sync ep for new connection in Driver " << mName << " , result " << result);
        return result;
    }

    OOBTCPClientPtr clt;
    if (mEnableTls) {
        auto oobSSLClt = new (std::nothrow) OOBSSLClient(NET_OOB_UDS, oobIp, oobPort,
            mTlsPrivateKeyCB, mTlsCertCB, mTlsCaCallback);
        NN_ASSERT_LOG_RETURN(oobSSLClt != nullptr, NN_NEW_OBJECT_FAILED)
        oobSSLClt->SetTlsOptions(mOptions);
        oobSSLClt->SetPSKCallback(mPskFindSessionCb, mPskUseSessionCb);
        clt = oobSSLClt;
    } else {
        clt = new (std::nothrow) OOBTCPClient(NET_OOB_UDS, oobIp, oobPort);
        NN_ASSERT_LOG_RETURN(clt.Get() != nullptr, NN_NEW_OBJECT_FAILED)
    }

    /* try to connect to oob server */
    OOBTCPConnection *conn = nullptr;
    if ((result = clt->Connect(conn)) != 0) {
        NN_LOG_ERROR("Shm Failed to connect server via oob, result" << " " << result);
        return result;
    }

    const auto &peerIpPort = conn->GetIpAndPort();
    NetLocalAutoDecreasePtr<OOBTCPConnection> autoDecPtr(conn);
    conn->SetIpAndPort(oobIp, oobPort);

    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBClient(mSecInfoProvider, mSecInfoValidator, conn, mName, ctx,
        mOptions.secType))) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    /* send connection header */
    ConnectHeader header {};
    SetConnHeader(header, mOptions.magic, mOptions.version, serverGrpNo, Protocol(), mMajorVersion,
                  mMinorVersion, mOptions.tlsVersion);
    if (NN_UNLIKELY((result = conn->Send(&header, sizeof(ConnectHeader))) != NN_OK)) {
        NN_LOG_ERROR("Failed to send conn header to oob server " << oobIp << ":" << oobPort << " in Driver " << mName);
        return NN_ERROR;
    }

    /* receive connect response and peer ep id */
    ConnRespWithUId rspWithUid {};
    void *tmpBuf = &rspWithUid;
    if (NN_UNLIKELY((result = conn->Receive(tmpBuf, sizeof(ConnRespWithUId))) != NN_OK)) {
        return result;
    }

    /* connect response */
    auto resp = rspWithUid.connResp;
    if (NN_UNLIKELY(resp != OK)) {
        NN_LOG_ERROR("Shm Failed to pass server validation in driver " << mName << ", result " << resp);
        return NN_CONNECT_REFUSED;
    }

    /* peer ep id */
    auto newId = rspWithUid.epId;
    NN_LOG_TRACE_INFO("new ep id will be set as " << newId << " in driver " << mName);

    /* create shm and init channel */
    ShmChannelPtr ch;
    result = ShmChannel::CreateAndInit(mName, newId, mOptions.mrSendReceiveSegSize, mOptions.qpSendQueueSize, ch);
    if (NN_UNLIKELY(result != NN_OK)) {
        return result;
    }

    /* fill exchange info */
    ShmConnExchangeInfo exInfo {};
    NN_ASSERT_LOG_RETURN(shmEp->FillQueueExchangeInfo(exInfo), NN_ERROR)
    NN_ASSERT_LOG_RETURN(ch->FillExchangeInfo(exInfo), NN_ERROR)
    exInfo.payLoadSize = payload.length();

    /* send exchange info */
    if (NN_UNLIKELY((result = SendExchangeInfo(*conn, exInfo)) != NN_OK)) {
        NN_LOG_ERROR("Shm Failed to send channel exchange info to oob server " << oobIp << ":" << oobPort <<
            " in driver " << mName);
        return NN_ERROR;
    }

    /* send payload */
    if (NN_UNLIKELY((result = conn->Send(const_cast<char *>(payload.c_str()), payload.length())) != NN_OK)) {
        NN_LOG_ERROR("Shm Failed to send payload to peer at " << peerIpPort << " in driver " << mName);
        return result;
    }

    /* receive exchange info */
    NN_LOG_TRACE_INFO("Shm Try to receive exchange info from peer, " << sizeof(ShmConnExchangeInfo));
    if (NN_UNLIKELY((result = ReceiveExchangeInfo(*conn, exInfo)) != NN_OK)) {
        return result;
    }

    /* change to ready */
    if ((result = ch->ChangeToReady(exInfo)) != NN_OK) {
        return result;
    }

    /* receive ready signal */
    int8_t ready = -1;
    tmpBuf = static_cast<void *>(&ready);
    result = conn->Receive(tmpBuf, sizeof(int8_t));
    if (result != NN_OK || ready != 1) {
        NN_LOG_ERROR("Failed to receive ready from " << peerIpPort << " in Driver " << mName << ", Result " << result);
        return result;
    }

    /* create ep */
    const UBSHcomNetWorkerIndex netWorkerIndex {};
    UBSHcomNetEndpointPtr newEp = new (std::nothrow)
        NetSyncEndpointShm(ch->Id(), ch.Get(), this, netWorkerIndex, shmEp.Get(), ShmMRHandleMap::GetInstance());
    if (NN_UNLIKELY(newEp.Get() == nullptr)) {
        NN_LOG_ERROR("Failed to new async shm ep in driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    if (mEnableTls) {
        auto chiEp = newEp.ToChild<NetSyncEndpointShm>();
        auto tmp = dynamic_cast<OOBSSLConnection *>(conn);
        if (NN_UNLIKELY(chiEp == nullptr || tmp == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        chiEp->EnableEncrypt(mOptions);
        chiEp->SetSecrets(tmp->Secret());
    }

    /* 1 transfer fd, 2 set upCtx, 3 set payload, 4 add ep into map, 5 set state */
    ch->UdsFD(conn->TransferFd());
    ch->UpContext(reinterpret_cast<uint64_t>(newEp.Get()));
    newEp->StoreConnInfo(NetFunc::GetIpByFd(ch->UdsFD()), conn->ListenPort(), header.version, payload);
    AddEp(newEp);
    newEp->State().Set(NEP_ESTABLISHED);

    outEp.Set(newEp.Get());
    if (mChannelKeeper == nullptr) {
        NN_LOG_INFO("New connection failed as mChannelKeeper is null");
        return NN_ERROR;
    }
    if ((result = mChannelKeeper->AddShmChannel(ch)) != NN_OK) {
        NN_LOG_ERROR("Adding Shm Channel failed, result: " << result);
        return result;
    }

    NN_LOG_INFO("New connection to " << oobIp << ":" << oobPort << " established, sync ep id " << outEp->Id());
    return result;
}

#define VALIDATE_DRIVER_INIT()                                     \
    if (NN_UNLIKELY(!mInited.load())) {                            \
        NN_LOG_ERROR("Driver " << mName << " is not initialized"); \
        return NN_NOT_INITIALIZED;                                 \
    }

#define VALIDATE_PAYLOAD(payloadSize)                                                                 \
    if ((payloadSize) > NN_NO1024) {                                                                  \
        NN_LOG_ERROR("Failed to connect server via payload size " << (payloadSize) << " over limit"); \
        return NN_INVALID_PARAM;                                                                      \
    }

#define VALIDATE_OOBTYPE()                                   \
    if (mOptions.oobType == NET_OOB_TCP) {                   \
        NN_LOG_WARN("The current oobType is not supported"); \
        return NN_INVALID_PARAM;                             \
    }

NResult NetDriverShmWithOOB::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (NN_UNLIKELY(size == 0 || size > NN_NO107374182400)) {
        NN_LOG_ERROR("Failed to create mem region as size is 0 or greater than 100 GB");
        return NN_INVALID_PARAM;
    }

    if (!mInited) {
        NN_LOG_ERROR("Failed to create Memory region in NetDriverShm " << mName << ", as not initialized");
        return NN_EP_NOT_INITIALIZED;
    }

    ShmMemoryRegion *tmp = nullptr;
    auto result = ShmMemoryRegion::Create(mName, size, tmp);
    if (NN_UNLIKELY(result != NN_OK)) {
        NN_LOG_ERROR("Failed to create Memory region in NetDriverShm " << mName << ", probably out of memory");
        return result;
    }

    if ((result = tmp->Initialize()) != NN_OK) {
        delete tmp;
        return result;
    }

    if ((result = mMrChecker.Register(tmp->GetLKey(), tmp->GetAddress(), size)) != NN_OK) {
        NN_LOG_ERROR("Failed to add memory region to range checker in driver" << mName << " for duplicate keys");
        delete tmp;
        return result;
    }

    // Prevent integer truncation, safely converts uint64_t to uint32_t
    if (NN_UNLIKELY(tmp->mLKey > UINT32_MAX)) {
        NN_LOG_ERROR("Failed to create Memory region in NetDriverShm as lKey is larger than uint32max, lKey" <<
            tmp->mLKey);
        delete tmp;
        return NN_INVALID_PARAM;
    }

    ShmMRHandleMap::GetInstance().AddToLocalMap(static_cast<uint32_t>(tmp->mLKey), tmp->GetMrHandle());

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));

    return NN_OK;
}
NResult NetDriverShmWithOOB::CreateMemoryRegion(uintptr_t address, uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    NN_LOG_WARN("Invalid operation, create memoryRegion is not supported by NetDriverShmWithOOB");
    return NN_INVALID_OPERATION;
}

NResult NetDriverShmWithOOB::CreateMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr, unsigned long memid)
{
    NN_LOG_ERROR("operation is not supported in shm");
    return NN_ERROR;
}

NResult NetDriverShmWithOOB::Connect(const std::string &payload, UBSHcomNetEndpointPtr &ep, uint32_t flags,
    uint8_t serverGrpNo, uint8_t clientGrpNo)
{
    if (mOptions.oobType == NET_OOB_TCP) {
        NN_LOG_WARN("The current oobType is not supported");
        return NN_INVALID_PARAM;
    } else if (mOptions.oobType == NET_OOB_UDS) {
        return Connect(mUdsName, 0, payload, ep, flags, serverGrpNo, clientGrpNo, 0);
    }
    return NN_ERROR;
}

NResult NetDriverShmWithOOB::SendExchangeInfo(OOBTCPConnection &conn, ShmConnExchangeInfo &exInfo)
{
    // create iov for general exchange message
    struct iovec iov = {
        .iov_base = &exInfo,
        .iov_len = sizeof(ShmConnExchangeInfo)
    };
    // fds, event queue fd and share mem fd
    int fds[NN_NO2];
    fds[0] = exInfo.queueFd;
    fds[1] = exInfo.channelFd;
    char buf[CMSG_SPACE(sizeof(fds))];
    bzero(buf, sizeof(buf));

    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = NN_NO1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (NN_UNLIKELY(cmsg == nullptr)) {
        NN_LOG_ERROR("CMSG_FIRSTHDR get empty msg");
        return NN_ERROR;
    }
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fds));

    if (NN_UNLIKELY(memcpy_s((char *)CMSG_DATA(cmsg), sizeof(fds), fds, sizeof(fds)) != NN_OK)) {
        NN_LOG_ERROR("Failed to copy fds to cmsg");
        return NN_INVALID_PARAM;
    }

    return conn.SendMsg(msg, sizeof(ShmConnExchangeInfo));
}

NResult NetDriverShmWithOOB::ReceiveExchangeInfo(OOBTCPConnection &conn, ShmConnExchangeInfo &exInfo)
{
    // create iov for general exchange message
    struct iovec iov = {
        .iov_base = &exInfo,
        .iov_len = sizeof(ShmConnExchangeInfo)
    };

    // fds, event queue fd and share mem fd
    int fds[NN_NO2];
    fds[0] = -1;
    fds[1] = -1;
    char buf[CMSG_SPACE(sizeof(fds))];
    bzero(buf, sizeof(buf));

    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = NN_NO1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    auto result = conn.ReceiveMsg(msg, sizeof(ShmConnExchangeInfo));
    if (result != NN_OK) {
        return result;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (NN_UNLIKELY(cmsg == nullptr)) {
        NN_LOG_ERROR("CMSG_FIRSTHDR get empty msg");
        return NN_ERROR;
    }
    if (NN_UNLIKELY(memcpy_s(fds, sizeof(fds), (char *)CMSG_DATA(cmsg), sizeof(fds)) != NN_OK)) {
        NN_LOG_ERROR("Failed to copy cmsg to fds");
        return NN_INVALID_PARAM;
    }
    exInfo.queueFd = fds[0];
    exInfo.channelFd = fds[1];

    return NN_OK;
}

NResult NetDriverShmWithOOB::HandleNewOobConn(OOBTCPConnection &conn)
{
    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBServer(mSecInfoProvider, mSecInfoValidator, conn, mName,
        mOptions.secType)) != NN_OK) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    if (NN_UNLIKELY(OOBSecureProcess::SecProcessCompareEpNum(conn.GetUdsName(), conn.GetIpAndPort(),
        mOobServers)) != NN_OK) {
        NN_LOG_ERROR("Shm connection num exceeds maximum");
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    NResult result = NN_OK;
    const auto &peerIpPort = conn.GetIpAndPort();
    /* receive header and verify */
    ConnectHeader header {};
    void *tmpBuf = &header;
    if (NN_UNLIKELY((result = conn.Receive(tmpBuf, sizeof(ConnectHeader))) != 0)) {
        NN_LOG_ERROR("OOB from " << peerIpPort << " dropped as read data or invalid data in driver " << mName <<
            ", result " << result);
        return result;
    }

    ConnRespWithUId respWithUId{ OK, 0 };
    result = OOBSecureProcess::SecCheckConnectionHeader(header, mOptions, mEnableTls, Protocol(), mMajorVersion,
        mMinorVersion, respWithUId);
    if (result != NN_OK) {
        conn.Send(&respWithUId, sizeof(ConnRespWithUId));
        return NN_ERROR;
    }

    uint64_t newId = NetUuid::GenerateUuid();
    NN_LOG_TRACE_INFO("new ep id will be set as " << newId << " in driver " << mName);

    respWithUId.connResp = OK;
    respWithUId.epId = newId;
    if (NN_UNLIKELY((result = conn.Send(&respWithUId, sizeof(ConnRespWithUId))) != NN_OK)) {
        NN_LOG_ERROR("Failed to send resp to " << peerIpPort << " in driver " << mName << ", result " << result);
        return result;
    }

    ShmConnExchangeInfo peerExInfo {}; /* fill exchange info */
    if (NN_UNLIKELY((result = ReceiveExchangeInfo(conn, peerExInfo)) != NN_OK)) {
        NN_LOG_ERROR("Failed to read ex from " << peerIpPort << " in driver " << mName << ", result " << result);
        return result;
    }

    if (NN_UNLIKELY(peerExInfo.payLoadSize > NN_NO1024)) {
        NN_LOG_ERROR("OOB from " << peerIpPort << " dropped as payload is too big in driver " << mName);
        return NN_INVALID_PARAM;
    }

    /* choose worker */
    uint16_t workerIndex = 0;
    if (NN_UNLIKELY(!mClientLb->ChooseWorker(header.groupIndex, std::to_string(newId), workerIndex)) ||
        workerIndex >= mWorkers.size()) {
        NN_LOG_ERROR("OOB from " << peerIpPort << " dropped as invalid group index in driver " << mName);
        return NN_ERROR;
    }

    NN_LOG_TRACE_INFO("Worker " << workerIndex << " is chosen in driver " << mName);

    auto worker = mWorkers[workerIndex];
    NN_ASSERT_LOG_RETURN(worker != nullptr, NN_ERROR)

    /* create shm and init channel */
    ShmChannelPtr ch;
    result = ShmChannel::CreateAndInit(mName, newId, mOptions.mrSendReceiveSegSize, mOptions.qpSendQueueSize, ch);
    if (NN_UNLIKELY(result != NN_OK)) {
        NN_LOG_ERROR("OOB from " << peerIpPort << " dropped as create channel failure in driver " << mName);
        return result;
    }

    /* fill exchange info */
    ShmConnExchangeInfo exInfo {};
    NN_ASSERT_LOG_RETURN(worker->FillQueueExchangeInfo(exInfo), NN_ERROR)
    NN_ASSERT_LOG_RETURN(ch->FillExchangeInfo(exInfo), NN_ERROR)

    /* send exchange info */
    if (NN_UNLIKELY((result = SendExchangeInfo(conn, exInfo)) != NN_OK)) {
        NN_LOG_ERROR("Failed to send ex to OOB from " << peerIpPort << " in driver " << mName << ", result " << result);
        return result;
    }

    if (NN_UNLIKELY((result = ch->ChangeToReady(peerExInfo)) != NN_OK)) {
        NN_LOG_ERROR("OOB from " << peerIpPort << " dropped as failed to change channel to ready in driver " << mName);
        return result;
    }

    /* receive payload if needed */
    char payChars[NN_NO1024 + NN_NO1] {};
    if (peerExInfo.payLoadSize != 0) {
        tmpBuf = &payChars;
        if (NN_UNLIKELY((result = conn.Receive(tmpBuf, peerExInfo.payLoadSize)) != 0)) {
            NN_LOG_ERROR("Failed to read payload from " << peerIpPort << " in driver " << mName << ", result " <<
                result);
            return result;
        }
    }
    payChars[NN_NO1024] = '\0';

    /* create ep */
    UBSHcomNetEndpointPtr newEp = new (std::nothrow)
        NetAsyncEndpointShm(ch->Id(), ch.Get(), worker, this, worker->Index(), ShmMRHandleMap::GetInstance());
    if (NN_UNLIKELY(newEp.Get() == nullptr)) {
        NN_LOG_ERROR("Failed to new async shm ep in driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    struct ucred remoteIds {};
    socklen_t len = sizeof(struct ucred);
    if (NN_UNLIKELY(getsockopt(conn.GetFd(), SOL_SOCKET, SO_PEERCRED, &remoteIds, &len) != 0)) {
        char errBuf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to get uds ids in driver " << mName << " errno:" << errno << " error:" <<
            NetFunc::NN_GetStrError(errno, errBuf, NET_STR_ERROR_BUF_SIZE));
        return NN_GET_UDS_ID_INFO_FAILED;
    }
    newEp->RemoteUdsIdInfo(remoteIds.pid, remoteIds.uid, remoteIds.gid);

    if (mEnableTls) {
        auto childEp = newEp.ToChild<NetAsyncEndpointShm>();
        auto tmp = dynamic_cast<OOBSSLConnection *>(&conn);
        if (NN_UNLIKELY(childEp == nullptr || tmp == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        childEp->EnableEncrypt(mOptions);
        childEp->SetSecrets(tmp->Secret());
    }

    std::string payload = std::string(payChars, peerExInfo.payLoadSize);
    /* call user handler new endpoint handler */
    if (NN_UNLIKELY((result = mNewEndPointHandler(peerIpPort, newEp, payload)) != NN_OK)) {
        NN_LOG_ERROR("Calling new endpoint handler failed in driver " << mName << ", result " << result);
        return result;
    }

    ch->UpContext1(reinterpret_cast<uint64_t>(worker));
    ch->UpContext(reinterpret_cast<uint64_t>(newEp.Get()));
    ch->UdsFD(conn.GetFd());
    ch->PeerIpAndPort(conn.GetIpAndPort());
    ch->UdsName(conn.GetUdsName());
    newEp->StoreConnInfo(NetFunc::GetIpByFd(ch->UdsFD()), conn.ListenPort(), header.version, payload);
    newEp->State().Set(NEP_ESTABLISHED);

    /* send ready signal to oob */
    int8_t ready = 1;
    if (NN_UNLIKELY((result = conn.Send(&ready, sizeof(int8_t))) != NN_OK)) {
        NN_LOG_ERROR("Failed to send ready to " << peerIpPort << " in driver " << mName << ", result " << result);
        return NN_ERROR;
    }

    /* 1 transfer fd, 2 add ep into map */
    conn.TransferFd();
    AddEp(newEp);
    NN_ASSERT_LOG_RETURN(mChannelKeeper != nullptr, NN_ERROR);
    if ((result = mChannelKeeper->AddShmChannel(ch)) != NN_OK) {
        NN_LOG_ERROR("Adding Shm Channel failed, result: " << result);
        return result;
    }

    OOBSecureProcess::SecProcessAddEpNum(conn.GetUdsName(), conn.GetIpAndPort(), mOobServers);
    NN_LOG_INFO("New connection from " << peerIpPort << " established, async ep id " << newEp->Id() <<
        " worker info " << worker->Name());

    return NN_OK;
}

NResult NetDriverShmWithOOB::Connect(const std::string &serverUrl, const std::string &payload,
    UBSHcomNetEndpointPtr &ep, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
    VALIDATE_DRIVER_INIT()
    VALIDATE_PAYLOAD(payload.size())

    NetDriverOobType type;
    std::string ip;
    uint16_t port = 0;
    if (NN_UNLIKELY(NetFunc::NN_ValidateUrl(serverUrl) != NN_OK)) {
        NN_LOG_ERROR("Invalid url");
        return NN_PARAM_INVALID;
    }
    if (NN_UNLIKELY(ParseUrl(serverUrl, type, ip, port) != NN_OK)) {
        NN_LOG_WARN("Invalid url, url:" << serverUrl);
        return NN_INVALID_PARAM;
    }

    if (NN_UNLIKELY(NetDriverOobType::NET_OOB_UDS != type)) {
        NN_LOG_WARN("The current oobType is not supported, url:" << serverUrl);
        return NN_INVALID_PARAM;
    }
    return Connect(ip, port, payload, ep, flags, serverGrpNo, clientGrpNo, ctx);
}

NResult NetDriverShmWithOOB::Connect(const std::string &oobIp, uint16_t oobPort, const std::string &payload,
    UBSHcomNetEndpointPtr &ep, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
    VALIDATE_DRIVER_INIT()
    VALIDATE_PAYLOAD(payload.size())

    if (NN_UNLIKELY(!mStarted)) {
        NN_LOG_ERROR("Failed to connect on driver " << mName << " as it is not started");
        return NN_ERROR;
    }

    if (flags & NET_EP_SELF_POLLING) {
        return ConnectSyncEp(oobIp, oobPort, payload, ep, serverGrpNo, ctx);
    }

    if (NN_UNLIKELY(clientGrpNo >= mWorkerGroups.size())) {
        NN_LOG_ERROR("Invalid clientGrpNo " << clientGrpNo << " as it is large than existed groups");
        return NN_ERROR;
    }

    NResult result = NN_OK;
    OOBTCPClientPtr client;
    if (mEnableTls) {
        auto oobSSLClient = new (std::nothrow) OOBSSLClient(NET_OOB_UDS, oobIp, oobPort,
            mTlsPrivateKeyCB, mTlsCertCB, mTlsCaCallback);
        NN_ASSERT_LOG_RETURN(oobSSLClient != nullptr, NN_NEW_OBJECT_FAILED)
        oobSSLClient->SetTlsOptions(mOptions);
        oobSSLClient->SetPSKCallback(mPskFindSessionCb, mPskUseSessionCb);
        client = oobSSLClient;
    } else {
        client = new (std::nothrow) OOBTCPClient(NET_OOB_UDS, oobIp, oobPort);
        NN_ASSERT_LOG_RETURN(client.Get() != nullptr, NN_NEW_OBJECT_FAILED)
    }

    /* try to connect to oob server */
    OOBTCPConnection *conn = nullptr;
    if ((result = client->Connect(conn)) != 0) {
        NN_LOG_ERROR("Failed to connect server via oob, result " << result);
        return result;
    }

    const auto &peerIpPort = conn->GetIpAndPort();
    NetLocalAutoDecreasePtr<OOBTCPConnection> autoDecPtr(conn);
    conn->SetIpAndPort(oobIp, oobPort);

    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBClient(mSecInfoProvider, mSecInfoValidator, conn, mName, ctx,
        mOptions.secType))) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    /* send connection header */
    ConnectHeader header {};
    SetConnHeader(header, mOptions.magic, mOptions.version, serverGrpNo, Protocol(), mMajorVersion,
                  mMinorVersion, mOptions.tlsVersion);
    if (NN_UNLIKELY((result = conn->Send(&header, sizeof(ConnectHeader))) != NN_OK)) {
        NN_LOG_ERROR("Failed to send conn header to oob server " << oobIp << ":" << oobPort << " in driver " << mName);
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
    if (NN_UNLIKELY(resp != OK)) {
        NN_LOG_ERROR("Shm Failed to pass server validation in driver " << mName << ", result " << resp);
        return NN_CONNECT_REFUSED;
    }

    /* peer ep id */
    auto newId = respWithUId.epId;
    NN_LOG_TRACE_INFO("new ep id will be set as " << newId << " in driver " << mName);

    /* create shm and init channel */
    ShmChannelPtr ch;
    result = ShmChannel::CreateAndInit(mName, newId, mOptions.mrSendReceiveSegSize, mOptions.qpSendQueueSize, ch);
    if (NN_UNLIKELY(result != NN_OK)) {
        return result;
    }

    /* choose worker */
    uint16_t workerIndex = 0;
    if (NN_UNLIKELY(!mClientLb->ChooseWorker(clientGrpNo, std::to_string(newId), workerIndex)) ||
        workerIndex >= mWorkers.size()) {
        NN_LOG_ERROR("Failed to choose worker during connect in driver " << mName);
        return NN_ERROR;
    }

    NN_LOG_TRACE_INFO("Worker " << workerIndex << " is chosen in driver " << mName);

    auto worker = mWorkers[workerIndex];
    NN_ASSERT_LOG_RETURN(worker != nullptr, NN_ERROR)

    /* fill exchange info */
    ShmConnExchangeInfo exInfo {};
    NN_ASSERT_LOG_RETURN(worker->FillQueueExchangeInfo(exInfo), NN_ERROR)
    NN_ASSERT_LOG_RETURN(ch->FillExchangeInfo(exInfo), NN_ERROR)
    exInfo.payLoadSize = payload.length();

    /* send exchange info */
    if (NN_UNLIKELY((result = SendExchangeInfo(*conn, exInfo)) != NN_OK)) {
        NN_LOG_ERROR("Failed to send channel exchange info to oob server " << oobIp << ":" << oobPort <<
            " in driver " << mName);
        return NN_ERROR;
    }

    /* send payload */
    if (NN_UNLIKELY((result = conn->Send(const_cast<char *>(payload.c_str()), payload.length())) != NN_OK)) {
        NN_LOG_ERROR("Failed to send payload to peer at " << peerIpPort << " in driver " << mName);
        return result;
    }

    /* receive exchange info */
    NN_LOG_INFO("Try to receive exchange info from peer, " << sizeof(ShmConnExchangeInfo));
    if (NN_UNLIKELY((result = ReceiveExchangeInfo(*conn, exInfo)) != NN_OK)) {
        return result;
    }

    /* change to ready */
    if ((result = ch->ChangeToReady(exInfo)) != NN_OK) {
        return result;
    }

    /* receive ready signal */
    int8_t ready = -1;
    tmpBuf = static_cast<void *>(&ready);
    result = conn->Receive(tmpBuf, sizeof(int8_t));
    if (result != NN_OK || ready != 1) {
        NN_LOG_ERROR("Failed to receive ready from " << peerIpPort << " in driver " << mName << ", result " << result);
        return result;
    }

    /* create ep */
    UBSHcomNetEndpointPtr newEp = new (std::nothrow)
        NetAsyncEndpointShm(ch->Id(), ch.Get(), worker, this, worker->Index(), ShmMRHandleMap::GetInstance());
    if (NN_UNLIKELY(newEp.Get() == nullptr)) {
        NN_LOG_ERROR("Failed to new async shm ep in driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    if (mEnableTls) {
        auto childEp = newEp.ToChild<NetAsyncEndpointShm>();
        auto tmp = dynamic_cast<OOBSSLConnection *>(conn);
        if (NN_UNLIKELY(childEp == nullptr || tmp == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        childEp->EnableEncrypt(mOptions);
        childEp->SetSecrets(tmp->Secret());
    }

    /* 1 transfer fd, 2 set upCtx, 3 set payload, 4 add ep into map, 5 set state */
    ch->UdsFD(conn->TransferFd());
    ch->UpContext1(reinterpret_cast<uint64_t>(worker));
    ch->UpContext(reinterpret_cast<uint64_t>(newEp.Get()));
    newEp->StoreConnInfo(NetFunc::GetIpByFd(ch->UdsFD()), conn->ListenPort(), header.version, payload);
    AddEp(newEp);
    newEp->State().Set(NEP_ESTABLISHED);

    ep.Set(newEp.Get());

    NN_ASSERT_LOG_RETURN(mChannelKeeper != nullptr, NN_ERROR);
    if ((result = mChannelKeeper->AddShmChannel(ch)) != NN_OK) {
        NN_LOG_ERROR("Adding Shm Channel failed, result: " << result);
        return result;
    }

    NN_LOG_INFO("New connection to " << oobIp << ":" << oobPort << " established, async ep id " << ep->Id() <<
        " worker info " << worker->Name());
    return NN_OK;
}

NResult NetDriverShmWithOOB::MultiRailNewConnection(OOBTCPConnection &conn)
{
    NN_LOG_ERROR("Invalid operation, SHM is not supported by MultiRail");
    return NN_ERROR;
}

void NetDriverShmWithOOB::DestroyEndpoint(UBSHcomNetEndpointPtr &ep)
{
    if (NN_UNLIKELY(ep.Get() == nullptr)) {
        NN_LOG_WARN("The shm ep is null already.");
        return;
    }

    NN_LOG_INFO("Destroy endpoint id " << ep->Id());
    if (NN_LIKELY(mDelayReleaseTimer != nullptr)) {
        mDelayReleaseTimer->EnqueueDelayRelease(ep);
    }

    auto result = Remove(ep->Id());
    if (result == 0) {
        NN_LOG_WARN("Unable to destroy shm endpoint as ep " << ep->Id() << " doesn't exist, maybe cleaned already");
        return;
    }

    ep.Set(nullptr);
}

void NetDriverShmWithOOB::DestroyMemoryRegion(UBSHcomNetMemoryRegionPtr &mr)
{
    if (NN_UNLIKELY(mr.Get() == nullptr)) {
        NN_LOG_WARN("Try to destroy null memory region in shm driver " << mName);
        return;
    }
    if (!mMrChecker.Contains(mr->GetLKey())) {
        NN_LOG_WARN("Try to destroy unowned memory region in shm driver " << mName);
        return;
    }
    mMrChecker.UnRegister(mr->GetLKey());
    mr->UnInitialize();
}
}
}