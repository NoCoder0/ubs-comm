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

#include "hcom_env.h"
#include "ub_urma_wrapper_jetty.h"
#include "ub_worker.h"

namespace ock {
namespace hcom {

std::atomic<uint32_t> g_jetty_id(1);

/* ******************************************************************************************** */
/* ******************************************************************************************** */
uint32_t UBJetty::G_INDEX = 1;

UResult UBJetty::CreateUrmaJetty(uintptr_t seg_pa, uint32_t seg_len, uint32_t seg_count, uint32_t token)
{
    if (mUBContext == nullptr || mUBContext->mUrmaContext == nullptr || mSendJfc == nullptr ||
        mSendJfc->mUrmaJfc == nullptr) {
        NN_LOG_ERROR("Invalid parameter for jetty creating");
        return UB_PARAM_INVALID;
    }

    mCtxPosted.next = nullptr;
    mCtxPosted.prev = nullptr;

    mJettyOptions.maxSendWr =
        (mJettyOptions.maxSendWr < JETTY_MAX_SEND_WR) ? JETTY_MAX_SEND_WR : mJettyOptions.maxSendWr;
    mJettyOptions.maxReceiveWr =
        (mJettyOptions.maxReceiveWr < JETTY_MAX_RECV_WR) ? JETTY_MAX_RECV_WR : mJettyOptions.maxReceiveWr;

    urma_jfs_cfg_t jfs_cfg{};
    FillJfsCfg(&jfs_cfg);
    urma_jfr_cfg_t jfr_cfg{};
    FillJfrCfg(&jfr_cfg, token);

    urma_jetty_flag_t jetty_flag{};
    jetty_flag.bs.share_jfr = 1;

    urma_jetty_cfg_t jetty_cfg{};
    jetty_cfg.id = 0;
    jetty_cfg.flag = jetty_flag;
    jetty_cfg.jfs_cfg = jfs_cfg;
    jetty_cfg.jfr_cfg = &jfr_cfg;

    urma_jetty_t *tmpJetty = nullptr;

    mJfr = HcomUrma::CreateJfr(mUBContext->mUrmaContext, &jfr_cfg);
    if (mJfr == nullptr) {
        NN_LOG_ERROR("urma create jfr failed");
        return UB_PARAM_INVALID;
    }
    jetty_cfg.shared.jfc = mRecvJfc->mUrmaJfc;
    jetty_cfg.shared.jfr = mJfr;
    tmpJetty = HcomUrma::CreateJetty(mUBContext->mUrmaContext, &jetty_cfg);
    if (tmpJetty == nullptr) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to create urma jetty for UBJetty " << mName << ", errno " <<
            NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        if (mJfr != nullptr) {
            HcomUrma::DeleteJfr(mJfr);
            mJfr = nullptr;
        }
        return UB_QP_CREATE_FAILED;
    }
    mUrmaJetty = tmpJetty;
    mUrmaJettyId = mUrmaJetty->jetty_id.id;

    NN_LOG_INFO("Create jetty success, jetty id: " << mUrmaJettyId << ", jfr id: " << (mJfr ? mJfr->jfr_id.id : -1) <<
        ", jfc id: " << mRecvJfc->mUrmaJfc->jfc_id.id << ", priority: " <<
        static_cast<int>(jetty_cfg.jfs_cfg.priority));
    return UB_OK;
}

UResult UBJetty::Stop()
{
    std::lock_guard<std::mutex> lock(mStopMutex);
    if (mUrmaJetty == nullptr) {
        return UB_OK;
    }

    // 标记为 ERROR，准备进入待清理流程
    //
    // 用户可能人工调用 EP->Close() 进入，与ProcessEpError (心跳线程或者是 UBWorker）产生竞争，避免因多次调用 modify
    // jetty error 产生多次 FLUSH_ERROR_DONE 的情况。
    UBJettyState expState = UBJettyState::READY;
    if (!mState.compare_exchange_strong(expState, UBJettyState::ERROR)) {
        return UB_OK;
    }

    // 仅 AsyncEp. 在 modify jetty error 后可能会立即触发 FLUSH_ERROR_DONE，需要提前准备好。
    auto *worker = reinterpret_cast<UBWorker *>(GetUpContext1());
    if (worker != nullptr) {
        worker->mJettyPtrMap.Emplace(mUrmaJettyId, this);
    }

    // jfr 为 error 后不会再收到对端发来的数据。
    if (mJfr != nullptr) {
        urma_jfr_attr_t jfr_attr = {};
        jfr_attr.mask = JFR_STATE;
        jfr_attr.state = URMA_JFR_STATE_ERROR;
        auto result = HcomUrma::ModifyJfr(mJfr, &jfr_attr);
        if (result != UB_OK) {
            NN_LOG_ERROR("Fail to modify jfr to URMA_JFR_STATE_ERROR, urma result is " << result);
            return result;
        }
    }

    // 大段注释，主要说明了需要先将jfr置为errror再ModifyJetty，否则会导致问题。
    struct urma_jetty_attr attr = {};
    attr.mask = JETTY_STATE;
    attr.state = URMA_JETTY_STATE_ERROR;
    int result = HcomUrma::ModifyJetty(mUrmaJetty, &attr);
    if (result != UB_OK) {
        NN_LOG_ERROR("Failed to modify jetty to URMA_JETTY_STATE_ERROR, urma result is " << result);
        return result;
    }

    if (mHBLocalMr != nullptr) {
        DestroyHBMemoryRegion(mHBLocalMr);
        mHBLocalMr.Set(nullptr);
    }

    if (mHBRemoteMr != nullptr) {
        DestroyHBMemoryRegion(mHBRemoteMr);
        mHBRemoteMr.Set(nullptr);
    }

    NN_LOG_INFO("Stop Jetty " << mName << ", jetty id " << mUrmaJetty->jetty_id.id << ", Ep Id " << mUpId);
    return result;
}

void UBJetty::FillJfsCfg(urma_jfs_cfg_t *jfs_cfg)
{
    jfs_cfg->user_ctx = reinterpret_cast<uint64_t>(this);
    jfs_cfg->jfc = mSendJfc->mUrmaJfc;
    jfs_cfg->trans_mode = URMA_TM_RC;
    jfs_cfg->depth = mJettyOptions.maxSendWr + NN_NO8;
    jfs_cfg->max_sge = static_cast<uint8_t>(mUBContext->mMaxSge);
    jfs_cfg->flag.value = 0;
    jfs_cfg->max_inline_data = HcomEnv::InlineThreshold();
    jfs_cfg->err_timeout = NN_NO8;
    jfs_cfg->rnr_retry = NN_NO7;
    // HighBandwidth RM mode, LowLatency RC mode
    jfs_cfg->trans_mode = (mJettyOptions.ubcMode == UBSHcomUbcMode::HighBandwidth) ? URMA_TM_RM : URMA_TM_RC;
    jfs_cfg->flag.bs.multi_path = (mJettyOptions.ubcMode == UBSHcomUbcMode::HighBandwidth) ? 1 : 0;
    jfs_cfg->priority = (mJettyOptions.ubcMode == UBSHcomUbcMode::HighBandwidth)
                        ? mUBContext->mCtpPri : mUBContext->mRtpPri;
}

void UBJetty::FillJfrCfg(urma_jfr_cfg_t *jfr_cfg, uint32_t token)
{
    jfr_cfg->user_ctx = reinterpret_cast<uint64_t>(this);
    jfr_cfg->jfc = mRecvJfc->mUrmaJfc;
    jfr_cfg->trans_mode = URMA_TM_RC;
    jfr_cfg->depth = mJettyOptions.maxReceiveWr + NN_NO8;
    jfr_cfg->max_sge = static_cast<uint8_t>(mUBContext->mMaxSge);
    jfr_cfg->token_value = {token};
    jfr_cfg->flag.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    jfr_cfg->id = 0;
    jfr_cfg->flag.bs.tag_matching = URMA_NO_TAG_MATCHING;
    // HighBandwidth RM mode, LowLatency RC mode
    jfr_cfg->trans_mode = (mJettyOptions.ubcMode == UBSHcomUbcMode::HighBandwidth) ? URMA_TM_RM : URMA_TM_RC;
}

UResult UBJetty::CreateJettyMr()
{
    NResult result = NN_OK;
    // create mr pool for send/receive and initialize
    if ((result = UBMemoryRegionFixedBuffer::Create(mName, mUBContext, mJettyOptions.mrSegSize,
        mJettyOptions.mrSegCount, mJettyOptions.slave, mJettyMr)) != 0) {
        NN_LOG_ERROR("Failed to create mr for send/receive in jetty " << mName << ", result " << result);
        return result;
    }
    mJettyMr->IncreaseRef();
    if ((result = mJettyMr->Initialize()) != 0) {
        NN_LOG_ERROR("Failed to initialize mr for send/receive in jetty " << mName << ", result " << result);
        return result;
    }

    return UB_OK;
}

UBMemoryRegionFixedBuffer *UBJetty::GetJettyMr()
{
    return mJettyMr;
}

bool UBJetty::GetFreeBuff(uintptr_t &item)
{
    return mJettyMr->GetFreeBuffer(item);
}

bool UBJetty::GetFreeBufferN(uintptr_t *&items, uint32_t n)
{
    return mJettyMr->GetFreeBufferN(items, n);
}

bool UBJetty::ReturnBuffer(uintptr_t value)
{
    return mJettyMr->ReturnBuffer(value);
}

uint64_t UBJetty::GetLKey()
{
    return mJettyMr->GetLKey();
}

urma_target_seg_t *UBJetty::GetMemorySeg()
{
    return reinterpret_cast<urma_target_seg_t *>(mJettyMr->GetMemorySeg());
}

UResult UBJetty::Initialize(uint32_t seg_count, unsigned long memid, uint32_t token)
{
    auto result = CreateJettyMr();
    if (result != UB_OK) {
        return result;
    }
    result = CreateUrmaJetty(0, 0, 0, token);
    if (result != UB_OK) {
        NN_LOG_ERROR("Failed to create urma jetty");
        return result;
    }
    return UB_OK;
}

UResult UBJetty::UnInitialize()
{
    int result = 0;
    if (mUrmaJetty != nullptr) {
        if (mJettyOptions.ubcMode == UBSHcomUbcMode::LowLatency) {
            result = HcomUrma::UnbindJetty(mUrmaJetty);
        }
        if (mTargetJetty != nullptr) {
            HcomUrma::UnimportJetty(mTargetJetty);
            mTargetJetty = nullptr;
        }
        if ((result = HcomUrma::DeleteJetty(mUrmaJetty)) != 0) {
            char buf[NET_STR_ERROR_BUF_SIZE] = {0};
            NN_LOG_WARN("Unable to delete jetty id " << mUrmaJettyId << ", result " << result << ", errno " <<
                NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        } else {
            NN_LOG_INFO("Delete jetty success, jetty id: " << mUrmaJettyId);
        }
        mUrmaJetty = nullptr;
    }

    if (mJfr != nullptr) {
        if ((result = HcomUrma::DeleteJfr(mJfr)) != 0) {
            char buf[NET_STR_ERROR_BUF_SIZE] = {0};
            NN_LOG_WARN("Unable to delete jfr " << result << ", as errno " <<
                NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        }
        mJfr = nullptr;
    }

    if (mSendJfc != nullptr) {
        mSendJfc->DecreaseRef();
    }

    if (mRecvJfc != nullptr && mRecvJfc != mSendJfc) {
        mRecvJfc->DecreaseRef();
    }
    mSendJfc = nullptr;
    mRecvJfc = nullptr;

    if (mUBContext != nullptr) {
        mUBContext->DecreaseRef();
        mUBContext = nullptr;
    }

    // 销毁jfr才能停止接收；先销毁jfr，再销毁接收缓冲区
    if (mJettyMr != nullptr) {
        mJettyMr->DecreaseRef();
        mJettyMr = nullptr;
    }

    if (mHBLocalMr != nullptr) {
        DestroyHBMemoryRegion(mHBLocalMr);
        mHBLocalMr.Set(nullptr);
    }

    if (mHBRemoteMr != nullptr) {
        DestroyHBMemoryRegion(mHBRemoteMr);
        mHBRemoteMr.Set(nullptr);
    }
    NN_LOG_INFO("Uninitialize jetty success, jetty id: " << mUrmaJettyId);
    return UB_OK;
}

void UBJetty::Cleanup()
{
    // 仅 AsyncEp 需要清理 op ctx list. SyncEp 使用的是 thread_local 级别的 op ctx， 无需清理
    auto *worker = reinterpret_cast<UBWorker *>(GetUpContext1());
    if (worker == nullptr) {
        return;
    }

    // 如果在创建 EP 过程中失败，则 UBJetty 无对应EP，依赖 ClearJettyResource 清理 PostReceive 的资源。
    // \see ClearJettyResource
    auto *ep = reinterpret_cast<NetUBAsyncEndpoint *>(GetUpContext());
    if (ep == nullptr) {
        return;
    }

    // EP 析构时先析构 jetty，再析构 worker、driver.
    auto *driver = ep->GetDriver();

    UBOpContextInfo *it = nullptr;
    GetCtxPosted(it);
    while (it != nullptr) {
        UBOpContextInfo *next = it->next;

        // 剩余的 op ctx 都未被硬件处理，无法获得CQE，需要 hcom 人工清理
        it->opResultType = UBOpContextInfo::ERR_EP_BROKEN;
        switch (it->opType) {
            case UBOpContextInfo::SEND:
            case UBOpContextInfo::SEND_RAW:
            case UBOpContextInfo::SEND_RAW_SGL:
                driver->ProcessErrorSendFinished(it);
                break;
            case UBOpContextInfo::RECEIVE:
            case UBOpContextInfo::RECEIVE_RAW:
                driver->ProcessErrorNewRequest(it);
                break;
            case UBOpContextInfo::WRITE:
            case UBOpContextInfo::READ:
            case UBOpContextInfo::SGL_WRITE:
            case UBOpContextInfo::SGL_READ:
            case UBOpContextInfo::HB_WRITE:
                driver->ProcessErrorOneSideDone(it);
                break;
        }

        // 至此，it 指向的内存可能会归还给 mempool，再修改 it 指向的内存可能会引起并发冲突
        it = next;
    }
}

UResult UBJetty::ChangeToInit(urma_jetty_attr_t &attr)
{
    return UB_OK;
}

UResult UBJetty::ChangeToReceive(ock::hcom::UBJettyExchangeInfo &exInfo, urma_jetty_attr_t &attr)
{
    return UB_OK;
}

UResult UBJetty::ChangeToSend(urma_jetty_attr_t &attr)
{
    return UB_OK;
}

UResult UBJetty::ChangeToReady(ock::hcom::UBJettyExchangeInfo &exInfo)
{
    if (NN_UNLIKELY(mUrmaJetty == nullptr)) {
        NN_LOG_ERROR("Failed to change jetty " << mName << " state to READY as urma jetty is not created.");
        return UB_QP_CHANGE_STATE_FAILED;
    }

    UResult ret = 0;
    ret = SetMaxSendWrConfig(exInfo);
    if (ret != UB_OK) {
        return ret;
    }

    ret = ImportAndBindJetty(exInfo.token);
    if (ret != UB_OK) {
        return ret;
    }

    NN_LOG_INFO("UB jetty " << mId << " attr send queue size " << mJettyOptions.maxSendWr << ", receive queue size " <<
        mJettyOptions.maxReceiveWr << ", eid-n-n " << (exInfo.eid.in6.interface_id != 0));

    mState = UBJettyState::READY;
    return UB_OK;
}

UResult UBJetty::SetMaxSendWrConfig(UBJettyExchangeInfo &exInfo)
{
    NN_LOG_TRACE_INFO("Remote qpId " << mId << " info: send wr " << exInfo.maxSendWr << ", receive wr " <<
        exInfo.maxReceiveWr << ", receive seg size " << exInfo.receiveSegSize << ", receive seg count " <<
        exInfo.receiveSegCount);
    NN_LOG_TRACE_INFO("Local qpId " << mId << " info: send wr " << mJettyOptions.maxSendWr << ", receive wr " <<
        mJettyOptions.maxReceiveWr << ", receive seg size " << mJettyOptions.mrSegSize << ", receive seg count " <<
        mJettyOptions.mrSegCount);

    int32_t maxWr = std::min(mJettyOptions.maxSendWr, exInfo.maxReceiveWr);
    int32_t maxPostSendWr = std::min(mJettyOptions.maxSendWr, exInfo.receiveSegCount);
    if (maxWr < maxPostSendWr) {
        NN_LOG_ERROR("Qp " << mId << " max wr " << maxWr << " is less than max post send wr" << maxPostSendWr);
        return UB_QP_RECEIVE_CONFIG_ERR;
    }
    // one side operation do not consume remote receive queue element
    mOneSideMaxWr = maxWr - maxPostSendWr;
    mOneSideRef = mOneSideMaxWr;
    mPostSendMaxWr = maxPostSendWr;
    mPostSendRef = mPostSendMaxWr;
    mPostSendMaxSize = exInfo.receiveSegSize;
    NN_LOG_TRACE_INFO("Qp id " << mId << " one side max wr " << mOneSideMaxWr << ", post send max wr " <<
        mPostSendMaxWr << ", post send max size " << mPostSendMaxSize);
    return UB_OK;
}

UResult UBJetty::FillExchangeInfo(UBJettyExchangeInfo &exInfo)
{
    if (mUrmaJetty == nullptr || mUBContext == nullptr) {
        return UB_QP_NOT_INITIALIZED;
    }

    exInfo.jettyId = mUrmaJetty->jetty_id;
    exInfo.eid = mUBContext->mBestEid.urmaEid;

    return UB_OK;
}

void UBJetty::StoreExchangeInfo(UBJettyExchangeInfo *exInfo)
{
    mRemoteJettyInfo.reset(exInfo);
}

UBJettyExchangeInfo &UBJetty::GetExchangeInfo()
{
    return *mRemoteJettyInfo;
}

void UBJetty::SetPeerIpAndPort(const std::string &value)
{
    mPeerIpPort = value;
}

uint32_t UBJetty::GetPostSendMaxSize() const
{
    return mPostSendMaxSize;
}

UResult UBJetty::ImportAndBindJetty(uint32_t token)
{
    // import/bind remote jetty
    urma_rjetty_t remoteJetty{}; // remote jetty on the other side
    remoteJetty.jetty_id = mRemoteJettyInfo->jettyId;
    remoteJetty.trans_mode = URMA_TM_RC;
    remoteJetty.type = URMA_JETTY;
    remoteJetty.trans_mode = (mJettyOptions.ubcMode == UBSHcomUbcMode::HighBandwidth) ? URMA_TM_RM : URMA_TM_RC;
    remoteJetty.flag.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    remoteJetty.tp_type = (mJettyOptions.ubcMode == UBSHcomUbcMode::HighBandwidth) ? URMA_CTP : URMA_RTP;
    urma_token_t tokenValue{token};
    if (mJettyOptions.ubcMode == UBSHcomUbcMode::HighBandwidth) {
        NN_LOG_ERROR("[PHZ]ubcMode == UBSHcomUbcMode::HighBandwidth, tp_type: " << static_cast<int>(remoteJetty.tp_type));
    }


    if (mJettyOptions.ubcMode == UBSHcomUbcMode::LowLatency) {
        NN_LOG_ERROR("[PHZ]ubcMode == UBSHcomUbcMode::LowLatency, tp_type: " << static_cast<int>(remoteJetty.tp_type));
    }

    if (remoteJetty.tp_type == URMA_CTP) {
        NN_LOG_ERROR("[PHZ]remoteJetty.tp_type == URMA_CTP, URMA_CTP " << URMA_CTP);
    }

    if (remoteJetty.tp_type == URMA_RTP) {
        NN_LOG_ERROR("[PHZ]remoteJetty.tp_type == URMA_RTP, URMA_RTP " << URMA_RTP);
    }

    mTargetJetty = HcomUrma::ImportJetty(mUBContext->mUrmaContext, &remoteJetty, &tokenValue);
    if (mTargetJetty == nullptr) {
        NN_LOG_ERROR("Failed to import jetty");
        return UB_QP_IMPORT_FAILED;
    }

    NN_LOG_INFO("Local jetty id: " << mUrmaJetty->jetty_id.id);
    NN_LOG_INFO("Remote jetty id: " << mRemoteJettyInfo->jettyId.id);

    if (mJettyOptions.ubcMode == UBSHcomUbcMode::LowLatency) {
        int ret = HcomUrma::BindJetty(mUrmaJetty, mTargetJetty);
        if (ret != URMA_SUCCESS && ret != URMA_EEXIST) {
            NN_LOG_ERROR("Failed to bind local jetty, result: " << ret);
            HcomUrma::UnimportJetty(mTargetJetty);
            mTargetJetty = nullptr;
            return UB_QP_BIND_FAILED;
        }
    }

    return UB_OK;
}

NResult UBJetty::CreateHBMemoryRegion(uint64_t size, UBSHcomNetMemoryRegionPtr &mr)
{
    if (NN_UNLIKELY(size == 0 || size > NN_NO65536)) {
        NN_LOG_ERROR("Failed to create heartbeat mem region as size is 0 or greater than 64 KB");
        return NN_INVALID_PARAM;
    }

    UBMemoryRegion *tmp = nullptr;
    auto result = UBMemoryRegion::Create(mName, mUBContext, size, tmp);
    if (NN_UNLIKELY(result != UB_OK)) {
        NN_LOG_ERROR("Failed to create heartbeat mem region, result " << result);
        return result;
    }

    if ((result = tmp->InitializeForOneSide()) != UB_OK) {
        delete tmp;
        return result;
    }

    mr.Set(static_cast<UBSHcomNetMemoryRegion *>(tmp));

    return UB_OK;
}

void UBJetty::DestroyHBMemoryRegion(UBSHcomNetMemoryRegionPtr &mr)
{
    if (mr.Get() == nullptr) {
        NN_LOG_WARN("Try to destroy null memory region");
        return;
    }

    mr->UnInitialize();
}

} // namespace hcom
} // namespace ock
#endif
