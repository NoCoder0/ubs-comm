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
#ifdef RDMA_BUILD_ENABLED
#include <algorithm>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/poll.h>

#include "rdma_verbs_wrapper_qp.h"

namespace ock {
namespace hcom {

uint32_t RDMAQp::G_INDEX = 1;

RResult RDMAQp::CreateIbvQp()
{
    NN_LOG_TRACE_INFO("RDMAQp::Initialize");
    if (mRDMAContext == nullptr || mRDMAContext->mContext == nullptr || mSendCQ == nullptr ||
        mSendCQ->mCompletionQueue == nullptr || mRecvCQ == nullptr || mRecvCQ->mCompletionQueue == nullptr) {
        return RR_PARAM_INVALID;
    }

    mCtxPosted.next = nullptr;
    mCtxPosted.prev = nullptr;

    struct ibv_qp_init_attr initAttr {};
    bzero(&initAttr, sizeof(ibv_qp_init_attr));
    initAttr.qp_context = this;
    initAttr.send_cq = mSendCQ->mCompletionQueue;
    initAttr.recv_cq = mRecvCQ->mCompletionQueue;
    initAttr.qp_type = IBV_QPT_RC;
    mQpOptions.maxSendWr = (mQpOptions.maxSendWr < QP_MAX_SEND_WR) ? QP_MAX_SEND_WR : mQpOptions.maxSendWr;
    mQpOptions.maxReceiveWr = (mQpOptions.maxReceiveWr < QP_MAX_RECV_WR) ? QP_MAX_RECV_WR : mQpOptions.maxReceiveWr;
    // NN_NO8 is the window size Preventing mPostSendMaxWr exceeds ibv max_send_wr caused by mPostSendMaxWr increasing
    // during waiting for mPostSendMaxWr,which will cause ibv_post_send return error 12
    initAttr.cap.max_send_wr = mQpOptions.maxSendWr + NN_NO8;
    initAttr.cap.max_recv_wr = mQpOptions.maxReceiveWr + NN_NO8;
    initAttr.cap.max_recv_sge = static_cast<uint32_t>(mRDMAContext->mMaxSge);
    initAttr.cap.max_send_sge = static_cast<uint32_t>(mRDMAContext->mMaxSge);
    initAttr.cap.max_inline_data = HcomEnv::InlineThreshold();

    NN_LOG_WARN("QP create: max_send_sge=" << initAttr.cap.max_send_sge
                << " NET_SGE_MAX_IOV=" << NET_SGE_MAX_IOV);
    auto tmpQP = HcomIbv::CreateQp(mRDMAContext->mProtectDomain, &initAttr);
    if (tmpQP == nullptr) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to create ibv qp RDMAQp " << mName << ", errno "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_QP_CREATE_FAILED;
    }

    mQP = tmpQP;
    NN_LOG_TRACE_INFO("RDMAQp::Initialized");
    return RR_OK;
}

RResult RDMAQp::CreateQpMr()
{
    NResult result = NN_OK;
    // create mr pool for send/receive and initialize
    if ((result = RDMAMemoryRegionFixedBuffer::Create(mName, mRDMAContext, mQpOptions.mrSegSize, mQpOptions.mrSegCount,
        mQpMr)) != 0) {
        NN_LOG_ERROR("Failed to create mr for send/receive in qp " << mName << ", result " << result);
        return result;
    }
    if ((result = mQpMr->Initialize()) != 0) {
        NN_LOG_ERROR("Failed to initialize mr for send/receive in qp " << mName << ", result " << result);
        return result;
    }
    mQpMr->IncreaseRef();
    return RR_OK;
}

bool RDMAQp::GetFreeBuff(uintptr_t &item)
{
    return mQpMr->GetFreeBuffer(item);
}

bool RDMAQp::GetFreeBufferN(uintptr_t *&items, uint32_t n)
{
    return mQpMr->GetFreeBufferN(items, n);
}

bool RDMAQp::ReturnBuffer(uintptr_t value)
{
    return mQpMr->ReturnBuffer(value);
}

uint32_t RDMAQp::GetLKey()
{
    return static_cast<uint32_t>(mQpMr->GetLKey());
}

RResult RDMAQp::Initialize()
{
    auto result = CreateIbvQp();
    if (result != RR_OK) {
        NN_LOG_ERROR("RDMA failed to create ibv qp");
        return result;
    }

    result = CreateQpMr();
    if (result != RR_OK) {
        NN_LOG_ERROR("RDMA failed to create qp mr");
        HcomIbv::DestroyQp(mQP);
        mQP = nullptr;
        return result;
    }

    return RR_OK;
}

RResult RDMAQp::UnInitialize()
{
    if (mQP != nullptr) {
        HcomIbv::DestroyQp(mQP);
        mQP = nullptr;
    }

    Stop();

    if (mQpMr != nullptr) {
        mQpMr->DecreaseRef();
        mQpMr = nullptr;
    }

    if (mSendCQ != nullptr) {
        mSendCQ->DecreaseRef();
    }

    if (mRecvCQ != nullptr && mRecvCQ != mSendCQ) {
        mRecvCQ->DecreaseRef();
    }
    mSendCQ = nullptr;
    mRecvCQ = nullptr;

    if (mRDMAContext != nullptr) {
        mRDMAContext->DecreaseRef();
        mRDMAContext = nullptr;
    }

    return RR_OK;
}

RResult RDMAQp::ChangeToInit(struct ibv_qp_attr &attr)
{
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = mRDMAContext->mPortNumber;
    attr.qp_access_flags =
        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_REMOTE_WRITE;

    if (HcomIbv::ModifyQp(mQP, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS) != 0) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to change qp " << mName << " state to INIT modify failed, errno:" << errno << " error:" <<
            NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_QP_CHANGE_STATE_FAILED;
    }

    return RR_OK;
}

RResult RDMAQp::ChangeToReceive(RDMAQpExchangeInfo &exInfo, struct ibv_qp_attr &attr)
{
    RResult ret = 0;
    static uint8_t tc = GetTrafficClass();
    static uint8_t rdAtomic = GetMaxRdAtomic();

    attr.qp_state = IBV_QPS_RTR;
    // path_mtu must not exceed the network mtu, otherwise >1 pkt messages (e.g. a merged SGE WR) get dropped
    attr.path_mtu = (mRDMAContext->mPortAttr.active_mtu > IBV_MTU_256) ?
        mRDMAContext->mPortAttr.active_mtu : IBV_MTU_256;
    attr.dest_qp_num = exInfo.qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = rdAtomic;
    attr.min_rnr_timer = QP_MIN_RNR_TIMER;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = exInfo.lid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1;
    if (exInfo.gid.global.interface_id) {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.dgid = exInfo.gid;
        attr.ah_attr.grh.sgid_index = mRDMAContext->mBestGid.gid;
        attr.ah_attr.grh.traffic_class = tc;
    }

    if ((ret = HcomIbv::ModifyQp(mQP, &attr,
        IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC |
        IBV_QP_MIN_RNR_TIMER)) != 0) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to change qp " << mName << " state to READY-TO-RECEIVE modify failed result " << ret <<
            ", errno:" << errno << " error:" << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_QP_CHANGE_STATE_FAILED;
    }

    return RR_OK;
}

RResult RDMAQp::ChangeToSend(struct ibv_qp_attr &attr)
{
    static uint8_t rdAtomic = GetMaxRdAtomic();
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = QP_TIMEOUT; // 2^14 * 4.096 us = 67108.86 us
    attr.retry_cnt = QP_RETRY_COUNT;
    attr.rnr_retry = QP_RNR_RETRY; // do later
    attr.sq_psn = 0;
    attr.max_rd_atomic = rdAtomic;

    if (HcomIbv::ModifyQp(mQP, &attr,
        IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
        IBV_QP_MAX_QP_RD_ATOMIC) != 0) {
        NN_LOG_ERROR("Failed to change qp " << mName << " state to READY-TO-SEND modify failed, errno " << errno);
        return RR_QP_CHANGE_STATE_FAILED;
    }

    return RR_OK;
}

RResult RDMAQp::SetMaxSendWrConfig(RDMAQpExchangeInfo &exInfo)
{
    NN_LOG_TRACE_INFO("Remote qpId " << mId << " info: send wr " << exInfo.maxSendWr << ", receive wr " <<
        exInfo.maxReceiveWr << ", receive seg size " << exInfo.receiveSegSize << ", receive seg count " <<
        exInfo.receiveSegCount);
    NN_LOG_TRACE_INFO("Local qpId " << mId << " info: send wr " << mQpOptions.maxSendWr << ", receive wr " <<
        mQpOptions.maxReceiveWr << ", receive seg size " << mQpOptions.mrSegSize << ", receive seg count " <<
        mQpOptions.mrSegCount);

    int32_t maxWr = std::min(mQpOptions.maxSendWr, exInfo.maxReceiveWr);
    int32_t maxPostSendWr = std::min(mQpOptions.maxSendWr, exInfo.receiveSegCount);
    if (maxWr < maxPostSendWr) {
        NN_LOG_ERROR("Qp " << mId << " max wr " << maxWr << " is less than max post send wr" << maxPostSendWr);
        return RR_QP_RECEIVE_CONFIG_ERR;
    }
    // one side operation do not consume remote receive queue element
    mOneSideMaxWr = maxWr - maxPostSendWr;
    mOneSideRef = mOneSideMaxWr;
    mPostSendMaxWr = maxPostSendWr;
    mPostSendRef = mPostSendMaxWr;
    mPostSendMaxSize = exInfo.receiveSegSize;
    NN_LOG_TRACE_INFO("Qp id " << mId << " one side max wr " << mOneSideMaxWr << ", post send max wr " <<
        mPostSendMaxWr << ", post send max size " << mPostSendMaxSize);
    return RR_OK;
}

RResult RDMAQp::ChangeToReady(RDMAQpExchangeInfo &exInfo)
{
    if (NN_UNLIKELY(mQP == nullptr)) {
        NN_LOG_ERROR("Failed to change qp " << mName << " state to READY-TO-SEND as qp is not created.");
        return RR_QP_CHANGE_STATE_FAILED;
    }

    RResult ret = 0;
    ret = SetMaxSendWrConfig(exInfo);
    if (ret != RR_OK) {
        return ret;
    }

    struct ibv_qp_attr attr {};
    ret = ChangeToInit(attr);
    if (ret != RR_OK) {
        return ret;
    }

    ret = ChangeToReceive(exInfo, attr);
    if (ret != RR_OK) {
        return ret;
    }

    ret = ChangeToSend(attr);
    if (ret != RR_OK) {
        return ret;
    }

    NN_LOG_INFO("RDMA qp " << mId << " attr send queue size " << mQpOptions.maxSendWr << ", receive queue size " <<
        mQpOptions.maxReceiveWr << ", tc " << std::to_string(attr.ah_attr.grh.traffic_class) << ", gid-n-n " <<
        (exInfo.gid.global.interface_id != 0));

    isStarted = true;
    return RR_OK;
}

RResult RDMAQp::GetExchangeInfo(RDMAQpExchangeInfo &exInfo)
{
    if (mQP == nullptr || mRDMAContext == nullptr) {
        return RR_QP_NOT_INITIALIZED;
    }

    exInfo.qpn = mQP->qp_num;
    exInfo.lid = mRDMAContext->mPortAttr.lid;
    exInfo.gid = mRDMAContext->mBestGid.ibvGid;
    return RR_OK;
}
}
}
#endif