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

#include "net_monotonic.h"
#include "hcom_rdma_trace.h"
#include "rdma_verbs_wrapper_cq.h"

namespace ock {
namespace hcom {

RResult RDMACq::CreatePollingCq()
{
    auto tmpCQ = HcomIbv::CreateCq(mRDMAContext->mContext, static_cast<int>(mCQCount), reinterpret_cast<void *>(mWork),
        nullptr, 0);
    if (tmpCQ == nullptr) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to create completion queue for RDMACq " << mName << ", error "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_NEW_OBJECT_FAILED;
    }

    mCompletionQueue = tmpCQ;
    return RR_OK;
}

RResult RDMACq::CreateEventCq()
{
    ibv_comp_channel *tmpCC = HcomIbv::CreateCompChannel(mRDMAContext->mContext);
    if (tmpCC == nullptr) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to create completion channel for RDMACq " << mName << ", error "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_NEW_OBJECT_FAILED;
    }

    auto tmpCQ = HcomIbv::CreateCq(mRDMAContext->mContext, static_cast<int>(mCQCount), reinterpret_cast<void *>(mWork),
        tmpCC, 0);
    if (tmpCQ == nullptr) {
        HcomIbv::DestroyCompChannel(tmpCC);
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to create completion queue for RDMACq " << mName << ", error "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_NEW_OBJECT_FAILED;
    }

    if (ibv_req_notify_cq(tmpCQ, 0) != 0) {
        HcomIbv::DestroyCompChannel(tmpCC);
        HcomIbv::DestroyCq(tmpCQ);
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to create completion queue for RDMACq " << mName << ", error "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_NEW_OBJECT_FAILED;
    }

    int flags = fcntl(tmpCC->fd, F_GETFL);
    if (fcntl(tmpCC->fd, F_SETFL, static_cast<uint32_t>(flags) | O_NONBLOCK) < 0) {
        HcomIbv::DestroyCompChannel(tmpCC);
        HcomIbv::DestroyCq(tmpCQ);
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to set no blocking for RDMACq " << mName << ", error "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_NEW_OBJECT_FAILED;
    }

    mCompletionChannel = tmpCC;
    mCompletionQueue = tmpCQ;
    return RR_OK;
}

RResult RDMACq::Initialize()
{
    NN_LOG_TRACE_INFO("RDMACq::Initialize");
    if (mCompletionQueue != nullptr) {
        return RR_OK;
    }

    if (mRDMAContext == nullptr || mRDMAContext->mContext == nullptr) {
        NN_LOG_ERROR("Failed to initialize RDMACq as rdma context is null");
        return RR_PARAM_INVALID;
    }

    if (mCreateCompletionChannel) {
        return CreateEventCq();
    } else {
        return CreatePollingCq();
    }

    NN_LOG_TRACE_INFO("RDMACq::Initialized");
    return RR_OK;
}

RResult RDMACq::UnInitialize()
{
    if (mCompletionQueue == nullptr) {
        return RR_OK;
    }

    HcomIbv::DestroyCq(mCompletionQueue);
    mCompletionQueue = nullptr;

    if (mCompletionChannel != nullptr) {
        HcomIbv::DestroyCompChannel(mCompletionChannel);
        mCompletionChannel = nullptr;
    }

    if (mRDMAContext != nullptr) {
        mRDMAContext->DecreaseRef();
        mRDMAContext = nullptr;
    }
    return RR_OK;
}

RResult RDMACq::ProgressV(struct ibv_wc *wc, int &countInOut)
{
    if (NN_UNLIKELY(mCompletionQueue == nullptr || wc == nullptr)) {
        return RR_CQ_NOT_INITIALIZED;
    }

    uint16_t times = 0;

    while (true) {
        const uint64_t traceEpoch = UBSHcomRdmaTraceEpoch();
        const uint64_t traceBegin = traceEpoch != 0 ? UBSHcomRdmaTraceNow() : 0;
        auto n = ibv_poll_cq(mCompletionQueue, countInOut, wc);
        if (traceEpoch != 0) {
            const uint64_t traceEnd = UBSHcomRdmaTraceNow();
            UBSHcomRdmaTracePoll(traceEpoch, traceBegin, traceEnd,
                reinterpret_cast<uintptr_t>(mCompletionQueue), n);
            for (int i = 0; i < n; ++i)
                UBSHcomRdmaTraceCqe(wc[i].wr_id, wc[i].qp_num, wc[i].opcode, wc[i].status);
        }
        if (NN_UNLIKELY(n < 0)) {
            NN_LOG_ERROR("Poll cq failed in RDMACq " << mName << ", errno " << errno);
            return RR_CQ_POLLING_FAILED;
        }
        if (n == 0) {
            times++;
            if (times < NN_NO10) {
                continue;
            }
        }

        countInOut = n;
        break;
    }

    return RR_OK;
}

RResult RDMACq::EventProgressV(struct ibv_wc *wc, int &countInOut, int32_t timeoutInMs)
{
    if (NN_UNLIKELY(mCompletionQueue == nullptr || mCompletionChannel == nullptr || wc == nullptr)) {
        return RR_CQ_NOT_INITIALIZED;
    }

POLL_CQ:
    auto n = ibv_poll_cq(mCompletionQueue, countInOut, wc);
    if (n < 0) {
        NN_LOG_ERROR("Poll cq failed in RDMACq " << mName << ", errno " << errno);
        return RR_CQ_POLLING_FAILED;
    } else if (n > 0) {
        countInOut = n;
        return RR_OK;
    }

    struct pollfd pollEventFd = {};
    pollEventFd.fd = mCompletionChannel->fd;
    pollEventFd.events = POLLIN;
    pollEventFd.revents = 0;
    int rc = 0;

    auto startTime = NetMonotonic::TimeMs();
    int64_t pollTime = 0;
    while (true) {
        rc = poll(&pollEventFd, 1, timeoutInMs);
        if (rc > 0) {
            break;
        }

        auto endTime = NetMonotonic::TimeMs();
        pollTime = static_cast<int64_t>(endTime - startTime);

        if (timeoutInMs >= 0 && pollTime > timeoutInMs) {
            return RR_CQ_EVENT_GET_TIMOUT;
        }

        if (rc < 0 && errno != EINTR) {
            char buf[NET_STR_ERROR_BUF_SIZE] = {0};
            NN_LOG_ERROR("Get poll event failed in RDMA Cq " << mName << ", errno "
                    << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
            return RR_CQ_EVENT_GET_FAILED;
        }
    }

    // wait request if n == 0
    void *cqContext = nullptr;
    struct ibv_cq *cqEvent = nullptr;

    // Wait for the completion event
    if (HcomIbv::GetCqEvent(mCompletionChannel, &cqEvent, &cqContext)) {
        NN_LOG_ERROR("Get cq event failed in RDMACq " << mName << ", errno " << errno);
        return RR_CQ_EVENT_GET_FAILED;
    }

    // Ack the event
    HcomIbv::AckCqEvents(cqEvent, 1);

    // Request notification upon the next completion event
    if (cqEvent != nullptr && ibv_req_notify_cq(cqEvent, 0) != 0) {
        NN_LOG_ERROR("Notify cq event failed in RDMACq " << mName << ", errno " << errno);
        return RR_CQ_EVENT_NOTIFY_FAILED;
    }

    goto POLL_CQ;
}
}
}
#endif
