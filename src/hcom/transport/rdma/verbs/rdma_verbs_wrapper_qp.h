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

#ifndef HCOM_RDMA_VERBS_WRAPPER_QP_H
#define HCOM_RDMA_VERBS_WRAPPER_QP_H
#ifdef RDMA_BUILD_ENABLED
#include <unistd.h>
#include <algorithm>
#include <string>

#include "hcom_env.h"
#include "hcom_rdma_trace.h"
#include "rdma_mr_fixed_buf.h"
#include "rdma_verbs_wrapper_cq.h"

namespace ock {
namespace hcom {
struct RDMAQpExchangeInfo {
    uint32_t lid = 0;
    uint32_t qpn = 0;
    union ibv_gid gid {};
    uintptr_t hbAddress = 0;
    uint32_t hbKey = 0;
    uint64_t hbMrSize = 0;
    uint32_t maxSendWr = QP_MAX_SEND_WR;
    uint32_t maxReceiveWr = QP_MAX_RECV_WR;
    uint32_t receiveSegSize = NN_NO1024;
    uint32_t receiveSegCount = NN_NO64;
} __attribute__((packed));

class RDMAQp {
public:
    RDMAQp(const std::string &name, uint32_t id, RDMAContext *ctx, RDMACq *cq, QpOptions qpOptions = {})
        : mName(name), mId(id), mRDMAContext(ctx), mSendCQ(cq), mRecvCQ(cq), mQpOptions(qpOptions)
    {
        if (mRDMAContext != nullptr) {
            mRDMAContext->IncreaseRef();
        }

        if (mSendCQ != nullptr) {
            mSendCQ->IncreaseRef();
        }
        OBJ_GC_INCREASE(RDMAQp);
    }

    RDMAQp(uint32_t id, RDMAContext *ctx, RDMACq *sendCq, RDMACq *receiveCq, QpOptions qpOptions)
        : mId(id), mRDMAContext(ctx), mSendCQ(sendCq), mRecvCQ(receiveCq), mQpOptions(qpOptions)
    {
        if (mRDMAContext != nullptr) {
            mRDMAContext->IncreaseRef();
        }

        if (mSendCQ != nullptr) {
            mSendCQ->IncreaseRef();
        }

        if (mRecvCQ != nullptr && mRecvCQ != mSendCQ) {
            mRecvCQ->IncreaseRef();
        }
        OBJ_GC_INCREASE(RDMAQp);
    }

    virtual ~RDMAQp()
    {
        UnInitialize();
        OBJ_GC_DECREASE(RDMAQp);
    }

    RResult CreateIbvQp();
    RResult CreateQpMr();

    /* call ibv_create_qp to create real QP */
    RResult Initialize();
    RResult UnInitialize();

    /*
    exchange information needs to be transformed by other channel (e.g. tcp connection)
    1 firstly do the initialization
    2 got qp exchange info from peer
    3 call this function to change qp state to ready state (INIT & RTS & RTR)
    */
    RResult ChangeToReady(RDMAQpExchangeInfo &exInfo);

    /* after qp initialized, retrieve the qp qp_num for exchange */
    RResult GetExchangeInfo(RDMAQpExchangeInfo &exInfo);

    inline RResult PostReceive(uintptr_t bufAddr, uint32_t bufSize, uint32_t localKey, uint64_t context)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        struct ibv_recv_wr *badWR;
        struct ibv_sge list {
            bufAddr, bufSize, localKey
        };

        struct ibv_recv_wr wr {};
        wr.wr_id = context;
        wr.sg_list = &list;
        wr.num_sge = 1;
        wr.next = nullptr;

        auto result = ibv_post_recv(mQP, &wr, &badWR);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post receive request to qp " << mName << ", result " << result);
            return RR_QP_POST_RECEIVE_FAILED;
        }
        return RR_OK;
    }

    inline RResult BatchPostReceive(RDMAOpContextInfo *ctx, uint16_t batchSize, uint32_t size)
    {
        if (NN_UNLIKELY(mQP == nullptr || batchSize <= 0)) {
            return RR_QP_NOT_INITIALIZED;
        }

        std::vector<ibv_sge> sges(batchSize);
        std::vector<ibv_recv_wr> wrs(batchSize);

        for (int i = 0; i < batchSize; ++i) {
            auto delayCtx = ctx->qp->mDelayList[i];
            ctx->qp->AddOpCtxInfo(delayCtx);

            sges[i].addr = delayCtx->mrMemAddr;
            sges[i].length = size;
            sges[i].lkey = static_cast<uint32_t>(ctx->lKey);

            wrs[i].wr_id = reinterpret_cast<uint64_t>(delayCtx);
            wrs[i].sg_list = &sges[i];
            wrs[i].num_sge = 1;
            wrs[i].next = (i == batchSize - 1) ? nullptr : &wrs[i + 1];
        }

        struct ibv_recv_wr *bad_wr;
        int result = ibv_post_recv(mQP, &wrs[0], &bad_wr);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("BatchPostReceive failed on qp " << mName << ", result=" << result << " (errno: " <<
                strerror(result) << ")");
            return RR_QP_POST_RECEIVE_FAILED;
        }
        return RR_OK;
    }

    inline RResult PostSend(uintptr_t bufAddr, uint32_t bufSize, uint32_t localKey, uint64_t context,
        uint32_t immData = 0)
    {
        NN_LOG_TRACE_INFO("Post send addr " << bufAddr << ", size " << bufSize << ", lkey " << localKey <<
            ", context " << context);
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        struct ibv_send_wr *badWR;
        struct ibv_sge list {
            bufAddr, bufSize, localKey
        };

        struct ibv_send_wr wr {};
        wr.sg_list = &list;
        wr.wr_id = context;
        wr.num_sge = 1;
        wr.next = nullptr;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.opcode = IBV_WR_SEND_WITH_IMM;
        /*
         * case 1: immData == 0, send header then user's data
         * case 2: immData != 0, send user's data only
         */
        wr.imm_data = immData;

        auto result = ibv_post_send(mQP, &wr, &badWR);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post send request to qp " << mName << ", result " << result);
            return RR_QP_POST_SEND_FAILED;
        }

        return RR_OK;
    }

    inline RResult PostSendSglInline(UBSHcomNetTransDataIov *iov, uint32_t iovCount, uint64_t context,
        uint32_t immData = 0)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        struct ibv_send_wr *badWR;
        struct ibv_sge list[NET_SGE_MAX_IOV] = {};
        for (uint32_t i = 0; i < iovCount; i++) {
            list[i].addr = iov[i].address;
            list[i].length = iov[i].size;
            list[i].lkey = static_cast<uint32_t>(iov[i].key);
        }

        struct ibv_send_wr wr {};
        wr.wr_id = context;
        wr.sg_list = list;
        wr.num_sge = static_cast<int>(iovCount);
        wr.next = nullptr;
        wr.opcode = IBV_WR_SEND_WITH_IMM;
        wr.send_flags = IBV_SEND_INLINE | IBV_SEND_SIGNALED;
        /*
         * case 1: immData == 0, send header then user's data
         * case 2: immData != 0, send user's data only
         */
        wr.imm_data = immData;

        auto result = ibv_post_send(mQP, &wr, &badWR);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post send request to qp " << mName << ", result " << result);
            return RR_QP_POST_SEND_FAILED;
        }

        return RR_OK;
    }

    inline RResult PostSendSgl(UBSHcomNetTransSgeIov *iov, uint32_t iovCount, uint64_t context, uint32_t immData = 0)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        struct ibv_send_wr *badWR;
        struct ibv_sge list[NET_SGE_MAX_IOV] = {};
        for (uint32_t i = 0; i < iovCount; i++) {
            list[i].addr = iov[i].lAddress;
            list[i].length = iov[i].size;
            list[i].lkey = static_cast<uint32_t>(iov[i].lKey);
        }

        struct ibv_send_wr wr {};
        wr.wr_id = context;
        wr.sg_list = list;
        wr.num_sge = static_cast<int>(iovCount);
        wr.next = nullptr;
        wr.opcode = IBV_WR_SEND_WITH_IMM;
        wr.send_flags = IBV_SEND_SIGNALED;
        /*
         * case 1: immData == 0, send header then user's data
         * case 2: immData != 0, send user's data only
         */
        wr.imm_data = immData;

        auto result = ibv_post_send(mQP, &wr, &badWR);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post send request to qp " << mName << ", result " << result);
            return RR_QP_POST_SEND_FAILED;
        }

        return RR_OK;
    }

    inline RResult PostOneSideSgl(UBSHcomNetTransSgeIov *iov, uint32_t iovCount,
        uint64_t (&context)[NET_SGE_MAX_IOV], bool isRead)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        struct ibv_send_wr *badWR;
        struct ibv_send_wr wrList[NET_SGE_MAX_IOV] = {};
        struct ibv_sge list[NET_SGE_MAX_IOV] = {};
        for (uint32_t i = 0; i < iovCount; i++) {
            list[i].addr = iov[i].lAddress;
            list[i].length = iov[i].size;
            list[i].lkey = static_cast<uint32_t>(iov[i].lKey);

            auto &wr = wrList[i];
            wr.wr_id = context[i];
            wr.num_sge = 1;
            wr.sg_list = &list[i];
            wr.send_flags = IBV_SEND_SIGNALED;
            wr.opcode = isRead ? IBV_WR_RDMA_READ : IBV_WR_RDMA_WRITE;
            wr.imm_data = 0;
            wr.next = (i + 1 == iovCount) ? nullptr : &wrList[i + 1];
            wr.wr.rdma.remote_addr = iov[i].rAddress;
            wr.wr.rdma.rkey = static_cast<uint32_t>(iov[i].rKey);
        }

        auto result = ibv_post_send(mQP, wrList, &badWR);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post oneSide request to qp " << mName << ", result " << result);
            return isRead ? RR_QP_POST_READ_FAILED : RR_QP_POST_WRITE_FAILED;
        }

        return RR_OK;
    }

    /* 多 SGE 版本：组内 iov（同 rkey 且远端地址连续）合并为一个 WR(多个本地 SGE)，
       一个 WR 一个完成项，覆盖 groupLen[g] 个 iov。仅供 worker/OOB async 路径使用，
       原 PostOneSideSgl 保持不变供 composed/sync 等路径使用。 */
    inline RResult PostOneSideSglGrouped(UBSHcomNetTransSgeIov *iov, uint32_t groupCount,
        const uint32_t *groupBegin, const uint32_t *groupLen, uint64_t (&context)[NET_SGE_MAX_IOV], bool isRead)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }
        if (NN_UNLIKELY(iov == nullptr || groupBegin == nullptr || groupLen == nullptr || groupCount == 0 ||
            groupCount > NET_SGE_MAX_IOV)) {
            NN_LOG_ERROR("Failed to post oneSide grouped request to qp " << mName
                                                                         << " as param invalid, groupCount "
                                                                         << groupCount);
            return RR_PARAM_INVALID;
        }

        struct ibv_send_wr *badWR = nullptr;
        struct ibv_send_wr wrList[NET_SGE_MAX_IOV] = {};
        struct ibv_sge sgeStore[NET_SGE_MAX_IOV][NET_SGE_MAX_IOV] = {};
        for (uint32_t g = 0; g < groupCount; ++g) {
            uint32_t begin = groupBegin[g];
            uint32_t num = groupLen[g];
            if (NN_UNLIKELY(num == 0 || begin + num > NET_SGE_MAX_IOV)) {
                NN_LOG_ERROR("Failed to post oneSide grouped request to qp " << mName << " as group " << g
                                                                            << " invalid, begin " << begin
                                                                            << " num " << num);
                return RR_PARAM_INVALID;
            }
            for (uint32_t k = 0; k < num; ++k) {
                sgeStore[g][k].addr = iov[begin + k].lAddress;
                sgeStore[g][k].length = iov[begin + k].size;
                sgeStore[g][k].lkey = static_cast<uint32_t>(iov[begin + k].lKey);
            }
            auto &wr = wrList[g];
            wr.wr_id = context[g];
            wr.sg_list = &sgeStore[g][0];
            wr.num_sge = static_cast<int>(num);
            wr.send_flags = IBV_SEND_SIGNALED;
            wr.opcode = isRead ? IBV_WR_RDMA_READ : IBV_WR_RDMA_WRITE;
            wr.imm_data = 0;
            wr.next = (g + 1 == groupCount) ? nullptr : &wrList[g + 1];
            /* 一个 WR 只能写一段连续远端：远端地址取组首，rkey 组内相同 */
            wr.wr.rdma.remote_addr = iov[begin].rAddress;
            wr.wr.rdma.rkey = static_cast<uint32_t>(iov[begin].rKey);
        }

        const uint64_t traceEpoch = UBSHcomRdmaTraceEpoch();
        const uint64_t traceBegin = traceEpoch != 0 ? UBSHcomRdmaTraceNow() : 0;
        auto result = ibv_post_send(mQP, wrList, &badWR);
        if (traceEpoch != 0) {
            const uint64_t traceEnd = UBSHcomRdmaTraceNow();
            for (uint32_t g = 0; g < groupCount; ++g) {
                uint64_t bytes = 0;
                for (uint32_t k = 0; k < groupLen[g]; ++k) bytes += sgeStore[g][k].length;
                // Only stack-owned WR metadata is read here. The completion
                // worker may already have freed the object identified by wr_id.
                UBSHcomRdmaTracePost(traceEpoch, traceBegin, traceEnd, mQP->qp_num,
                    wrList[g].wr_id, wrList[g].opcode, groupLen[g], bytes, result);
            }
        }
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post oneSide grouped request to qp " << mName << ", result " << result);
            return isRead ? RR_QP_POST_READ_FAILED : RR_QP_POST_WRITE_FAILED;
        }
        return RR_OK;
    }

    inline RResult PostRead(uintptr_t bufAddr, uint32_t localKey, uintptr_t remoteBufAddr, uint32_t remoteKey,
        uint32_t bufSize, uint64_t context)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        struct ibv_send_wr *badWR;
        struct ibv_sge list {
            bufAddr, bufSize, localKey
        };

        struct ibv_send_wr wr {};
        wr.sg_list = &list;
        wr.num_sge = 1;
        wr.next = nullptr;
        wr.wr_id = context;
        wr.opcode = IBV_WR_RDMA_READ;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.wr.rdma.remote_addr = remoteBufAddr;
        wr.wr.rdma.rkey = remoteKey;

        auto result = ibv_post_send(mQP, &wr, &badWR);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post read request to qp " << mName << ", result " << result);
            return RR_QP_POST_READ_FAILED;
        }

        return RR_OK;
    }

    inline RResult PostWrite(uintptr_t bufAddr, uint32_t localKey, uintptr_t remoteBufAddr, uint32_t remoteKey,
        uint32_t bufSize, uint64_t context)
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return RR_QP_NOT_INITIALIZED;
        }

        struct ibv_send_wr *badWR;
        struct ibv_sge list {
            bufAddr, bufSize, localKey
        };

        struct ibv_send_wr wr {};
        wr.wr_id = context;
        wr.sg_list = &list;
        wr.num_sge = 1;
        wr.next = nullptr;
        wr.opcode = IBV_WR_RDMA_WRITE;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.wr.rdma.remote_addr = remoteBufAddr;
        wr.wr.rdma.rkey = remoteKey;

        auto result = ibv_post_send(mQP, &wr, &badWR);
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to post write request to qp " << mName << ", result " << result);
            return RR_QP_POST_WRITE_FAILED;
        }

        return RR_OK;
    }

    inline uint32_t Id() const
    {
        return mId;
    }

    inline void UpId(uint64_t id)
    {
        mUpId = id;
    }

    inline uint64_t UpId() const
    {
        return mUpId;
    }

    inline const std::string &Name() const
    {
        return mName;
    }

    inline void Name(const std::string &value)
    {
        mName = value;
    }

    inline const std::string &PeerIpAndPort() const
    {
        return mPeerIpPort;
    }

    inline void PeerIpAndPort(const std::string &value)
    {
        mPeerIpPort = value;
    }

    inline uint32_t PostSendMaxSize() const
    {
        return mPostSendMaxSize;
    }

    inline uint8_t PortNum() const
    {
        return mRDMAContext->mPortNumber;
    }

    inline void UpContext(uintptr_t ctx)
    {
        mUpContext = ctx;
    }

    inline uintptr_t UpContext() const
    {
        return mUpContext;
    }

    inline void UpContext1(uintptr_t ctx)
    {
        mUpContext1 = ctx;
    }

    inline uintptr_t UpContext1() const
    {
        return mUpContext1;
    }

    bool GetFreeBuff(uintptr_t &item);
    bool ReturnBuffer(uintptr_t value);
    bool GetFreeBufferN(uintptr_t *&items, uint32_t n);
    uint32_t GetLKey();

    inline void AddOpCtxInfo(RDMAOpContextInfo *verbsCtxInfo)
    {
        if (NN_LIKELY(verbsCtxInfo != nullptr)) {
            // bi-direction linked list, 4 step to insert to head
            verbsCtxInfo->prev = &mCtxPosted;
            mLock.Lock();
            // head -><- first -><- second -><- third -> nullptr
            // insert into the head place
            verbsCtxInfo->next = mCtxPosted.next;
            if (mCtxPosted.next != nullptr) {
                mCtxPosted.next->prev = verbsCtxInfo;
            }
            mCtxPosted.next = verbsCtxInfo;
            ++mCtxPostedCount;
            mLock.Unlock();
        }
    }

    inline void RemoveOpCtxInfo(RDMAOpContextInfo *ctxInfo)
    {
        if (NN_LIKELY(ctxInfo != nullptr)) {
            // bi-direction linked list, 4 step to remove one
            mLock.Lock();

            // repeat remove
            if (ctxInfo->prev == nullptr) {
                mLock.Unlock();
                return;
            }

            // head-><- first -><- second -><- third -> nullptr
            ctxInfo->prev->next = ctxInfo->next;
            if (ctxInfo->next != nullptr) {
                ctxInfo->next->prev = ctxInfo->prev;
            }
            --mCtxPostedCount;

            ctxInfo->prev = nullptr;
            ctxInfo->next = nullptr;
            mLock.Unlock();
        }
    }

    // need to call this when qp broken, to get these contexts to return mrs
    inline void GetCtxPosted(RDMAOpContextInfo *&remaining)
    {
        mLock.Lock();
        // head -> first -><- second -><- third -> nullptr
        remaining = mCtxPosted.next;
        mCtxPosted.next = nullptr;
        mCtxPostedCount = 0;
        mLock.Unlock();
    }

    /// 获取所有提交至 QP 队列中的任务个数，总数为 PostReceive + PostSend 族函数
    /// 的和。因为 RDMA 有 prePostReceive 机制，所以它的值一般会大于等于
    /// prePostReceiveSizePerQP 的值。
    /// \see prePostReceiveSizePerQP
    inline uint32_t GetPostedCount()
    {
        mLock.Lock();
        auto tmp = mCtxPostedCount;
        mLock.Unlock();
        return tmp;
    }

    /// 获取 QP 发送队列的长度。
    inline uint32_t GetSendQueueSize()
    {
        int32_t ref = __sync_fetch_and_add(&mPostSendRef, 0);
        ref = std::max(0, std::min(ref, mPostSendMaxWr));
        return static_cast<uint32_t>(mPostSendMaxWr - ref);
    }

    inline bool GetPostSendWr(uint32_t times = NN_NO8, uint32_t sleepUs = NN_NO64)
    {
        while (times-- > 0) {
            if (NN_LIKELY(__sync_sub_and_fetch(&mPostSendRef, 1) >= 0)) {
                return true;
            }
            __sync_add_and_fetch(&mPostSendRef, 1);
            usleep(sleepUs);
        }
        return false;
    }

    inline void ReturnPostSendWr()
    {
        int32_t ref = __sync_add_and_fetch(&mPostSendRef, 1);
        if (ref > mPostSendMaxWr) {
            NN_LOG_WARN("[RDMA] Posted send requests " << ref << " over capacity " << mPostSendMaxWr);
        }
    }

    inline bool GetOneSideWr(uint32_t times = NN_NO8, uint32_t sleepUs = NN_NO64)
    {
        while (times-- > 0) {
            if (NN_LIKELY(__sync_sub_and_fetch(&mOneSideRef, 1) >= 0)) {
                return true;
            }
            __sync_add_and_fetch(&mOneSideRef, 1);
            usleep(sleepUs);
        }
        return false;
    }

    inline void ReturnOneSideWr()
    {
        int32_t ref = __sync_add_and_fetch(&mOneSideRef, 1);
        if (ref > mOneSideMaxWr) {
            NN_LOG_WARN("[RDMA] Posted one side requests " << ref << " over capacity " << mOneSideMaxWr);
        }
    }

    DEFINE_RDMA_REF_COUNT_FUNCTIONS

public:
    static uint32_t NewId()
    {
        return __sync_fetch_and_add(&G_INDEX, 1);
    }

    inline uint32_t QpNum() const
    {
        if (NN_UNLIKELY(mQP == nullptr)) {
            return 0xffffffff;
        }

        return mQP->qp_num;
    }

    inline uint32_t PostRegMrSize() const
    {
        return mQpOptions.mrSegSize;
    }

    inline RResult Stop()
    {
        if (!isStarted || mQP == nullptr) {
            return RR_OK;
        }

        struct ibv_qp_attr attr = {};
        attr.qp_state = IBV_QPS_ERR;
        auto result = HcomIbv::ModifyQp(mQP, &attr, IBV_QP_STATE);
        if (result != 0) {
            char buf[NET_STR_ERROR_BUF_SIZE] = {0};
            NN_LOG_ERROR("Failed to modify QP state to ERR " << result << ", as " <<
                NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
            return RR_QP_CHANGE_ERR;
        }

        isStarted = false;
        return RR_OK;
    }

private:
    RResult ChangeToInit(struct ibv_qp_attr &attr);
    RResult ChangeToReceive(RDMAQpExchangeInfo &exInfo, struct ibv_qp_attr &attr);
    RResult ChangeToSend(struct ibv_qp_attr &attr);
    RResult SetMaxSendWrConfig(RDMAQpExchangeInfo &exInfo);

    std::string mName;
    std::string mPeerIpPort;
    uint32_t mId = 0;
    uint64_t mUpId = 0;
    bool isStarted = false;

    RDMAContext *mRDMAContext = nullptr;
    RDMACq *mSendCQ = nullptr;
    RDMACq *mRecvCQ = nullptr;
    QpOptions mQpOptions {};
    ibv_qp *mQP = nullptr;
    uintptr_t mUpContext = 0;
    uintptr_t mUpContext1 = 0;
    NetSpinLock mLock;
    RDMAOpContextInfo mCtxPosted {};
    uint32_t mCtxPostedCount { 0 };
    RDMAMemoryRegionFixedBuffer *mQpMr = nullptr;

    int32_t mOneSideMaxWr = QP_MAX_SEND_WR - NN_NO64;
    int32_t mOneSideRef = QP_MAX_SEND_WR - NN_NO64;
    int32_t mPostSendMaxWr = NN_NO64;
    uint32_t mPostSendMaxSize = NN_NO1024;
    int32_t mPostSendRef = NN_NO64;
    // delay batch return wr
    std::atomic<uint16_t> mDelayNum { 0 };
    struct RDMAOpContextInfo *mDelayList[QP_MAX_BATCH_RETURN_WR_SIZE];
    DEFINE_RDMA_REF_COUNT_VARIABLE;

    static uint32_t G_INDEX;

    friend class RDMAWorker;
};
}
}
#endif
#endif // HCOM_RDMA_VERBS_WRAPPER_QP_H
