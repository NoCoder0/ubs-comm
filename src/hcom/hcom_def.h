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
#ifndef OCK_HCOM_CPP_UTIL_H_34523
#define OCK_HCOM_CPP_UTIL_H_34523

#include <cstdint>
#include <iostream>
#include <sstream>

#include "hcom_num_def.h"

namespace ock {
namespace hcom {
#define NET_FLAGS_BIT(i) (1UL << (i))

constexpr const uint32_t NET_SGE_MAX_SIZE = 524288000;
constexpr const uint32_t NET_STR_ERROR_BUF_SIZE = 128;
constexpr const uint32_t NET_SGE_MAX_IOV = 30;

// enum num should less than 128
enum NET_FLAGS {
    NTH_TWO_SIDE = 0,
    NTH_TWO_SIDE_SGL = 1,
    NTH_REPLY_REQUIRED = 2,
    NTH_READ = 3,
    NTH_READ_ACK = 4,
    NTH_WRITE = 5,
    NTH_WRITE_ACK = 6,
    NTH_READ_SGL = 7,
    NTH_READ_SGL_ACK = 8,
    NTH_WRITE_SGL = 9,
    NTH_WRITE_SGL_ACK = 10
};

/* opcode specifically reserved for some operations */
enum NetPrivateOpCode {
    HB_SEND_OP = 1024,
    HB_RECV_OP = 1025,
    MR_INFO_OP = 1026,
};

#if __GNUC__ == 4 && __GNUC_MINOR__ == 8 && __GNUC_PATCHLEVEL__ == 5
template <class T, class U = T> T exchangeHcom(T &obj, U &&new_value)
{
    T old_value = std::move(obj);
    obj = std::forward<U>(new_value);
    return old_value;
}
#endif

template <typename T> class UBSHcomNetAtomicState {
public:
    explicit UBSHcomNetAtomicState(T state) : mState(state) {}

    ~UBSHcomNetAtomicState() = default;

    inline void Set(T newState)
    {
        __sync_lock_test_and_set(&mState, newState);
    }

    inline bool CAS(T oldState, T newState)
    {
        return __sync_bool_compare_and_swap(&mState, oldState, newState);
    }

    inline bool Compare(T state) const
    {
        return mState == state;
    }

    inline T Get() const
    {
        return mState;
    }

    UBSHcomNetAtomicState() = default;

    UBSHcomNetAtomicState(const UBSHcomNetAtomicState<T> &) = delete;

    UBSHcomNetAtomicState(UBSHcomNetAtomicState<T> &&) = delete;

    UBSHcomNetAtomicState<T> &operator = (const UBSHcomNetAtomicState<T> &) = delete;

    UBSHcomNetAtomicState<T> &operator = (UBSHcomNetAtomicState<T> &&) = delete;

private:
    T mState;
};

/**
 * @brief const variables
 */
const std::string CONST_EMPTY_STRING;

using NResult = int32_t;

constexpr uint16_t INVALID_WORKER_INDEX = 0xFFFF;
constexpr uint8_t INVALID_WORKER_GROUP_INDEX = 0xFF;
constexpr uint32_t INVALID_IP = 0xFFFFFFFF;

struct UBSHcomNetTransSgeIov {
    uintptr_t lAddress = 0;
    uintptr_t rAddress = 0;
    uint64_t lKey = 0;
    uint64_t rKey = 0;
    uint32_t size = 0;
    void *srcSeg;            // ptr to description of src mem seg for urma
    void *dstSeg;            // ptr to description of dst mem seg for urma

    UBSHcomNetTransSgeIov() = default;
    UBSHcomNetTransSgeIov(uintptr_t lAddress, uintptr_t rAddress, uint64_t lKey, uint64_t rKey, uint32_t size)
        : lAddress(lAddress), rAddress(rAddress), lKey(lKey), rKey(rKey), size(size),
          srcSeg(nullptr), dstSeg(nullptr) {}
    UBSHcomNetTransSgeIov(uintptr_t lAddr, uint64_t lK, uint32_t s)
        : lAddress(lAddr), lKey(lK), size(s), srcSeg(nullptr), dstSeg(nullptr) {}
} __attribute__((packed));

struct UBSHcomNetTransDataIov {
    uintptr_t address = 0;
    uint64_t key = 0;
    uint32_t size = 0;
    UBSHcomNetTransDataIov() = default;
    UBSHcomNetTransDataIov(uintptr_t address, uint64_t key, uint32_t size)
        : address(address), key(key), size(size) {}
};

/// 本类型主要用于描述存在于传输层 payload 中可能存在的额外头部，以指导服务层如
/// 何处理 payload.
enum class UBSHcomExtHeaderType : uint32_t {
    RAW = 0,   ///< 裸 payload
    FRAGMENT,  ///< SplitSend 专用的分片头，对应下方的 UBSHcomFragmentHeader
};

struct UBSHcomNetTransHeader {
    uint32_t headerCrc = 0;  // header crc code
    int16_t opCode = 0;      // user define op code, it can be 0~1023
    uint16_t flags = 0;      // flags on the header, the upper 8 bits are reserved for the user
    uint32_t seqNo = 0;      // seq no
    int16_t timeout = 0;    // timeout from client
    int16_t errorCode = 0;   // error code for response
    uint32_t dataLength = 0; // body length
    uint32_t immData = 0;    // immData
    UBSHcomExtHeaderType extHeaderType = UBSHcomExtHeaderType::RAW;  // 传输层 payload 中是否存在服务层的头部

    UBSHcomNetTransHeader() = default;

    inline void Invalid()
    {
        opCode = NN_NO1024;
        seqNo = NN_NO0;
        errorCode = NN_NO0;
        dataLength = NN_NO0;
    }
} __attribute__((packed));

/// 服务层分片头所属消息 ID
struct UBSHcomFragmentMessageId {
    uint64_t epId;   ///< endpoint ID，用来区分不同连接发送的消息
    uint64_t seqNo;  ///< endpoint 自増 seqNo，用来区分同一连接发送的不同消息

    bool operator==(const UBSHcomFragmentMessageId &rhs) const
    {
        return epId == rhs.epId && seqNo == rhs.seqNo;
    }

    bool operator<(const UBSHcomFragmentMessageId &rhs) const
    {
        return epId != rhs.epId ? epId < rhs.epId : seqNo < rhs.seqNo;
    }

    friend std::ostream &operator<<(std::ostream &os, const UBSHcomFragmentMessageId &rhs)
    {
        return os << "(" << rhs.epId << " " << rhs.seqNo << ")";
    }
};

/// 服务层分片头，当服务层一次性发送数据大小超过单个 MemoryRegion 容量时，需要记
/// 录单个 fragment 信息以供接收端恢复.
struct UBSHcomFragmentHeader {
    UBSHcomFragmentMessageId msgId;  ///< 分片所属原消息 ID
    uint32_t totalLength;     ///< 原消息总大小，接收端在收到分片时会首先分配 totalLength 大小的内存
    uint32_t offset;          ///< 分片在原消息中的偏移
} __attribute__((packed));

/**
 * @brief Worker index
 */
union UBSHcomNetWorkerIndex {
    struct {
        uint32_t idxInGrp : 16; /* index in one worker group */
        uint32_t grpIdx : 8;    /* index of the group in the net driver */
        uint32_t driverIdx : 8; /* index of the net driver in one process */
    };
    uint32_t wholeIdx = 0;

    void Set(uint32_t idx, uint32_t gIdx, uint16_t dIdx)
    {
        idxInGrp = idx;
        grpIdx = gIdx;
        driverIdx = dIdx;
    }

    std::string ToString() const
    {
        std::ostringstream oss;
        oss << driverIdx << "-" << grpIdx << "-" << idxInGrp;
        return oss.str();
    }
};

/**
 * @brief Device information for user
 */
struct UBSHcomNetDriverDeviceInfo {
    int maxSge = NN_NO4; // max iov count in UBSHcomNetTransSglRequest
} __attribute__((packed));

/**
 * @brief macros
 */
//  macro for reference count
#ifndef DEFINE_RDMA_REF_COUNT_FUNCTIONS
#define DEFINE_RDMA_REF_COUNT_FUNCTIONS                    \
public:                                                    \
    inline void IncreaseRef()                              \
    {                                                      \
        __sync_fetch_and_add(&mRefCount, 1);               \
    }                                                      \
                                                           \
    inline void DecreaseRef()                              \
    {                                                      \
        int32_t tmp = __sync_sub_and_fetch(&mRefCount, 1); \
        if (tmp == 0) {                                    \
            delete this;                                   \
        }                                                  \
    }                                                      \
                                                           \
    inline int32_t GetRef()                                \
    {                                                      \
        return __sync_sub_and_fetch(&mRefCount, 0);        \
    }
#endif

#ifndef DEFINE_RDMA_REF_COUNT_VARIABLE
#define DEFINE_RDMA_REF_COUNT_VARIABLE \
private:                               \
    int32_t mRefCount = 0
#endif

// macro for gcc optimization for prediction of if/else
#ifndef NN_LIKELY
#define NN_LIKELY(x) (__builtin_expect(!!(x), 1) != 0)
#endif

#ifndef NN_UNLIKELY
#define NN_UNLIKELY(x) (__builtin_expect(!!(x), 0) != 0)
#endif

// macro for flag
#define NN_FLAGS_BIT(i) (1UL << (i))
}
}

#endif // OCK_HCOM_CPP_UTIL_H_34523
