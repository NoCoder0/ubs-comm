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
#ifndef OCK_RDMA_COMMON_1234234341233_H
#define OCK_RDMA_COMMON_1234234341233_H
#ifdef RDMA_BUILD_ENABLED

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <strings.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "hcom_def.h"
#include "hcom_log.h"
#include "net_common.h"
#include "net_obj_pool.h"
#include "verbs_api_wrapper.h"

namespace ock {
namespace hcom {
/*
 * return type
 */
using RResult = int;

enum RRCode {
    RR_OK = 0,
    RR_PARAM_INVALID = 200,
    RR_MEMORY_ALLOCATE_FAILED = 201,
    RR_NEW_OBJECT_FAILED = 202,
    RR_OPEN_FILE_FAILED = 203,
    RR_READ_FILE_FAILED = 204,
    RR_DEVICE_FAILED_OPEN = 205,
    RR_DEVICE_INDEX_OVERFLOW = 206,
    RR_DEVICE_OPEN_FAILED = 207,
    RR_DEVICE_FAILED_GET_IF_ADDRESS = 208,
    RR_DEVICE_NO_IF_MATCHED = 209,
    RR_DEVICE_NO_IF_TO_GID_MATCHED = 210,
    RR_DEVICE_INVALID_IP_MASK = 211,
    RR_MR_REG_FAILED = 212,
    RR_CQ_NOT_INITIALIZED = 213,
    RR_CQ_POLLING_FAILED = 214,
    RR_CQ_POLLING_TIMEOUT = 215,
    RR_CQ_POLLING_ERROR_RESULT = 216,
    RR_CQ_POLLING_UNMATCHED_OPCODE = 217,
    RR_CQ_EVENT_GET_FAILED = 218,
    RR_CQ_EVENT_NOTIFY_FAILED = 219,
    RR_CQ_WC_WRONG = 220,
    RR_CQ_EVENT_GET_TIMOUT = 221,
    RR_QP_CREATE_FAILED = 222,
    RR_QP_NOT_INITIALIZED = 223,
    RR_QP_CHANGE_STATE_FAILED = 224,
    RR_QP_POST_RECEIVE_FAILED = 225,
    RR_QP_POST_SEND_FAILED = 226,
    RR_QP_POST_READ_FAILED = 227,
    RR_QP_POST_WRITE_FAILED = 228,
    RR_QP_RECEIVE_CONFIG_ERR = 229,
    RR_QP_POST_SEND_WR_FULL = 230,
    RR_QP_ONE_SIDE_WR_FULL = 231,
    RR_QP_CTX_FULL = 232,
    RR_QP_CHANGE_ERR = 233,
    RR_OOB_LISTEN_SOCKET_ERROR = 234,
    RR_OOB_CONN_SEND_ERROR = 235,
    RR_OOB_CONN_RECEIVE_ERROR = 236,
    RR_OOB_CONN_CB_NOT_SET = 237,
    RR_OOB_CLIENT_SOCKET_ERROR = 238,
    RR_OOB_SSL_INIT_ERROR = 239,
    RR_OOB_SSL_WRITE_ERROR = 240,
    RR_OOB_SSL_READ_ERROR = 241,
    RR_EP_NOT_INITIALIZED = 242,
    RR_WORKER_NOT_INITIALIZED = 243,
    RR_WORKER_BIND_CPU_FAILED = 244,
    RR_WORKER_REQUEST_HANDLER_NOT_SET = 245,
    RR_WORKER_SEND_POSTED_HANDLER_NOT_SET = 246,
    RR_WORKER_ONE_SIDE_DONE_HANDLER_NOT_SET = 247,
    RR_WORKER_FAILED_ADD_QP = 248,
    RR_HEARTBEAT_CREATE_EPOLL_FAILED = 249,
    RR_HEARTBEAT_SET_SOCKET_OPT_FAILED = 250,
    RR_HEARTBEAT_IP_ALREADY_EXISTED = 251,
    RR_HEARTBEAT_IP_ADD_FAILED = 252,
    RR_HEARTBEAT_IP_ADD_EPOLL_FAILED = 253,
    RR_HEARTBEAT_IP_REMOVE_EPOLL_FAILED = 254,
    RR_HEARTBEAT_IP_NO_FOUND = 255,
    RR_WORKER_START_ERROR = 256,
};

// constant variable
constexpr uint32_t QP_MAX_SEND_WR = 256;
constexpr uint32_t QP_MAX_RECV_WR = 256;
constexpr uint32_t QP_MIN_RNR_TIMER = 12;
constexpr uint32_t QP_TIMEOUT = 14;
constexpr uint32_t QP_RETRY_COUNT = 7;
constexpr uint32_t QP_RNR_RETRY = 7;
constexpr uint32_t CQ_COUNT = 1024;
constexpr uint32_t QP_MAX_BATCH_RETURN_WR_SIZE = 64;

const std::string RDMA_EMPTY_STRING;

/*
 * class forward declaration
 */

class RDMAMemoryRegionFixedBuffer;

// verbs wrappers
class RDMADeviceHelper;
class RDMAContext;
class RDMAQp;
class RDMACq;
class RDMAMemoryRegion;

// logic part
class RDMAWorker;

// oob for qp setup
class OOBTCPConnection;
class OOBTCPServer;
class OOBTCPClient;

// the size of RDMAOpContextInfo is 64 bytes which fit to single CPU cache line
struct RDMAOpContextInfo {
    enum OpType : uint8_t {
        SEND = 0,
        SEND_RAW = 1,
        SEND_RAW_SGL = 2,
        RECEIVE = 3,
        RECEIVE_RAW = 4,
        WRITE = 5,
        READ = 6,
        SGL_WRITE = 7,
        SGL_READ = 8,
        HB_WRITE = 9,
        SEND_SGL_INLINE = 10,
        SEND_RAW_NO_CP = 11,
    };

    enum OpResultType : uint8_t {
        SUCCESS = 0,
        ERR_TIMEOUT = 1,
        ERR_CANCELED = 2,
        ERR_IO_ERROR = 3,
        ERR_EP_BROKEN = 4,
        ERR_EP_CLOSE = 5,

        INVALID_MAGIC = 0xFF,
    };

    enum MrType : uint8_t {
        MR = 2
    };

    RDMAQp      *qp = nullptr;                         /* pointer to qp */
    struct RDMAOpContextInfo *prev = nullptr;          /* link to prev context */
    struct RDMAOpContextInfo *next = nullptr;          /* link to next context */

    union {
        uintptr_t whole = 0;
        struct {
            /* low address */
            /* address of the buffer, the uintptr_t has 64 bits, only the low 48 bits would be used for address */
            uintptr_t mrMemAddr : 56;
            /* high address */
            MrType mrType : 8;
        };
    } __attribute__((packed));
    uint32_t lKey = 0;                                 /* local key */
    uint32_t dataSize = 0;                             /* actual data size */
    uint32_t qpNum = 0;                                /* qp ID */
    OpType opType = RECEIVE;                           /* op type */
    OpResultType opResultType = OpResultType::SUCCESS; /* op result */
    uint16_t upCtxSize = 0;                            /* up context size stored in upCtx[] */
    char upCtx[NN_NO16] = {};                          /* 16 bytes for upper context */

    static inline OpResultType OpResult(struct ibv_wc &result)
    {
        // any status except success indicating the qp is abnormal
        switch (result.status) {
            case IBV_WC_SUCCESS:
                return OpResultType::SUCCESS;
            case IBV_WC_RETRY_EXC_ERR:
            case IBV_WC_RNR_RETRY_EXC_ERR:
                return OpResultType::ERR_TIMEOUT;
            case IBV_WC_WR_FLUSH_ERR:
                return OpResultType::ERR_CANCELED;
            default:
                return OpResultType::ERR_IO_ERROR;
        }
    }

    static inline NResult GetNResult(OpResultType opResult)
    {
        switch (opResult) {
            case OpResultType::SUCCESS:
                return NN_OK;
            case OpResultType::ERR_TIMEOUT:
                return NN_MSG_TIMEOUT;
            case OpResultType::ERR_CANCELED:
                return NN_MSG_CANCELED;
            case OpResultType::ERR_EP_BROKEN:
                return NN_EP_BROKEN;
            case OpResultType::ERR_EP_CLOSE:
                return NN_EP_CLOSE;
            default:
                return NN_MSG_ERROR;
        }
    }
} __attribute__((packed));

struct RDMASglContextInfo {
    RDMAQp *qp = nullptr; // the qp pointer which posted from
    UBSHcomNetTransSgeIov iov[NET_SGE_MAX_IOV] = {};
    NResult result = NN_OK;
    uint32_t reserve1 = 0;
    uint16_t refCount = 0; // equal to iovCount
    uint16_t iovCount = 0; // max count:NN_NO16
    uint16_t upCtxSize = 0;
    uint16_t reserve2 = 0;
    char upCtx[NN_NO16] = {}; // 16 bytes for upper context
} __attribute__((packed));

struct RDMASgeCtxInfo {
    RDMASglContextInfo *ctx = nullptr;
    uint16_t idx = 0;    /* 该 WR/组的起始 iov 下标 */
    uint16_t count = 1;  /* 该 WR 覆盖的 iov 数(多SGE合并时>1，否则=1) */

    RDMASgeCtxInfo() = default;
    explicit RDMASgeCtxInfo(RDMASglContextInfo *sglCtx) : ctx(sglCtx) {}
} __attribute__((packed));

enum RDMAPollingMode : uint8_t {
    BUSY_POLLING = 0,
    EVENT_POLLING = 1,
};

struct QpOptions {
    uint32_t maxSendWr = QP_MAX_SEND_WR;
    uint32_t maxReceiveWr = QP_MAX_RECV_WR;
    uint32_t mrSegSize = NN_NO1024;
    uint32_t mrSegCount = NN_NO64;

    QpOptions() = default;

    QpOptions(uint32_t maxSendWrNum, uint32_t maxReceiveWrNum, uint32_t segSize, uint32_t segCount)
        : maxSendWr(maxSendWrNum), maxReceiveWr(maxReceiveWrNum), mrSegSize(segSize), mrSegCount(segCount)
    {}
} __attribute__((packed));

inline RResult ReadRoCEVersionFromFile(const std::string &deviceName, uint32_t portNumber, uint32_t gid,
    std::string &version)
{
    std::ostringstream oSStream;
    char filePath[PATH_MAX] = {0};
    oSStream << "/sys/class/infiniband/" << deviceName.c_str() << "/ports/" << portNumber << "/gid_attrs/types/" << gid;
    if (oSStream.str().length() > IBV_SYSFS_PATH_MAX || nullptr == realpath(oSStream.str().c_str(), filePath)) {
        NN_LOG_ERROR("The file name is incorrect");
        return RR_PARAM_INVALID;
    }

    char fileContent[64] = {0};
    int fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to open file " << oSStream.str() << ", error "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_OPEN_FILE_FAILED;
    }

    auto len = read(fd, fileContent, 15);
    if (len < 0) {
        close(fd);
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to read content file " << oSStream.str() << ", error "
                << NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return RR_READ_FILE_FAILED;
    }

    if (len > 1 && fileContent[len - 1] == '\n') {
        version = std::string(fileContent, len - 1);
    } else {
        version = std::string(fileContent, len);
    }

    close(fd);
    return RR_OK;
}
}
}
#endif
#endif // OCK_RDMA_COMMON_1234234341233_H
