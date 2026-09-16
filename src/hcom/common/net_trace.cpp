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
#include "net_trace.h"
#include "net_common.h"

namespace ock {
namespace hcom {
static const char *g_idToString[] = {
    "SERVICE_INSTANCE",
    "SERVICE_START",
    "SERVICE_STOP",
    "SERVICE_CONNECT_DO",
    "SERVICE_RECONNECT_DO",
    "SERVICE_RECONNECT_COMFIRM",
    "SERVICE_REG_MR",
    "SERVICE_REG_MR_WITH_PTR",
    "SERVICE_DESTROY_MR",
    "SERVICE_OP_HANDLE_RNDV",
    "SERVICE_OP_HANDLE_RNDV_SGL",
    "SERVICE_OP_HANDLE_RECONNECT",
    "SERVICE_CB_REQUEST_RECEIVED",
    "SERVICE_CB_REQUEST_POSTED",
    "SERVICE_CB_ONESIDE_DONE",
    "SERVICE_CB_NEW_CHANNEL",
    "SERVICE_CB_BROKEN_CHANNEL",
    "SERVICE_THREAD_PERIODIC",

    "CHANNEL_SEND",
    "CHANNEL_SEND_RAW",
    "CHANNEL_SEND_RAW_SGL",
    "CHANNEL_SYNC_CALL",
    "CHANNEL_ASYNC_CALL",
    "CHANNEL_SYNC_CALL_RAW",
    "CHANNEL_ASYNC_CALL_RAW",
    "CHANNEL_SYNC_CALL_RAW_SGL",
    "CHANNEL_ASYNC_CALL_RAW_SGL",
    "CHANNEL_SYNC_RNDV_CALL",
    "CHANNEL_ASYNC_RNDV_CALL",
    "CHANNEL_SYNC_RNDV_SGL_CALL",
    "CHANNEL_ASYNC_RNDV_SGL_CALL",
    "CHANNEL_READ",
    "CHANNEL_READ_SGL",
    "CHANNEL_WRITE",
    "CHANNEL_WRITE_SGL",
    "CHANNEL_SEND_FD",
    "CHANNEL_RECEIVE_FD",

    "RDMA_DRIVER_INIT",
    "RDMA_DRIVER_UNINIT",
    "RDMA_DRIVER_START",
    "RDMA_DRIVER_STOP",
    "RDMA_DRIVER_CONNECT_EP",
    "RDMA_DRIVER_DESTROY_EP",
    "RDMA_THREAD_HEARTBEAT",
    "RDMA_THREAD_ASYNC_EVENT",
    "RDMA_WORKER_BUSY_POLLING",
    "RDMA_WORKER_EVENT_POLLING",
    "RDMA_EP_ASYNC_POST_SEND",
    "RDMA_EP_ASYNC_POST_SEND_RAW",
    "RDMA_EP_ASYNC_POST_SEND_RAW_SGL",
    "RDMA_EP_ASYNC_POST_READ",
    "RDMA_EP_ASYNC_POST_READ_SGL",
    "RDMA_EP_ASYNC_POST_WRITE",
    "RDMA_EP_ASYNC_POST_WRITE_SGL",
    "RDMA_EP_SYNC_POST_SEND",
    "RDMA_EP_SYNC_POST_SEND_RAW",
    "RDMA_EP_SYNC_POST_SEND_RAW_SGL",
    "RDMA_EP_SYNC_POST_READ",
    "RDMA_EP_SYNC_POST_READ_SGL",
    "RDMA_EP_SYNC_POST_WRITE",
    "RDMA_EP_SYNC_POST_WRITE_SGL",
    "RDMA_EP_SYNC_RECEIVE",
    "RDMA_EP_SYNC_WAIT_COMPLETION",

    "SOCK_DRIVER_CONNECT",
    "SOCK_DRIVER_HANDLE_CONNECT",
    "SOCK_DRIVER_INITIALIZE",
    "SOCK_DRIVER_START",
    "SOCK_DRIVER_CREATE_WORKER_RESOURCE",
    "SOCK_DRIVER_CREATE_WORKERS",
    "SOCK_DRIVER_CREATE_CLIENT_LB",
    "SOCK_DRIVER_CREATE_LISTENERS",
    "SOCK_DRIVER_WORKER_START",
    "SOCK_DRIVER_START_LISTENERS",
    "SOCK_WORKER_EPOLL_WAIT",
    "SOCK_WORKER_HANDLE_EVENT",
    "SOCK_WORKER_HANDLE_EPOLLIN_EVENT",
    "SOCK_WORKER_HANDLE_EPOLL_OUT_EVENT",
    "SOCK_WORKER_HANDLE_EPOLL_WRNORM_EVENT",
    "SOCK_WORKER_IDLE_HANDLER",
    "SOCK_EP_BLOCK_POST_SEND",
    "SOCK_EP_ASYNC_POST_SEND",
    "SOCK_EP_ASYNC_POST_SEND_RAW",
    "SOCK_EP_ASYNC_POST_SEND_RAW_SGL",
    "SOCK_EP_ASYNC_POST_READ",
    "SOCK_EP_ASYNC_POST_READ_SGL",
    "SOCK_EP_ASYNC_POST_WRITE",
    "SOCK_EP_ASYNC_POST_WRITE_SGL",
    "SOCK_EP_SYNC_POST_SEND",
    "SOCK_EP_SYNC_POST_SEND_RAW",
    "SOCK_EP_SYNC_POST_SEND_RAW_SGL",
    "SOCK_EP_SYNC_POST_READ",
    "SOCK_EP_SYNC_POST_READ_SGL",
    "SOCK_EP_SYNC_POST_WRITE",
    "SOCK_EP_SYNC_POST_WRITE_SGL",
    "SOCK_EP_SYNC_RECEIVE",
    "SOCK_EP_SYNC_WAIT_COMPLETION",

    "SHM_DRIVER_INIT",
    "SHM_DRIVER_UNINIT",
    "SHM_DRIVER_START",
    "SHM_DRIVER_STOP",
    "SHM_DRIVER_CONNECT",
    "SHM_DRIVER_CREATE_MEMORY_REGION",
    "SHM_DRIVER_DESTORY_MEMORY_REGION",
    "SHM_WORKER_BUSY_POLLING",
    "SHM_WORKER_EVENT_POLLING",
    "SHM_THREAD_CHANNEL_KEEPER",
    "SHM_EP_ASYNC_POST_SEND",
    "SHM_EP_ASYNC_POST_SEND_RAW",
    "SHM_EP_ASYNC_POST_SEND_RAW_SGL",
    "SHM_EP_ASYNC_POST_READ",
    "SHM_EP_ASYNC_POST_READ_SGL",
    "SHM_EP_ASYNC_POST_WRITE",
    "SHM_EP_ASYNC_POST_WRITE_SGL",
    "SHM_EP_ASYNC_SEND_FDS",
    "SHM_EP_ASYNC_RECEIVE_FDS",
    "SHM_EP_SYNC_POST_SEND",
    "SHM_EP_SYNC_POST_SEND_RAW",
    "SHM_EP_SYNC_POST_SEND_RAW_SGL",
    "SHM_EP_SYNC_POST_READ",
    "SHM_EP_SYNC_POST_READ_SGL",
    "SHM_EP_SYNC_POST_WRITE",
    "SHM_EP_SYNC_POST_WRITE_SGL",
    "SHM_EP_SYNC_WAIT_COMPLETION",
    "SHM_EP_SYNC_RECEIVE",
    "SHM_EP_SYNC_RECEIVE_RAW",

    "UB_WORKER_BUSY_POLLING",
    "UB_WORKER_EVENT_POLLING",
    "UB_EP_ASYNC_POST_SEND",
    "UB_EP_ASYNC_POST_SEND_RAW",
    "UB_EP_ASYNC_POST_SEND_RAW_SGL",
    "UB_EP_ASYNC_POST_READ",
    "UB_EP_ASYNC_POST_READ_SGL",
    "UB_EP_ASYNC_POST_WRITE",
    "UB_EP_ASYNC_POST_WRITE_SGL",
    "UB_EP_SYNC_POST_SEND",
    "UB_EP_SYNC_POST_SEND_RAW",
    "UB_EP_SYNC_POST_SEND_RAW_SGL",
    "UB_EP_SYNC_POST_READ",
    "UB_EP_SYNC_POST_READ_SGL",
    "UB_EP_SYNC_POST_WRITE",
    "UB_EP_SYNC_POST_WRITE_SGL",

    "OOB_START",
    "OOB_STOP",
    "OOB_CONN_SEND",
    "OOB_CONN_RECEIVE",
    "OOB_CONN_SEND_MSG",
    "OOB_CONN_RECEIVE_MSG",
    "OOB_ACCREPT_SOCKET",
    "OOB_CONNECT_SOCKET",
    "OOB_EXEC_CONN_TASK",
    "OOB_SECINFO_PROVIDER",
    "OOB_SECINFO_VALIDATOR",

    "SERVICE_IO_BROKEN_CALLBACK",
    "SERVICE_POSTED_OR_DONE_CALLBACK",
    "SERVICE_CALL_DONE_CALLBACK",
    "SERVICE_RUN_CALLBACK",
    "TIMEOUT_RUN_CALLBACK",

    "CHANNEL_ONESIDE_SGL_CHOOSE_EP",
    "CHANNEL_ONESIDE_SGL_TIMER_CTX",
    "CHANNEL_ONESIDE_SGL_BUILD_SGL",
    "CHANNEL_ONESIDE_SGL_POST_WRITE",
    "RDMA_WORKER_SGL_PREPARE",
    "RDMA_WORKER_SGL_GROUP",
    "RDMA_WORKER_SGL_POST_SEND",
    "RDMA_WORKER_SGL_WR_COUNT",
    "RDMA_WORKER_SGL_IOV_COUNT",
};

void NetTrace::Initialize()
{
    uint32_t stringArraySize = sizeof(g_idToString) / sizeof(g_idToString[0]);
    if (NN_UNLIKELY(stringArraySize != MAX_MODULE_ID_INNER)) {
        NN_LOG_WARN("Id to string table size " << stringArraySize << " different from trace size " <<
            MAX_MODULE_ID_INNER);
    }
    for (uint32_t traceId = 0; traceId < MAX_MODULE_ID_INNER; traceId++) {
        if (traceId < stringArraySize) {
            mPointProperty[traceId].name = g_idToString[traceId];
        }
    }

    auto envString = getenv("HCOM_TRACE_LEVEL");
    if (envString != nullptr) {
        long tmp = 0;
        if (NetFunc::NN_Stol(envString, tmp) && tmp >= LEVEL0 && tmp <= LEVEL3) {
            mEnableLevel = static_cast<NetTraceLevel>(tmp);
        }
    } else {
        NN_LOG_INFO("Default trace level " << mEnableLevel);
    }
}

NetTrace *NetTrace::gTraceInst = nullptr;
std::mutex NetTrace::gTraceLock;

void NetTrace::Instance()
{
    if (gTraceInst == nullptr) {
        std::lock_guard<std::mutex> locker(gTraceLock);
        if (gTraceInst == nullptr) {
            // double check nullptr
            gTraceInst = new (std::nothrow) NetTrace();
            if (NN_UNLIKELY(gTraceInst == nullptr)) {
                return;
            }
            gTraceInst->Initialize();
        }
    }
}

bool NetTrace::gEnableHtrace = false;
void NetTrace::HtraceInit(const std::string &name)
{
    auto ret = HTracerInit(name);
    if (ret != 0) {
        NN_LOG_WARN("HTracerInit failed, ret " << ret);
        return;
    }
    auto envString = getenv("HCOM_ENABLE_TRACE");
    if (envString != nullptr) {
        long tmp = 0;
        if (NetFunc::NN_Stol(envString, tmp) && tmp >= LEVEL0 && tmp <= LEVEL1) {
            gEnableHtrace = static_cast<bool>(tmp);
        } else {
            NN_LOG_WARN("Failed to set env 'HCOM_ENABLE_TRACE', the value can be 0 or 1. ");
        }
    } else {
        NN_LOG_INFO("Default diseable trace. ");
    }
    EnableHtrace(gEnableHtrace);
}
}
}
