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
#include <dlfcn.h>

#if defined(TEST_LLT) && defined(MOCK_VERBS)
#include "fake_ibv.h"
#endif
#include "hcom_log.h"
#include "verbs_api_dl.h"
#include "../../common/net_common.h"
using namespace ock::hcom;

// ibv APIs
IBV_GET_DEVICE_LIST VerbsAPI::hcomInnerIbvGetDevList = nullptr;
IBV_FORK_INIT VerbsAPI::hcomInnerIbvForkInit = nullptr;
IBV_QUERY_PORT VerbsAPI::hcomInnerIbvQueryPort = nullptr;
IBV_OPEN_DEVICE VerbsAPI::hcomInnerIbvOpenDevice = nullptr;
IBV_ALLOC_PD VerbsAPI::hcomInnerIbvAllocPD = nullptr;
IBV_FREE_DEVICE_LIST VerbsAPI::hcomInnerIbvFreeDevList = nullptr;
IBV_CREATE_COMP_CHANNEL VerbsAPI::hcomInnerIbvCreateCompChannel = nullptr;
IBV_GET_CQ_EVENT VerbsAPI::hcomInnerIbvGetCQEvent = nullptr;
IBV_GET_ASYNC_EVENT VerbsAPI::hcomInnerIbvGetAsyncEvent = nullptr;
IBV_ACK_ASYNC_EVENT VerbsAPI::hcomInnerIbvAckAsyncEvent = nullptr;
IBV_CREATE_QP VerbsAPI::hcomInnerIbvCreateQP = nullptr;
IBV_CLOSE_DEVICE VerbsAPI::hcomInnerIbvCloseDev = nullptr;
IBV_DEALLOC_PD VerbsAPI::hcomInnerIbvDeallocPD = nullptr;
IBV_CREATE_CQ VerbsAPI::hcomInnerCreateCQ = nullptr;
IBV_DESTROY_COMP_CHANNEL VerbsAPI::hcomInnerDestroyCompChannel = nullptr;
IBV_DESTROY_CQ VerbsAPI::hcomInnerDestroyCQ = nullptr;
IBV_ACK_CQ_EVENTS VerbsAPI::hcomInnerAckCQ = nullptr;
IBV_DESTROY_QP VerbsAPI::hcomInnerDestroyQP = nullptr;
IBV_MODIFY_QP VerbsAPI::hcomInnerModityQP = nullptr;
IBV_DEREG_MR VerbsAPI::hcomInnerDeregMr = nullptr;
IBV_QUERY_GID VerbsAPI::hcomInnerQueryGid = nullptr;
IBV_QUERY_DEVICE VerbsAPI::hcomInnerQueryDevice = nullptr;
IBV_PORT_STATE_STR VerbsAPI::hcomInnerPortStateStr = nullptr;
IBV_REG_MR_IOVA2 VerbsAPI::hcomInnerRegMrIOVA2 = nullptr;
IBV_REG_MR VerbsAPI::hcomInnerRegMr = nullptr;

bool VerbsAPI::gLoaded = false;

#if !defined(TEST_LLT) || !defined(MOCK_VERBS)
#define DLSYM(type, ptr, sym)                                                           \
    do {                                                                                \
        auto ptr1 = dlsym(handle, sym);                                                 \
        if (ptr1 == nullptr) {                                                          \
            NN_LOG_ERROR("Failed to load function " << sym << ", error " << dlerror()); \
            dlclose(handle);                                                            \
            return -1;                                                                  \
        }                                                                               \
        ptr = (type)ptr1;                                                               \
    } while (0)

int VerbsAPI::LoadVerbsAPI()
{
    if (gLoaded) {
        return 0;
    }

    auto handle = dlopen(IVERBS_SO_PATH, RTLD_NOW);
    if (handle == nullptr) {
        NN_LOG_ERROR("Failed to load verbs so " << IVERBS_SO_PATH << ", error " << dlerror());
        return -1;
    }

    DLSYM(IBV_GET_DEVICE_LIST, VerbsAPI::hcomInnerIbvGetDevList, "ibv_get_device_list");
    DLSYM(IBV_FORK_INIT, VerbsAPI::hcomInnerIbvForkInit, "ibv_fork_init");
    DLSYM(IBV_QUERY_PORT, VerbsAPI::hcomInnerIbvQueryPort, "ibv_query_port");
    DLSYM(IBV_OPEN_DEVICE, VerbsAPI::hcomInnerIbvOpenDevice, "ibv_open_device");
    DLSYM(IBV_ALLOC_PD, VerbsAPI::hcomInnerIbvAllocPD, "ibv_alloc_pd");
    DLSYM(IBV_FREE_DEVICE_LIST, VerbsAPI::hcomInnerIbvFreeDevList, "ibv_free_device_list");
    DLSYM(IBV_CREATE_COMP_CHANNEL, VerbsAPI::hcomInnerIbvCreateCompChannel, "ibv_create_comp_channel");
    DLSYM(IBV_GET_CQ_EVENT, VerbsAPI::hcomInnerIbvGetCQEvent, "ibv_get_cq_event");
    DLSYM(IBV_GET_ASYNC_EVENT, VerbsAPI::hcomInnerIbvGetAsyncEvent, "ibv_get_async_event");
    DLSYM(IBV_ACK_ASYNC_EVENT, VerbsAPI::hcomInnerIbvAckAsyncEvent, "ibv_ack_async_event");
    DLSYM(IBV_CREATE_QP, VerbsAPI::hcomInnerIbvCreateQP, "ibv_create_qp");
    DLSYM(IBV_CLOSE_DEVICE, VerbsAPI::hcomInnerIbvCloseDev, "ibv_close_device");
    DLSYM(IBV_DEALLOC_PD, VerbsAPI::hcomInnerIbvDeallocPD, "ibv_dealloc_pd");
    DLSYM(IBV_CREATE_CQ, VerbsAPI::hcomInnerCreateCQ, "ibv_create_cq");
    DLSYM(IBV_DESTROY_COMP_CHANNEL, VerbsAPI::hcomInnerDestroyCompChannel, "ibv_destroy_comp_channel");
    DLSYM(IBV_DESTROY_CQ, VerbsAPI::hcomInnerDestroyCQ, "ibv_destroy_cq");
    DLSYM(IBV_ACK_CQ_EVENTS, VerbsAPI::hcomInnerAckCQ, "ibv_ack_cq_events");
    DLSYM(IBV_DESTROY_QP, VerbsAPI::hcomInnerDestroyQP, "ibv_destroy_qp");
    DLSYM(IBV_MODIFY_QP, VerbsAPI::hcomInnerModityQP, "ibv_modify_qp");
    DLSYM(IBV_DEREG_MR, VerbsAPI::hcomInnerDeregMr, "ibv_dereg_mr");
    DLSYM(IBV_QUERY_GID, VerbsAPI::hcomInnerQueryGid, "ibv_query_gid");
    DLSYM(IBV_QUERY_DEVICE, VerbsAPI::hcomInnerQueryDevice, "ibv_query_device");
    DLSYM(IBV_REG_MR_IOVA2, VerbsAPI::hcomInnerRegMrIOVA2, "ibv_reg_mr_iova2");
    DLSYM(IBV_REG_MR, VerbsAPI::hcomInnerRegMr, "ibv_reg_mr");
    DLSYM(IBV_PORT_STATE_STR, VerbsAPI::hcomInnerPortStateStr, "ibv_port_state_str");

    NN_LOG_INFO("Success to load ibverbs");
    gLoaded = true;

    return 0;
}
#else
int VerbsAPI::LoadFakeVerbsAPI()
{
    if (gLoaded) {
        return 0;
    }

    VerbsAPI::hcomInnerIbvGetDevList = ibv_get_device_list;
    VerbsAPI::hcomInnerIbvForkInit = ibv_fork_init;
    VerbsAPI::hcomInnerIbvQueryPort = fake_ibv_query_port;
    VerbsAPI::hcomInnerIbvOpenDevice = ibv_open_device;
    VerbsAPI::hcomInnerQueryDevice = ibv_query_device;
    VerbsAPI::hcomInnerIbvAllocPD = ibv_alloc_pd;
    VerbsAPI::hcomInnerIbvFreeDevList = ibv_free_device_list;
    VerbsAPI::hcomInnerIbvCreateCompChannel = ibv_create_comp_channel;
    VerbsAPI::hcomInnerIbvGetCQEvent = ibv_get_cq_event;
    VerbsAPI::hcomInnerIbvGetAsyncEvent = ibv_get_async_event;
    VerbsAPI::hcomInnerIbvAckAsyncEvent = ibv_ack_async_event;
    VerbsAPI::hcomInnerIbvCreateQP = ibv_create_qp;
    VerbsAPI::hcomInnerIbvCloseDev = ibv_close_device;
    VerbsAPI::hcomInnerIbvDeallocPD = ibv_dealloc_pd;
    VerbsAPI::hcomInnerCreateCQ = ibv_create_cq;
    VerbsAPI::hcomInnerDestroyCompChannel = ibv_destroy_comp_channel;
    VerbsAPI::hcomInnerDestroyCQ = ibv_destroy_cq;
    VerbsAPI::hcomInnerAckCQ = ibv_ack_cq_events;
    VerbsAPI::hcomInnerDestroyQP = ibv_destroy_qp;
    VerbsAPI::hcomInnerModityQP = ibv_modify_qp;
    VerbsAPI::hcomInnerDeregMr = ibv_dereg_mr;
    VerbsAPI::hcomInnerQueryGid = ibv_query_gid;
    VerbsAPI::hcomInnerRegMrIOVA2 = ibv_reg_mr_iova2;
    VerbsAPI::hcomInnerRegMr = ibv_reg_mr;
    VerbsAPI::hcomInnerPortStateStr = ibv_port_state_str;

    NN_LOG_INFO("Success to load fake ibverbs");
    gLoaded = true;

    return 0;
}
#endif

#endif