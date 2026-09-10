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
#ifndef HCOM_CAPI_V2_HCOM_SERVICE_C_V2_H_
#define HCOM_CAPI_V2_HCOM_SERVICE_C_V2_H_

#include <stdbool.h>
#include <stdint.h>
#include "hcom_c.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uintptr_t ubs_hcom_channel;
/*
 * @brief Service context, which used for callback as param
 */
typedef uintptr_t ubs_hcom_service_context;

/*
 * @brief service, which include oob & multi protocols(TCP/RDMA/SHM) workers & callback etc
 */
typedef uintptr_t ubs_hcom_service;

/*
 * @brief Channel, represent multi connections(EPs) of one protocol
 *
 * two side operation, Hcom_ChannelSend
 * read operation from remote, Hcom_ChannelRead
 * write operation from remote, Hcom_ChannelWrite
 */
typedef uintptr_t ubs_hcom_channel;

typedef uintptr_t ubs_hcom_memory_region;

/*
 * @brief Service context, which used for callback as param
 */
typedef uintptr_t ubs_hcom_service_context;

/*
 * Callback function which will be invoked by async use mode
 */
typedef void (*ubs_hcom_channel_cb_func)(void *arg, ubs_hcom_service_context context);
/*
 * @brief Callback function definition
 * 1) new endpoint connected from client, only need to register this at sever side
 * 2) endpoint is broken, called when RDMA qp detection error or broken
 */
typedef int (*ubs_hcom_service_channel_handler)(ubs_hcom_channel channel, uint64_t usrCtx, const char *payLoad);
typedef void (*ubs_hcom_service_idle_handler)(uint8_t wkrGrpIdx, uint16_t idxInGrp, uint64_t usrCtx);
typedef int (*ubs_hcom_service_request_handler)(ubs_hcom_service_context ctx, uint64_t usrCtx);

/*
 * @brief keyPass          [in] erase function
 * @param keyPass          [in] the memory address of keyPass
 */
typedef void (*ubs_hcom_tls_keypass_erase)(char *keyPass, int len);

/*
 * @brief The cert verify function
 *
 * @param x509             [in] the x509 object of CA
 * @param crlPath          [in] the crl file path
 *
 * @return -1 for failed, and 1 for success
 */
typedef int (*ubs_hcom_tls_cert_verify)(void *x509, const char *crlPath);

/*
 * @brief Get the certificate file of public key
 *
 * @param name             [out] the name
 * @param certPath         [out] the path of certificate
 */
typedef int (*ubs_hcom_tls_get_cert_cb)(const char *name, char **certPath);

/*
 * @brief Get private key file's path and length, and get the keyPass
 * @param name             [out] the name
 * @param priKeyPath       [out] the path of private key
 * @param keyPass          [out] the keyPass
 * @param erase            [out] the erase function
 */
typedef int (*ubs_hcom_tls_get_pk_cb)(
    const char *name, char **priKeyPath, char **keyPass, ubs_hcom_tls_keypass_erase *erase);

/*
 * @brief Get the CA and verify
 * @param name             [out] the name
 * @param caPath           [out] the path of CA file
 * @param crlPath          [out] the crl file path
 * @param verifyType       [out] the type of verify in[VERIFY_BY_NONE,VERIFY_BY_DEFAULT, VERIFY_BY_CUSTOM_FUNC]
 * @param verify           [out] the verify function, only effect in VERIFY_BY_CUSTOM_FUNC mode
 */
typedef int (*ubs_hcom_tls_get_ca_cb)(const char *name, char **caPath, char **crlPath,
    ubs_hcom_peer_cert_verify_type *verifyType, ubs_hcom_tls_cert_verify *verify);

/*
 * @brief Sec callback function, when oob connect build, this function will be called to generate auth info.
 * if this function not set secure type is C_NET_SEC_NO_VALID and oob will not send secure info
 *
 * @param ctx              [in] ctx from connect param ctx, and will send in auth process
 * @param flag             [out] flag to sent in auth process
 * @param type             [out] secure type, value should set in oob client, and should in [C_NET_SEC_ONE_WAY,
 * C_NET_SEC_TWO_WAY]
 * @param output           [out] secure info created
 * @param outLen           [out] secure info length
 * @param needAutoFree     [out] secure info need to auto free in hcom or not
 */
typedef int (*ubs_hcom_secinfo_provider)(uint64_t ctx, int64_t *flag, ubs_hcom_driver_sec_type *type, char **output,
    uint32_t *outLen, int *needAutoFree);

/*
 * @brief ValidateSecInfo callback function, when oob connect build, this function will be called to validate auth info
 * if this function not set oob will not validate secure info
 *
 * @param flag             [in] flag received in auth process
 * @param ctx              [in] ctx received in auth process
 * @param input            [in] secure info received
 * @param inputLen         [in] secure info length
 */
typedef int (*ubs_hcom_secinfo_validator)(uint64_t ctx, int64_t flag, const char *input, uint32_t inputLen);

/*
 * @brief External log callback function
 *
 * @param level            [in] level, 0/1/2/3 represent debug/info/warn/error
 * @param msg              [in] message, log message with name:code-line-number
 */
typedef void (*ubs_hcom_log_handler)(int level, const char *msg);

/*
 * @brief Worker polling type
 * 1 For RDMA:
 * C_BUSY_POLLING, means cpu 100% polling no matter there is request cb, better performance but cost dedicated CPU
 * C_EVENT_POLLING, waiting on OS kernel for request cb
 * 2 For TCP/UDS
 * only event pooling is supported
 */
typedef enum {
    C_SERVICE_BUSY_POLLING = 0,
    C_SERVICE_EVENT_POLLING = 1,
} ubs_hcom_service_worker_mode;

typedef enum {
    C_CLIENT_WORKER_POLL = 0,
    C_CLIENT_SELF_POLL_BUSY = 1,
    C_CLIENT_SELF_POLL_EVENT = 2,
} ubs_hcom_service_polling_mode;

typedef enum {
    C_CHANNEL_FUNC_CB = 0,   // use channel function param (const NetCallback *cb)
    C_CHANNEL_GLOBAL_CB = 1, // use service RegisterOpHandler
} ubs_hcom_channel_cb_type;

typedef enum {
    HIGH_LEVEL_BLOCK,   /* spin-wait by busy loop */
    LOW_LEVEL_BLOCK,    /* full sleep */
} ubs_hcom_channel_flowctl_level;

typedef enum {
    C_SERVICE_RDMA = 0,
    C_SERVICE_TCP = 1,
    C_SERVICE_UDS = 2,
    C_SERVICE_SHM = 3,
    C_SERVICE_UBC = 6,
} ubs_hcom_service_type;

typedef enum {
    C_CHANNEL_BROKEN_ALL = 0, /* when one ep broken, all eps broken */
    C_CHANNEL_RECONNECT = 1,  /* when one ep broken, try re-connect first. If re-connect fail, broken all eps */
    C_CHANNEL_KEEP_ALIVE = 2, /* when one ep broken, keep left eps alive until all eps broken */
} ubs_hcom_service_channel_policy;

/*
 * @brief Enum for callback register [new endpoint connected or endpoint broken]
 */
typedef enum {
    C_CHANNEL_NEW = 0,
    C_CHANNEL_BROKEN = 1,
} ubs_hcom_service_channel_handler_type;

typedef enum {
    C_SERVICE_REQUEST_RECEIVED = 0,
    C_SERVICE_REQUEST_POSTED = 1,
    C_SERVICE_READWRITE_DONE = 2,
} ubs_hcom_service_handler_type;

typedef enum {
    SERVICE_ROUND_ROBIN = 0,
    SERVICE_HASH_IP_PORT = 1,
} ubs_hcom_service_lb_policy;

typedef enum {
    C_SERVICE_TLS_1_2 = 771,
    C_SERVICE_TLS_1_3 = 772,
} ubs_hcom_service_tls_version;

typedef enum {
    C_SERVICE_AES_GCM_128 = 0,
    C_SERVICE_AES_GCM_256 = 1,
    C_SERVICE_AES_CCM_128 = 2,
    C_SERVICE_CHACHA20_POLY1305 = 3,
} ubs_hcom_service_cipher_suite;

typedef enum {
    C_SERVICE_NET_SEC_DISABLED = 0,
    C_SERVICE_NET_SEC_ONE_WAY = 1,
    C_SERVICE_NET_SEC_TWO_WAY = 2,
} ubs_hcom_service_secure_type;

/*
 * @brief Enum for UBC mode
 */
typedef enum {
    C_SERVICE_LOWLATENCY = 0,
    C_SERVICE_HIGHBANDWIDTH = 1,
} ubs_hcom_service_ubc_mode;

/*
 * @brief Context type, part of ubs_hcom_service_context, sync mode is not aware most of them
 */
typedef enum {
    SERVICE_RECEIVED = 0,     /* support invoke all functions */
    SERVICE_RECEIVED_RAW = 1, /* support invoke most functions except Service_GetOpInfo() */
    SERVICE_SENT = 2,         /* support invoke basic functions except
                                 Service_GetMessage() * 3、Service_GetRspCtx()、 */
    SERVICE_SENT_RAW = 3,     /* support invoke basic functions except
                                 Service_GetMessage() * 3、、Service_GetRspCtx()、Service_GetOpInfo() */
    SERVICE_ONE_SIDE = 4,     /* support invoke basic functions except
                                 Service_GetMessage() * 3、、Service_GetRspCtx()、Service_GetOpInfo() */
    SERVICE_RNDV = 5,
    SERVICE_INVALID_OP_TYPE = 255,
} ubs_hcom_service_context_type;

typedef struct {
    uint32_t maxSendRecvDataSize;
    uint16_t workerGroupId;
    uint16_t workerGroupThreadCount;
    ubs_hcom_service_worker_mode workerGroupMode;
    int8_t workerThreadPriority;
    char workerGroupCpuRange[64];   // worker group cpu range, for example 6-10
} ubs_hcom_service_options;

typedef struct {
    ubs_hcom_channel_cb_func cb; // User callback function
    void *arg;               // Argument of callback
} ubs_hcom_channel_callback;


typedef struct {
    uint16_t clientGroupId;     // worker group id of client
    uint16_t serverGroupId;     // worker group id of server
    uint8_t linkCount;     // actual link count of the channel
    ubs_hcom_service_polling_mode mode;
    ubs_hcom_channel_cb_type cbType;
    char payLoad[512];
} ubs_hcom_service_connect_options;

typedef struct {
    void *address;    /* pointer of data */
    uint32_t size;              /* size of data */
    uint16_t opcode;
} ubs_hcom_channel_request;

typedef struct {
    void *address;              /* pointer of data */
    uint32_t size;              /* size of data */
    int16_t errorCode;          /* error code of response */
} ubs_hcom_channel_response;

typedef struct {
    void *rspCtx;
    int16_t errorCode;
} ubs_hcom_channel_reply_context;

typedef struct {
    uint64_t keys[4];
    uint64_t tokens[4];
    uint8_t eid[16];
} ubs_hcom_oneside_key;

/*
 * @brief Read/write mr info for one side rdma operation
 */
typedef struct {
    uintptr_t lAddress; // local memory region address
    ubs_hcom_oneside_key lKey;      // local memory region key
    uint64_t size;      // data size
} ubs_hcom_mr_info;

typedef struct {
    void *lAddress;
    void *rAddress;
    ubs_hcom_oneside_key lKey;
    ubs_hcom_oneside_key rKey;
    uint32_t size;
} ubs_hcom_oneside_request;

typedef struct {
    ubs_hcom_oneside_request iov[C_NET_SGE_MAX_IOV];
    uint16_t iovCount;
} ubs_hcom_onesidesgl_request;

typedef struct {
    uint16_t intervalTimeMs;
    uint64_t thresholdByte;
    ubs_hcom_channel_flowctl_level flowCtrlLevel;
} ubs_hcom_flowctl_opts;

typedef struct {
    uint32_t splitThreshold;
    uint32_t rndvThreshold;
} ubs_hcom_twoside_threshold;

int ubs_hcom_service_create(ubs_hcom_service_type t, const char *name, ubs_hcom_service_options options,
    ubs_hcom_service *service);

int ubs_hcom_service_bind(ubs_hcom_service service, const char *listenerUrl, ubs_hcom_service_channel_handler h);

int ubs_hcom_service_start(ubs_hcom_service service);

int ubs_hcom_service_destroy(ubs_hcom_service service, const char *name);

int ubs_hcom_service_connect(ubs_hcom_service service, const char *serverUrl, ubs_hcom_channel *channel,
    ubs_hcom_service_connect_options options);

int ubs_hcom_service_disconnect(ubs_hcom_service service, ubs_hcom_channel channel);

int ubs_hcom_service_register_memory_region(ubs_hcom_service service, uint64_t size, ubs_hcom_memory_region *mr);

int ubs_hcom_reg_seg(ubs_hcom_service service, uintptr_t address, uint64_t size, ubs_hcom_oneside_key *key);

int ubs_hcom_service_get_memory_region_info(ubs_hcom_memory_region mr, ubs_hcom_mr_info *info);

int ubs_hcom_service_register_assign_memory_region(
    ubs_hcom_service service, uintptr_t address, uint64_t size, ubs_hcom_memory_region *mr);

int ubs_hcom_service_destroy_memory_region(ubs_hcom_service service, ubs_hcom_memory_region mr);

void ubs_hcom_service_register_broken_handler(ubs_hcom_service service, ubs_hcom_service_channel_handler h,
    ubs_hcom_service_channel_policy policy, uint64_t usrCtx);

void ubs_hcom_service_register_idle_handler(ubs_hcom_service service, ubs_hcom_service_idle_handler h, uint64_t usrCtx);

void ubs_hcom_service_register_handler(ubs_hcom_service service, ubs_hcom_service_handler_type t,
    ubs_hcom_service_request_handler h, uint64_t usrCtx);

void ubs_hcom_service_add_workergroup(ubs_hcom_service service, int8_t priority, uint16_t workerGroupId,
    uint32_t threadCount, const char *cpuIdsRange);

void ubs_hcom_service_add_listener(ubs_hcom_service service, const char *url, uint16_t workerCount);

void ubs_hcom_service_set_lbpolicy(ubs_hcom_service service, ubs_hcom_service_lb_policy lbPolicy);

void ubs_hcom_service_set_tls_opt(ubs_hcom_service service, bool enableTls, ubs_hcom_service_tls_version version,
    ubs_hcom_service_cipher_suite cipherSuite, ubs_hcom_tls_get_cert_cb certCb, ubs_hcom_tls_get_pk_cb priKeyCb,
    ubs_hcom_tls_get_ca_cb caCb);

void ubs_hcom_service_set_secure_opt(ubs_hcom_service service, ubs_hcom_service_secure_type secType,
    ubs_hcom_secinfo_provider provider, ubs_hcom_secinfo_validator validator, uint16_t magic, uint8_t version);

void ubs_hcom_service_set_tcp_usr_timeout(ubs_hcom_service service, uint16_t timeOutSec);

void ubs_hcom_service_set_tcp_send_zcopy(ubs_hcom_service service, bool tcpSendZCopy);

void ubs_hcom_service_set_ipmask(ubs_hcom_service service, const char *ipMask);

void ubs_hcom_service_set_ipgroup(ubs_hcom_service service, const char *ipGroup);

void ubs_hcom_service_set_cq_depth(ubs_hcom_service service, uint16_t depth);

void ubs_hcom_service_set_sq_size(ubs_hcom_service service, uint32_t sqSize);

void ubs_hcom_service_set_rq_size(ubs_hcom_service service, uint32_t rqSize);

void ubs_hcom_service_set_prepost_size(ubs_hcom_service service, uint32_t prePostSize);

void ubs_hcom_service_set_polling_batchsize(ubs_hcom_service service, uint16_t pollSize);

void ubs_hcom_service_set_polling_timeoutus(ubs_hcom_service service, uint16_t pollTimeout);

void ubs_hcom_service_set_timeout_threadnum(ubs_hcom_service service, uint32_t threadNum);

void ubs_hcom_service_set_max_connection_cnt(ubs_hcom_service service, uint32_t maxConnCount);

void ubs_hcom_service_set_heartbeat_opt(ubs_hcom_service service, uint16_t idleSec, uint16_t probeTimes,
    uint16_t intervalSec);

void ubs_hcom_service_set_multirail_opt(ubs_hcom_service service, bool enable, uint32_t threshold);

void ubs_hcom_service_set_ubcmode(ubs_hcom_service service, ubs_hcom_service_ubc_mode ubcMode);

void ubs_hcom_service_set_max_send_recv_data_cnt(ubs_hcom_service service, uint32_t maxSendRecvDataCount);

void ubs_hcom_service_set_enable_mrcache(ubs_hcom_service service, bool enableMrCache);

void ubs_hcom_service_set_ub_priority(ubs_hcom_service service, uint32_t ubPriority);

void ubs_hcom_channel_refer(ubs_hcom_channel channel);
void ubs_hcom_channel_derefer(ubs_hcom_channel channel);
int ubs_hcom_channel_send(ubs_hcom_channel channel, ubs_hcom_channel_request req, ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_call(ubs_hcom_channel channel, ubs_hcom_channel_request req, ubs_hcom_channel_response *rsp,
    ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_reply(ubs_hcom_channel channel, ubs_hcom_channel_request req, ubs_hcom_channel_reply_context ctx,
    ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_put(ubs_hcom_channel channel, ubs_hcom_oneside_request req, ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_get(ubs_hcom_channel channel, ubs_hcom_oneside_request req, ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_putv(ubs_hcom_channel channel, ubs_hcom_onesidesgl_request req, ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_getv(ubs_hcom_channel channel, ubs_hcom_onesidesgl_request req, ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_recv(ubs_hcom_channel channel, ubs_hcom_service_context ctx, uintptr_t address, uint32_t size,
    ubs_hcom_channel_callback *cb);
int ubs_hcom_channel_send_fds(ubs_hcom_channel channel, int fds[], uint32_t len);
int ubs_hcom_channel_recv_fds(ubs_hcom_channel channel, int fds[], uint32_t len, int32_t timeoutSec);
int ubs_hcom_channel_set_flowctl_cfg(ubs_hcom_channel channel, ubs_hcom_flowctl_opts opt);
void ubs_hcom_channel_set_timeout(ubs_hcom_channel channel, int16_t oneSideTimeout, int16_t twoSideTimeout);
int ubs_hcom_channel_set_twoside_threshold(ubs_hcom_channel channel, ubs_hcom_twoside_threshold threshold);
uint64_t ubs_hcom_channel_get_id(ubs_hcom_channel channel);

int ubs_hcom_context_get_rspctx(ubs_hcom_service_context context, ubs_hcom_channel_reply_context *rspCtx);
int ubs_hcom_context_get_channel(ubs_hcom_service_context context, ubs_hcom_channel *channel);
int ubs_hcom_context_get_type(ubs_hcom_service_context context, ubs_hcom_service_context_type *type);
int ubs_hcom_context_get_result(ubs_hcom_service_context context, int *result);
uint16_t ubs_hcom_context_get_opcode(ubs_hcom_service_context context);
void *ubs_hcom_context_get_data(ubs_hcom_service_context context);
uint32_t ubs_hcom_context_get_datalen(ubs_hcom_service_context context);
ubs_hcom_service_context ubs_hcom_context_clone(ubs_hcom_service_context context);
void ubs_hcom_context_free(ubs_hcom_service_context context);

/*
 * @brief Set external logger function
 *
 * @param h                [in] the log function ptr
 */
void ubs_hcom_set_log_handler(ubs_hcom_log_handler h);

#ifdef __cplusplus
}
#endif

#endif // HCOM_HCOM_SERVICE_C_V2_H
