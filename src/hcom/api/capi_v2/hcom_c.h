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

#ifndef HCOM_CAPI_V2_HCOM_C_H_
#define HCOM_CAPI_V2_HCOM_C_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define C_NET_SGE_MAX_IOV 16
#define MAX_IP_LENGTH 16
#define NET_C_FLAGS_BIT(i) (1UL << (i))

/*
 * @brief Driver, which include oob & rdma communication & callback etc
 */
typedef uintptr_t ubs_hcom_driver;

/*
 * @brief Endpoint, represent one RDMA connection to dual-direction communication
 *
 * two side operation, ubs_hcom_ep_post_send
 * read operation from remote, ubs_hcom_ep_post_read
 * write operation from remote, ubs_hcom_ep_post_write
 */
typedef uintptr_t ubs_hcom_endpoint;

/*
 * @brief RegMemoryRegion, which region memory in RDMA Nic for write/read operation
 */
typedef uintptr_t ubs_hcom_memory_region;

typedef enum {
    NET_C_EP_SELF_POLLING = NET_C_FLAGS_BIT(0),
    NET_C_EP_EVENT_POLLING = NET_C_FLAGS_BIT(1)
} ubs_hcom_polling_mode;

/*
 * @brief Request type, part of ubs_hcom_request_context
 */
typedef enum {
    C_SENT = 0,
    C_SENT_RAW = 1,
    C_SENT_RAW_SGL = 2,
    C_RECEIVED = 3,
    C_RECEIVED_RAW = 4,
    C_WRITTEN = 5,
    C_READ = 6,
    C_SGL_WRITTEN = 7,
    C_SGL_READ = 8,
} ubs_hcom_request_type;

/*
 * @brief Worker polling type
 * 1 For RDMA:
 * C_BUSY_POLLING, means cpu 100% polling no matter there is request done, better performance but cost dedicated CPU
 * C_EVENT_POLLING, waiting on OS kernel for request done
 * 2 For TCP/UDS
 * only event pooling is supported
 */
typedef enum {
    C_BUSY_POLLING = 0,
    C_EVENT_POLLING = 1,
} ubs_hcom_driver_working_mode;

typedef enum {
    C_DRIVER_RDMA = 0,
    C_DRIVER_TCP = 1,
    C_DRIVER_UDS = 2,
    C_DRIVER_SHM = 3,
    C_DRIVER_UBC = 6,
} ubs_hcom_driver_type;

/*
 * @brief DriverOobType working mode
 */
typedef enum {
    C_NET_OOB_TCP = 0,
    C_NET_OOB_UDS = 1,
} ubs_hcom_driver_oob_type;

/*
 * @brief Enum for secure type
 */
typedef enum {
    C_NET_SEC_DISABLED = 0,
    C_NET_SEC_ONE_WAY = 1,
    C_NET_SEC_TWO_WAY = 2,
} ubs_hcom_driver_sec_type;

typedef enum {
    C_TLS_1_2 = 771,
    C_TLS_1_3 = 772,
} ubs_hcom_driver_tls_version;

/*
 * @brief DriverCipherSuite mode
 */
typedef enum {
    C_AES_GCM_128 = 0,
    C_AES_GCM_256 = 1,
    C_AES_CCM_128 = 2,
    C_CHACHA20_POLY1305 = 3,
} ubs_hcom_driver_cipher_suite;

/*
 * @brief Memory allocator cache tier policy
 */
typedef enum {
    C_TIER_TIMES = 0, /* tier by times of min-block-size */
    C_TIER_POWER = 1, /* tier by power of min-block-size */
} ubs_hcom_memory_allocator_cache_tier_policy;

/*
 * @brief Enum for tls callback, set peer cert verify type
 */
typedef enum {
    C_VERIFY_BY_NONE = 0,
    C_VERIFY_BY_DEFAULT = 1,
    C_VERIFY_BY_CUSTOM_FUNC = 2,
} ubs_hcom_peer_cert_verify_type;

/*
 * @brief Type of allocator
 */
typedef enum {
    C_DYNAMIC_SIZE = 0,            /* allocate dynamic memory size, there is alignment with X KB */
    C_DYNAMIC_SIZE_WITH_CACHE = 1, /* allocator with dynamic memory size, with pre-allocate cache for performance */
} ubs_hcom_memory_allocator_type;

/*
 * @brief Enum for callback register [new endpoint connected or endpoint broken]
 */
typedef enum {
    C_EP_NEW = 0,
    C_EP_BROKEN = 1,
} ubs_hcom_ep_handler_type;

/*
 * @brief Enum for callback register [request received, request posted, read/write done]
 */
typedef enum {
    C_OP_REQUEST_RECEIVED = 0,
    C_OP_REQUEST_POSTED = 1,
    C_OP_READWRITE_DONE = 2,
} ubs_hcom_op_handler_type;

/*
 * @brief Two side RDMA operation (i.e. RDMA send/receive)
 *
 * @param data, pointer of data need to send to peer (the data will be copied to register RDMA memory region
 * the data must be less than mrSendReceiveSegSize of driver
 * @param size, size of data
 */
typedef struct {
    uintptr_t data;         // pointer of data to send to peer
    uint32_t size;          // size of data
    uint16_t upCtxSize;     // user context size
    char upCtxData[64];     // user context
} ubs_hcom_send_request;

typedef struct {
    uint32_t seqNo;    // seq no
    int16_t timeout;  // timeout
    int16_t errorCode; // error code
    uint8_t flags;     // flags
} ubs_hcom_opinfo;

/*
 * @brief Device information for user
 */
typedef struct {
    int maxSge; // max iov count in UBSHcomNetTransSglRequest
} ubs_hcom_device_info;

/*
 * @brief Read/write request for one side rdma operation
 */
typedef struct {
    uintptr_t lMRA;         // local memory region address
    uintptr_t rMRA;         // remote memory region address
    uint64_t lKey;          // local memory region key
    uint64_t rKey;          // remote memory region key
    uint32_t size;          // data size
    uint16_t upCtxSize;     // user context size
    char upCtxData[64]; // user context
} ubs_hcom_readwrite_request;

typedef struct {
    uintptr_t lAddress; // local memory region address
    uintptr_t rAddress; // remote memory region address
    uint64_t lKey;      // local memory region key
    uint64_t rKey;      // remote memory region key
    uint32_t size;      // data size
} __attribute__((packed)) ubs_hcom_readwrite_sge;

typedef struct {
    ubs_hcom_readwrite_sge *iov;  // sgl array
    uint16_t iovCount;      // max count:NUM_4
    uint16_t upCtxSize;     // user context size
    char upCtxData[16]; // user context
} __attribute__((packed)) ubs_hcom_readwrite_request_sgl;

/*
 * @brief Read/write mr info for one side rdma operation
 */
typedef struct {
    uintptr_t lAddress; // local memory region address
    uint64_t lKey;      // local memory region key
    uint32_t size;      // data size
} ubs_hcom_memory_region_info;

/*
 * @brief Callback function context, for received, post done, read/write done
 */
typedef struct {
    ubs_hcom_request_type type;
    uint16_t opCode;   // for post send
    uint16_t flags;    // flags on the header
    int16_t timeout;  // timeout
    int16_t errorCode; // error code
    int result;        // return 0 successful
    void *msgData;     // for receive operation or C_OP_REQUEST_RECEIVED callback
    uint32_t msgSize;  // for receive operation or C_OP_REQUEST_RECEIVED callback
    uint32_t seqNo;    // for post send raw
    ubs_hcom_endpoint ep;
    ubs_hcom_send_request originalSend;           // for C_OP_REQUEST_POSTED, copy struct information, not original
                                            // originalSend.data is self rdma address, not original input data address
    ubs_hcom_readwrite_request originalReq;       // for C_OP_READWRITE_DONE, copy struct information, not original
    ubs_hcom_readwrite_request_sgl originalSglReq; // for C_OP_READWRITE_DONE, copy struct information, not original
} ubs_hcom_request_context;

typedef struct {
    uint16_t opCode;
    uint32_t seqNo;
    void *msgData;
    uint32_t msgSize;
} ubs_hcom_response_context;

typedef struct {
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
} ubs_hcom_uds_id_info;

/*
 * @brief Options for driver initialization
 */
typedef struct {
    ubs_hcom_driver_working_mode mode;        // polling mode
    uint32_t mrSendReceiveSegCount;    // segment count of segment for send/receive
    uint32_t mrSendReceiveSegSize;     // single segment size of send/receive memory region
    char netDeviceIpMask[256];     // device ip mask, for multiple net device cases
    char netDeviceIpGroup[1024];   // ip group for devices
    uint16_t completionQueueDepth;     // rdma completion queue size
    uint16_t maxPostSendCountPerQP;    // max post send count
    uint16_t prePostReceiveSizePerQP;  // pre post receive size for one qp
    uint16_t pollingBatchSize;         // polling wc size on at one time
    uint32_t qpSendQueueSize;          // qp send queue size, by default is 256
    uint32_t qpReceiveQueueSize;       // qp receive queue size, by default is 256
    uint16_t dontStartWorkers;         // start worker or not, 1 means don't start, 0 means start
    char workerGroups[64];         // worker groups, for example 1,3,3
    char workerGroupsCpuSet[128];  // worker groups cpu set, for example 1-16
    // worker thread priority [-20,20], 20 is the lowest, -20 is the highest, 0 (default) means do not set priority
    int workerThreadPriority;
    uint16_t heartBeatIdleTime;        // heart beat idle time, in seconds
    uint16_t heartBeatProbeTimes;      // heart beat probe times, in seconds
    uint16_t heartBeatProbeInterval;   // heart beat probe interval, in seconds
    // timeout during io (s), it should be [-1, 1024], -1 means do not set, 0 means never timeout during io
    int16_t tcpUserTimeout;
    bool tcpEnableNoDelay;             // tcp TCP_NODELAY option, true in default
    bool tcpSendZCopy;                 // tcp whether copy request to inner memory, false in default
    /* The buffer sizes will be adjusted automatically when these two variables are 0, and the performance would be
     * better */
    uint16_t tcpSendBufSize;           // tcp connection send buffer size in kernel, in KB
    uint16_t tcpReceiveBufSize;        // tcp connection send receive buf size in kernel, in KB
    uint16_t enableTls;                // value only in 0 and 1, value 1 means enable ssl and encrypt, 0 on the contrary
    ubs_hcom_driver_sec_type secType;         // security type
    ubs_hcom_driver_tls_version tlsVersion;   // tls version, default TLS1.3 (772)
    ubs_hcom_driver_cipher_suite cipherSuite; // if tls enabled can set cipher suite, client and server should same
    ubs_hcom_driver_oob_type oobType;         // oob type, tcp or UDS, UDS cannot accept remote connection
    uint8_t version;                   // program version used by connect validation
    uint32_t maxConnectionNum;         // max connection number
    char oobPortRange[16];         // port range when enable port auto selection
} ubs_hcom_driver_opts;

/*
 * @brief Options for multiple listeners
 */
typedef struct {
    char ip[16];            // ip to be listened
    uint16_t port;              // port to be listened
    uint16_t targetWorkerCount; // the count of workers can be dispatched to, for connections from this listener
} ubs_hcom_driver_listen_opts;

/*
 * @brief Oob uds listening information
 */
typedef struct {
    char name[96];              // UDS name for listen or file path
    uint16_t perm;              // if 0 means not use file, otherwise use file and this perm as file perm
    uint16_t targetWorkerCount; // the count of target workers, if >= 1,
                                // the accepted socket will be attached to sub set to workers, 0 means all
} ubs_hcom_driver_uds_listen_opts;

/*
 * @brief Callback function definition
 * 1) new endpoint connected from client, only need to register this at sever side
 * 2) endpoint is broken, called when RDMA qp detection error or broken
 */
typedef int (*ubs_hcom_ep_handler)(ubs_hcom_endpoint ep, uint64_t usrCtx, const char *payLoad);

/*
 * @brief Callback function definition
 *
 * it is called when the following cases happen
 * 1) post send done
 * 2) read done
 * 3) write done
 *
 * Important notes:
 * 1) ctx is a thread local static variable, cannot transform to another thread directly
 * 2) msgData need to copy to another space properly
 * 3) ep can be transferred to another thread for further reply or other stuff
 * in this case, need to call ubs_hcom_ep_refer() to increase reference count
 * and call ubs_hcom_ep_destroy() after to decrease the reference count
 */
typedef int (*ubs_hcom_request_handler)(ubs_hcom_request_context *ctx, uint64_t usrCtx);

/*
 * @brief Idle callback function, when worker thread idle, this function will be called
 *
 * @param wkrGrpIdx        [in] worker group index in on net driver
 * @param idxInGrp         [in] worker index in the group
 * @param usrCtx           [in] user context
 */
typedef void (*ubs_hcom_idle_handler)(uint8_t wkrGrpIdx, uint16_t idxInGrp, uint64_t usrCtx);

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
typedef int (*ubs_hcom_tls_get_pk_cb)
    (const char *name, char **priKeyPath, char **keyPass, ubs_hcom_tls_keypass_erase *erase);

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
 * @brief External log callback function
 *
 * @param level            [in] level, 0/1/2/3 represent debug/info/warn/error
 * @param msg              [in] message, log message with name:code-line-number
 */
typedef void (*ubs_hcom_log_handler)(int level, const char *msg);

/*
 * @brief Options for Memory Allocator
 */
typedef struct {
    uintptr_t address;                                  /* base address of large range of memory for allocator */
    uint64_t size;                                      /* size of large memory chuck */
    uint32_t minBlockSize;                              /* min size of block, more than 4 KB is required */
    uint32_t bucketCount;                               /* default size of hash bucket */
    uint16_t alignedAddress;                            /* force to align the memory block allocated, 0 means not align
                                                          1 means align */
    uint16_t cacheTierCount;                            /* for DYNAMIC_SIZE_WITH_CACHE only */
    uint16_t cacheBlockCountPerTier;                    /* for DYNAMIC_SIZE_WITH_CACHE only */
    ubs_hcom_memory_allocator_cache_tier_policy cacheTierPolicy; /* tier policy */
} ubs_hcom_memory_allocator_options;

/*
 * @brief memory allocator ptr
 */
typedef uintptr_t ubs_hcom_memory_allocator;

/*
 * @brief Memory allocator create
 *
 * @param t                [in] type of allocator
 * @param options          [in] options
 * @param allocator        [out] allocator created
 */
int ubs_hcom_mem_allocator_create(ubs_hcom_memory_allocator_type t, ubs_hcom_memory_allocator_options *options,
    ubs_hcom_memory_allocator *allocator);

/*
 * @brief destroy the memory allocator
 *
 * @param allocator        [in] memory allocator
 *
 * @return 0 if successful
 */
int ubs_hcom_mem_allocator_destroy(ubs_hcom_memory_allocator allocator);

/*
 * @brief Set the memory region key
 * @param allocator        [in] memory allocator
 *
 * @return 0 if successful
 */
int ubs_hcom_mem_allocator_set_mr_key(ubs_hcom_memory_allocator allocator, uint64_t mrKey);

/*
 * @brief Get the memory offset based on base address
 *
 * @param allocator        [in] memory allocator
 * @param address          [in] memory address
 * @param offset           [out] offset comparing to base address
 *
 * @return 0 if successful
 */
int ubs_hcom_mem_allocator_get_offset(ubs_hcom_memory_allocator allocator, uintptr_t address, uintptr_t *offset);

/*
 * @brief Get free memory size
 *
 * @param allocator        [in] memory allocator
 *
 * @return 0 if successful
 */
int ubs_hcom_mem_allocator_get_free_size(ubs_hcom_memory_allocator allocator, uintptr_t *size);

/*
 * @brief Allocate memory area
 *
 * @param allocator        [in] memory allocator
 * @param size             [in] size of memory of demand
 * @param address          [out] allocated memory address
 * @param key              [out] allocated memory key
 *
 * @return 0 if successful
 */
int ubs_hcom_mem_allocator_allocate(ubs_hcom_memory_allocator allocator, uint64_t size, uintptr_t *address,
    uint64_t *key);

/*
 * @brief Free the address allocated by #Allocate function
 *
 * @param allocator        [in] memory allocator
 * @param address          [in] address to be freed
 *
 * @return 0 if successful
 */
int ubs_hcom_mem_allocator_free(ubs_hcom_memory_allocator allocator, uintptr_t address);

/*
 * @brief Set external logger function
 *
 * @param h                [in] the log function ptr
 */
void ubs_hcom_set_log_handler(ubs_hcom_log_handler h);

/*
 * @brief Check if local host support certain protocol
 *
 * @param t                [in] driver type
 * @param info             [out] driver info
 *
 * @return 1 if supported, 0 if not
 */
int ubs_hcom_check_local_support(ubs_hcom_driver_type t, ubs_hcom_device_info *info);
/*
 * @brief Create a driver
 *
 * @param t                [in] type of driver
 * @param name             [in] the name of driver
 * @param startOobSvr      [in] 0 or 1, 1 to start Oob server, 0 don't start Oob server
 * @param driver           [out] created driver address
 *
 * @return 0, if created successfully
 */
int ubs_hcom_driver_create(ubs_hcom_driver_type t, const char *name, uint8_t startOobSvr, ubs_hcom_driver *driver);

/*
 * @brief Set the out of bound ip and port, for endpoint connection
 *
 * @param driver           [in] the address of driver
 * @param ip               [in] the ip for listen or connect
 * @param port             [in] the port for listen or connect
 */
void ubs_hcom_driver_set_ipport(ubs_hcom_driver driver, const char *ip, uint16_t port);

/*
 * @brief Get the out of bound ip and port
 *
 * @param driver           [in] the address of driver
 * @param ipArray          [out] oob ip list
 * @param port             [out] oob port list
 * @param length           [out] the length of ipArray and portArray
 */
bool ubs_hcom_driver_get_ipport(ubs_hcom_driver driver, char ***ipArray, uint16_t **portArray, int *length);

/*
 * @brief Set oob listener of uds type
 *
 * @param name            [in] name of uds listener
 *
 */
void ubs_hcom_driver_set_udsname(ubs_hcom_driver driver, const char *name);

/*
 * @brief Add multiple oob uds listeners, if there is only one listener just use OobUdsName
 *
 * @param option          [in] option of uds listener option
 *
 */
void ubs_hcom_driver_add_uds_opt(ubs_hcom_driver driver, ubs_hcom_driver_uds_listen_opts option);

/*
 * @brief Add listen option if to enable multiple listener, duplicated ip and port cannot be added
 *
 * @param driver           [in] the address of driver
 * @param options          [in] the options of the listener
 *
 */
void ubs_hcom_driver_add_oob_opt(ubs_hcom_driver driver, ubs_hcom_driver_listen_opts options);

/*
 * @brief Initialize the driver
 *
 * @param driver           [in] the address of driver
 * @param options          [in] options for initialization
 *
 * @return 0 if successful
 */
int ubs_hcom_driver_initialize(ubs_hcom_driver driver, ubs_hcom_driver_opts options);

/*
 * @brief Start the driver, start oob accept thread (server only) and RDMA polling thread
 *
 * @param driver           [in] the address of driver
 *
 * @return 0 if successful
 */
int ubs_hcom_driver_start(ubs_hcom_driver driver);

/*
 * @brief, Connect to another driver (which is server) and new endpoint will be created if successful
 *
 * There is a retry in it in case of sever is quite busy
 *
 * @param driver           [in] the address of driver
 * @param payloadData      [in] the payloadData, must be ended with \0, i.e. it is a string
 * @param ep               [out] the new endpoint created after connect to server
 * @param flags            [in] flags of ep to be created, NET_C_EP_SELF_POLLING for self polling ep, and
 * NET_C_EP_EVENT_POLLING is the self polling mode
 *
 * @return 0 if successful
 */
int ubs_hcom_driver_connect(ubs_hcom_driver driver, const char *payloadData, ubs_hcom_endpoint *ep, uint32_t flags);

int ubs_hcom_driver_connect_with_grpno(ubs_hcom_driver driver, const char *payloadData, ubs_hcom_endpoint *ep,
    uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo);

/*
 * @brief Connect to another driver (which is server) and new endpoint will be created if successful
 *
 * There is a retry in it in case of sever is quite busy
 *
 * @param driver           [in] the address of driver
 * @param serverIp         [in] server ip
 * @param serverPort       [in] server listen port
 * @param payloadData      [in] the payloadData, must be ended with \0, i.e. it is a string
 * @param ep               [out] the new endpoint created after connect to server
 * @param flags            [in] flags of ep to be created, NET_C_EP_SELF_POLLING for self polling ep, and
 * NET_C_EP_EVENT_POLLING is the self polling mode
 *
 * @return 0 if successful
 */
int ubs_hcom_driver_connect_to_ipport(ubs_hcom_driver driver, const char *serverIp, uint16_t serverPort,
    const char *payloadData, ubs_hcom_endpoint *ep, uint32_t flags);

int ubs_hcom_driver_connect_to_ipport_with_groupno(ubs_hcom_driver driver, const char *serverIp, uint16_t serverPort,
    const char *payloadData, ubs_hcom_endpoint *ep, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo);

int ubs_hcom_driver_connect_to_ipport_with_ctx(ubs_hcom_driver driver, const char *serverIp, uint16_t serverPort,
    const char *payloadData, ubs_hcom_endpoint *ep, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo,
    uint64_t ctx);
/*
 * @brief Stop the driver
 *
 * @param driver           [in] the address of driver
 */
void ubs_hcom_driver_stop(ubs_hcom_driver driver);

/*
 * @brief Un-initialize the driver
 *
 * @param driver           [in] the address of driver
 */
void ubs_hcom_driver_uninitialize(ubs_hcom_driver driver);

/*
 * @brief Destroy the driver
 *
 * @param driver           [in] the address of driver
 *
 * @return 0 if destroy successful
 */
int ubs_hcom_driver_destroy(ubs_hcom_driver driver);

/*
 * @brief Register callback function for endpoint
 *
 * @param driver           [in] the address of driver
 * @param t                [in] handle type, could be C_EP_NEW or C_EP_BROKEN
 * @param h                [in] callback function address
 *
 * @return an inner handler address, for un-register in case of memory leak
 */
uintptr_t ubs_hcom_driver_register_ep_handler(ubs_hcom_driver driver, ubs_hcom_ep_handler_type t,
    ubs_hcom_ep_handler h, uint64_t usrCtx);

/*
 * @brief Register callback function for endpoint operation
 *
 * @param driver           [in] the address of driver
 * @param t                [in] handle type, could be C_OP_REQUEST_RECEIVED or C_OP_REQUEST_POSTED or
 * C_OP_READWRITE_DONE
 * @param h                [in] callback function address
 *
 * @return an inner handler address, for un-register in case of memory leak
 */
uintptr_t ubs_hcom_driver_register_op_handler(ubs_hcom_driver driver, ubs_hcom_op_handler_type t,
    ubs_hcom_request_handler h, uint64_t usrCtx);

/*
 * @brief Register callback function for worker idle
 *
 * @param driver           [in] the address of driver
 * @param t                [in] handler
 * @param usrCtx           [in] user context, passed to callback function
 *
 * @return an inner handler address, for un-register in case of memory leak
 */
uintptr_t ubs_hcom_driver_register_idle_handler(ubs_hcom_driver driver, ubs_hcom_idle_handler h, uint64_t usrCtx);

/*
 * @brief Register callback function for create secure info
 *
 * @param driver           [in] the address of driver
 * @param provider         [in] callback function address
 *
 * @return an inner handler address, for un-register in case of memory leak
 */
uintptr_t ubs_hcom_driver_register_secinfo_provider(ubs_hcom_driver driver, ubs_hcom_secinfo_provider provider);

/*
 * @brief Register callback function for validate secure info from peer
 *
 * @param driver           [in] the address of driver
 * @param validator        [in] callback function address
 *
 * @return an inner handler address, for un-register in case of memory leak
 */
uintptr_t ubs_hcom_driver_register_secinfo_validator(ubs_hcom_driver driver, ubs_hcom_secinfo_validator validator);

/*
 * @brief Register callback function for tls enable
 *
 * @param driver           [in] the address of driver
 * @param certCb           [in] callback to get cert
 * @param priKeyCb         [in] callback to get private key
 * @param caCb             [in] callback to get ca
 *
 * @return an inner handler address, for un-register in case of memory leak
 */
uintptr_t ubs_hcom_driver_register_tls_cb(ubs_hcom_driver driver, ubs_hcom_tls_get_cert_cb certCb,
    ubs_hcom_tls_get_pk_cb priKeyCb, ubs_hcom_tls_get_ca_cb caCb);

/*
 * @brief Un-register callback function for endpoint
 *
 * @param t                [in] handle type, could be C_EP_NEW or C_EP_BROKEN
 * @param handle           [in] callback function address returned when registered
 *
 */
void ubs_hcom_driver_unregister_ep_handler(ubs_hcom_ep_handler_type t, uintptr_t handle);

/*
 * @brief Un-register callback function for endpoint operation
 *
 * @param t                [in] handle type, could be C_OP_REQUEST_RECEIVED or C_OP_REQUEST_POSTED or
 * C_OP_READWRITE_DONE
 * @param handle           [in] callback function address returned when registered
 *
 */
void ubs_hcom_driver_unregister_op_handler(ubs_hcom_op_handler_type t, uintptr_t handle);

/*
 * @brief Un-register idle callback
 *
 * @param handle           [in] callback function address returned when registered
 */
void ubs_hcom_driver_unregister_idle_handler(uintptr_t handle);

/*
 * @brief Register a memory region, the memory will be allocated internally
 *
 * @param driver           [in] the address of driver
 * @param size             [in]  size of the memory region
 * @param mr               [out] memory region registered
 *
 * @return 0 successful
 */
int ubs_hcom_driver_create_memory_region(ubs_hcom_driver driver, uint64_t size, ubs_hcom_memory_region *mr);

/*
 * @brief Register a memory region, the memory need to be passed in
 *
 * @param driver           [in] the address of driver
 * @param address          [in]  the memory point need to be registered
 * @param size             [in]  size of the memory region
 * @param mr               [out] memory region registered
 *
 * @return 0 successful
 */
int ubs_hcom_driver_create_assign_memory_region(ubs_hcom_driver driver, uintptr_t address, uint64_t size,
    ubs_hcom_memory_region *mr);

/*
 * @brief Unregister the memory region
 *
 * @param driver           [in] the address of driver
 * @param mr               [in] memory region registered
 *
 * @return 0 successful
 */
void ubs_hcom_driver_destroy_memory_region(ubs_hcom_driver driver, ubs_hcom_memory_region mr);

/*
 * @brief Parse the memory region, get info
 *
 * @param mr               [in] memory region registered
 * @param info             [in] memory region info
 *
 * @return 0 successful
 */
int ubs_hcom_driver_get_memory_region_info(ubs_hcom_memory_region mr, ubs_hcom_memory_region_info *info);

/*
 * @brief User can set a relative object address to endpoint
 * this can be used locally only, not send to peer
 *
 * @param ep               [in] address of ep
 * @param ctx              [in] context value to set
 */
void ubs_hcom_ep_set_context(ubs_hcom_endpoint ep, uint64_t ctx);

/*
 * @brief Get the relative object address of the endpoint
 *
 * @param ep               [in] address of ep
 *
 * @return the context set by ubs_hcom_ep_set_context
 */
uint64_t ubs_hcom_ep_get_context(ubs_hcom_endpoint ep);

#define NET_INVALID_WORKER_INDEX 0xffff
#define NET_INVALID_WORKER_GROUP_INDEX 0xff
/*
 * @brief Get worker index from ep, 0xffff is invalid
 *
 * @param ep               [in] address of ep
 *
 * @return Worker index in the worker group
 */
uint16_t ubs_hcom_ep_get_worker_idx(ubs_hcom_endpoint ep);

/*
 * @brief Get worker group index from ep, 0xff is invalid
 *
 * @param ep               [in] address of ep
 *
 * @return Group index in the net driver
 */
uint8_t ubs_hcom_ep_get_workergroup_idx(ubs_hcom_endpoint ep);

/*
 * @brief Get ep listen port, 0 is invalid
 *
 * @param ep               [in] address of ep
 *
 * @return Listen port of the ep accept from
 */
uint32_t ubs_hcom_ep_get_listen_port(ubs_hcom_endpoint ep);

/*
 * @brief Get ep version of peer, the version is transferred when connecting
 *
 * This could be used for version matching for backward compatibility
 *
 * @param ep               [in] address of ep
 *
 * @return Version transferred from peer
 */
uint8_t ubs_hcom_ep_version(ubs_hcom_endpoint ep);

/*
 * @brief Set default timeout
 *
 * 1. timeout = 0: return immediately
 * 2. timeout < 0: never timeout, usually set to -1
 * 3. timeout > 0: second precision timeout.
 */
void ubs_hcom_ep_set_timeout(ubs_hcom_endpoint ep, int32_t timeout);

/*
 * @brief Two side RDMA operation, send a data to peer
 *
 * 1) the callback function 'ubs_hcom_request_handler' will be triggered
 * 2) after peer successfully received by RDMA driver, 'ubs_hcom_request_handler'
      will be trigger as well, i.e. post done
 *
 * @param ep               [in] the endpoint address
 * @param opcode           [in] opcode to peer
 * @param req              [in] request wrappers the data and size
 *
 * @return 0 for successful
 */
int ubs_hcom_ep_post_send(ubs_hcom_endpoint ep, uint16_t opcode, ubs_hcom_send_request *req);

/*
 * @brief Two side RDMA operation, send a data to peer
 *
 * 1) the callback function 'ubs_hcom_request_handler' will be triggered
 * 2) after peer successfully received by RDMA driver, 'ubs_hcom_request_handler'
      will be trigger as well, i.e. post done
 *
 * @param ep               [in] the endpoint address
 * @param opcode           [in] opcode to peer
 * @param req              [in] request wrappers the data and size
 * @param opInfo           [in] opInfo to peer
 *
 * @return 0 for successful
 */
int ubs_hcom_ep_post_send_with_opinfo(ubs_hcom_endpoint ep, uint16_t opcode, ubs_hcom_send_request *req,
    ubs_hcom_opinfo *opInfo);
/*
 * @brief Two side RDMA operation, send a data to peer
 *
 * 1) the callback function 'ubs_hcom_request_handler' will be triggered
 * 2) after peer successfully received by RDMA driver, 'ubs_hcom_request_handler'
      will be trigger as well, i.e. post done
 *
 * @param ep               [in] the endpoint address
 * @param opcode           [in] opcode to peer
 * @param req              [in] request wrappers the data and size
 * @param replySeqNo       [in]
 *
 * @return 0 for successful
 */
int ubs_hcom_ep_post_send_with_seqno(ubs_hcom_endpoint ep, uint16_t opcode, ubs_hcom_send_request *req,
    uint32_t replySeqNo);

/*
 * @brief Post send a request without opcode and header to peer, peer will be trigger new request callback also
 * without opcode and header, this could be used when you have self define header
 *
 * @param ep               [in] the endpoint address
 * @param req              [in] request information, local address and size is used only, the data is copied, you can
 * free it after called
 * @param seqNo            [in] seq no for peer to reply, must be > 0, peer can get it from context.Header().seqNo,
 * for sync client it will be matching request and response
 *
 * Behavior:
 * 1 For RDMA,
 * case a) if NET_EP_SELF_POLLING is not set, just issue the send request, not wait for sending request finished
 * case b) if NET_EP_SELF_POLLING is set, issue the send request and wait for sending arrived to peer
 *
 * @return 0 if successful
 *
 */
int ubs_hcom_ep_post_send_raw(ubs_hcom_endpoint ep, ubs_hcom_send_request *req, uint32_t seqNo);

/*
 * @brief Post send a request without opcode and header to peer, peer will be trigger new request callback also
 * without opcode and header, this could be used when you have self define header
 *
 * @param request          [in] request information, fill with local different MRs, send to the same remote MR by local
 * MRs sequence, you can free it after called. rKey/rAddress do not need to assign
 * @param seqNo            [in] seq no for peer to reply, must be > 0, peer can get it from context.Header().seqNo,
 * for sync client it will be matching request and response
 *
 * Behavior:
 * 1 For RDMA,
 * case a) if NET_EP_SELF_POLLING is not set, just issue the send request, not wait for sending request finished
 * case b) if NET_EP_SELF_POLLING is set, issue the send request and wait for sending arrived to peer
 *
 * @return 0 if successful
 *
 */
int ubs_hcom_ep_post_send_raw_sgl(ubs_hcom_endpoint ep, ubs_hcom_readwrite_request_sgl *req, uint32_t seqNo);

/*
 * @brief Read RDMA operation, read from peer
 *
 * 1) after peer successfully received by RDMA driver, 'ubs_hcom_request_handler'
      will be trigger as well, i.e. read done
 *
 * @param ep               [in] the endpoint address
 * @param req              [in] request wrappers the data and size
 *
 * @return 0 for successful
 */
int ubs_hcom_ep_post_read(ubs_hcom_endpoint ep, ubs_hcom_readwrite_request *req);
int ubs_hcom_ep_post_read_sgl(ubs_hcom_endpoint ep, ubs_hcom_readwrite_request_sgl *req);

/*
 * @brief Write RDMA operation, read from peer
 *
 * 1) after peer successfully received by RDMA driver, 'ubs_hcom_request_handler'
      will be trigger as well, i.e. read done
 *
 * @param ep               [in] the endpoint address
 * @param req              [in] request wrappers the data and size
 *
 * @return 0 for successful
 */
int ubs_hcom_ep_post_write(ubs_hcom_endpoint ep, ubs_hcom_readwrite_request *req);
int ubs_hcom_ep_post_write_sgl(ubs_hcom_endpoint ep, ubs_hcom_readwrite_request_sgl *req);

/*
 * @brief Wait for send/read/write finish, only for NET_EP_SELF_POLLING is set
 *
 * @param timeout          [in] in second
 * 1. timeout = 0: return immediately
 * 2. timeout < 0: never timeout, usually set to -1
 * 3. timeout > 0: second precision timeout max is 2000s.
 *
 * Behavior:
 * 1 for send, return when request send to peer
 * 2 for read, return when read completion
 * 3 for write, return when write completion
 *
 * @return 0 if successful
 *
 * NN_TIMEOUT if timeout
 */
int ubs_hcom_ep_wait_completion(ubs_hcom_endpoint ep, int32_t timeout);

/*
 * @brief Get the response for send request reply
 *
 * @param timeout          [in] in second
 * 1. timeout = 0: return immediately
 * 2. timeout < 0: never timeout, usually set to -1
 * 3. timeout > 0: second precision timeout max is 2000s.
 * @param ctx              [out] ctx for response message, ctx cannot be freed by caller
 *
 * @return 0 if successful
 */
int ubs_hcom_ep_receive(ubs_hcom_endpoint ep, int32_t timeout, ubs_hcom_response_context **ctx);

/*
 * @brief Get the response for send request reply
 *
 * @param timeout          [in] in second
 * 1. timeout = 0: return immediately
 * 2. timeout < 0: never timeout, usually set to -1
 * 3. timeout > 0: second precision timeout max is 2000s.
 * @param ctx              [out] ctx for response message, ctx cannot be freed by caller
 *
 * @return 0 if successful
 */
int ubs_hcom_ep_receive_raw(ubs_hcom_endpoint ep, int32_t timeout, ubs_hcom_response_context **ctx);

/*
 * @brief Get the response for send request reply
 *
 * @param timeout          [in] in second
 * 1. timeout = 0: return immediately
 * 2. timeout < 0: never timeout, usually set to -1
 * 3. timeout > 0: second precision timeout max is 2000s.
 * @param ctx              [out] ctx for response message, ctx cannot be freed by caller
 *
 * @return 0 if successful
 */
int ubs_hcom_ep_receive_raw_sgl(ubs_hcom_endpoint ep, int32_t timeout, ubs_hcom_response_context **ctx);

/*
 * @brief Increase the internal reference count, need to call this when forwarding the context to another thread to
 * process
 *
 * @param ep,              [in] the endpoint address
 */
void ubs_hcom_ep_refer(ubs_hcom_endpoint ep);

/*
 * @brief Close endpoint, then will async call broken function
 */
void ubs_hcom_ep_close(ubs_hcom_endpoint ep);

/*
 * @brief Destroy the end point
 *
 * @param ep,              [in] the endpoint address
 */
void ubs_hcom_ep_destroy(ubs_hcom_endpoint ep);

const char *ubs_hcom_err_str(int16_t errCode);

/*
 * @brief Estimated Encrypt length for input raw len
 *
 * @param ep               [in] the endpoint address
 * @param rawLen           [in] raw length before encrypt
 *
 * @return the length after encrypt
 */
uint64_t ubs_hcom_estimate_encrypt_len(ubs_hcom_endpoint ep, uint64_t rawLen);

/*
 * @brief Encrypt data
 *
 * @param ep               [in] the endpoint address
 * @param rawData          [in] raw data before encrypt
 * @param rawLen           [in] raw data length before encrypt
 * @param cipher           [out] cipher data after encrypt
 * @param cipherLen        [out] cipher data length after encrypt
 *
 * @return 0 if success
 */
int ubs_hcom_encrypt(ubs_hcom_endpoint ep, const void *rawData, uint64_t rawLen, void *cipher, uint64_t *cipherLen);

/*
 * @brief Estimate Decrypt length
 *
 * @param ep               [in] the endpoint address
 * @param cipherLen        [in] cipher len before decrypt
 *
 * @return the raw length after decrypt
 */
uint64_t ubs_hcom_estimate_decrypt_len(ubs_hcom_endpoint ep, uint64_t cipherLen);

/*
 * @brief Decrypt data
 *
 * @param ep               [in] the endpoint address
 * @param cipher           [in] cipher data after encrypt
 * @param cipherLen        [in] cipher data length after encrypt
 * @param rawData          [out] raw data before encrypt
 * @param rawLen           [out] raw data length before encrypt
 *
 * @return 0 if success
 */
int ubs_hcom_decrypt(ubs_hcom_endpoint ep, const void *cipher, uint64_t cipherLen, void *rawData, uint64_t *rawLen);

/*
 * @brief Send shm fds, only shm protocol support
 *
 * @param ep               [in] the endpoint address
 * @param fds              [in] fds to send
 * @param len              [in] fds count to send
 *
 * @return 0 if success
 */
int ubs_hcom_send_fds(ubs_hcom_endpoint ep, int fds[], uint32_t len);

/*
 * @brief Receive shm fds, only shm protocol support
 *
 * @param ep               [in] the endpoint address
 * @param fds              [out] fds to be received
 * @param len              [in] fds count to be received
 * @param timeoutSec       [in] timeout in second for receive. -1 is never timeout
 *
 * @return 0 if success
 */
int ubs_hcom_receive_fds(ubs_hcom_endpoint ep, int fds[], uint32_t len, int timeoutSec);

/*
 * @brief Get remote uds ids include pid uid gid, only support in oob server and when oob type is uds
 *
 * @param ep               [in] the endpoint address
 * @param idInfo           [out] remote uds idInfo
 *
 * @return 0 if success
 */
int ubs_hcom_get_remote_uds_info(ubs_hcom_endpoint ep, ubs_hcom_uds_id_info *idInfo);
#ifdef __cplusplus
}
#endif

#endif // HCOM_CAPI_V2_HCOM_C_H_
