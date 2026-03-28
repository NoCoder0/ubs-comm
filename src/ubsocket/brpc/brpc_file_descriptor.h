/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Provide the utility for umq buffer, iov, etc
 * Author:
 * Create: 2025-07-31
 * Note:
 * History: 2025-07-31
*/

#ifndef BRPC_FILE_DESCRIPTOR_H
#define BRPC_FILE_DESCRIPTOR_H

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <set>
#include <unordered_set>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <string>
#include <netinet/in.h>
#include "umq_pro_api.h"
#include "umq_errno.h"
#include "brpc_context.h"
#include "brpc_share_jfr.h"
#include "file_descriptor.h"
#include "configure_settings.h"
#include "qbuf_list.h"
#include "buffer_util.h"
#include "statistics.h"
#include "share_jfr_common.h"
#include "cli_message.h"
#include "umq_dfx_types.h"
#include "umq_dfx_api.h"
#include "utracer.h"
#include "net_common.h"
#include "ub_thread_pool.h"
#include "ub_lock_manager.h"

#define UMQ_BIND_INFO_SIZE_MAX  (512)
#define UMQ_BIND_SYNC_MSG       "SYNC_DONE"
#define DIVIDED_NUMBER          (2)
#define CACHE_LINE_ALIGNMENT    (64)
#define HANDLE_THRESHOLD        (2)
#define RETRIEVE_THRESHOLD      (1)
#define REPORT_THRESHOLD        (1)

#ifndef EID_FMT
#define EID_FMT "%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#endif

#ifndef EID_RAW_ARGS
#define EID_RAW_ARGS(eid) eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6], eid[7], eid[8], eid[9], \
eid[10], eid[11], eid[12], eid[13], eid[14], eid[15]
#endif

#ifndef EID_ARGS
#define EID_ARGS(eid) EID_RAW_ARGS((eid).raw)
#endif

constexpr uint64_t SIZE_8K  = 8192;
constexpr uint64_t SIZE_16K = 16384;
constexpr uint64_t SIZE_32K = 32768;
constexpr uint64_t SIZE_64K = 65536;
constexpr uint64_t MASK_DIFF = 1;
constexpr uint64_t IOBUF_DIFF = 32;
constexpr uint16_t REFILL_THRESHOLD = 32;
constexpr int RETRY_NEEDED = 1;
// to improve the efficiency, do one ack event operation per GET_PER_ACK times get event operation(same as brpc)
constexpr uint32_t GET_PER_ACK = 32;
// currently, poll batch use 32 is for the balance of performance and efficiency
constexpr uint32_t POLL_BATCH_MAX = 32;

namespace Brpc {
using namespace Statistics;
// adapt to brpc, brpc IOBuf block use 8k as buffer slice with a 32 bytes head, thus, RX buffer size is 8160
inline uint32_t BrpcIOBufSize()
{
    umq_buf_block_size_t blockType = Context::GetContext()->GetIOBlockType();
    switch (blockType) {
        case BLOCK_SIZE_8K:  return SIZE_8K - IOBUF_DIFF;
        case BLOCK_SIZE_16K: return SIZE_16K - IOBUF_DIFF;
        case BLOCK_SIZE_32K: return SIZE_32K - IOBUF_DIFF;
        case BLOCK_SIZE_64K: return SIZE_64K - IOBUF_DIFF;
        default:
            return SIZE_8K - IOBUF_DIFF;
    }
}
class FallbackTcpMgr {
public:
    ALWAYS_INLINE bool TxUseTcp(void)
    {
        return m_tx_use_tcp;
    }
    
    ALWAYS_INLINE bool RxUseTcp(void)
    {
        return m_rx_use_tcp;
    } 

    ALWAYS_INLINE bool UseTcp(void)
    {
        return m_rx_use_tcp || m_tx_use_tcp;
    }
    
protected:
    
    bool m_tx_use_tcp = false;
    bool m_rx_use_tcp = false;
}; 

class EidRegistry {
public:
    bool RegisterEid(const umq_eid_t& eid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_registered_eids.insert(eid).second;
    }

    bool IsRegisteredEid(const umq_eid_t& eid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_registered_eids.count(eid) > 0;
    }

    bool UnregisterEid(const umq_eid_t& eid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_registered_eids.erase(eid) > 0;
    }

    // 控制建链轮询
    // 注册或者替换index值
    void RegisterOrReplaceEidIndex(const umq_eid_t& eid, uint32_t index) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_eid_index_map[eid] = index;
    }

    // 仅检查eid是否存在（不获取值）
    bool IsRegisteredEidIndex(const umq_eid_t& eid) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_eid_index_map.find(eid) != m_eid_index_map.end();
    }

    // 获得index值
    bool GetEidIndex(const umq_eid_t& eid, uint32_t& index) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_eid_index_map.find(eid);
        if (it != m_eid_index_map.end()) {
            index = it->second;
            return true;
        }
        return false;
    }

    //删除 eid 及其值
    bool UnregisterEidIndex(const umq_eid_t& eid)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_eid_index_map.erase(eid) > 0;
    }

private:
    mutable std::mutex m_mutex;
    std::unordered_set<umq_eid_t, UmqEidHash> m_registered_eids;   // 存储已经被umq_dev_add eid信息
    std::unordered_map<umq_eid_t, uint32_t, UmqEidHash> m_eid_index_map; // 控制轮询，对端bonding eid与route_list index对应关系
};

class RouteListRegistry {
public:
    // 注册或者替换routeList值
    void RegisterOrReplaceRouteList(const umq_eid_t &eid, const umq_route_list_t &routeList)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_route_list_map[eid] = routeList;
    }

    // 仅检查eid对应的routeList是否存在（不获取值）
    bool IsRegisteredRouteList(const umq_eid_t &eid) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_route_list_map.find(eid) != m_route_list_map.end();
    }

    bool GetRouteList(const umq_eid_t &eid, umq_route_list_t &routeList) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_route_list_map.find(eid);
        if (it != m_route_list_map.end()) {
            routeList = it->second;
            return true;
        }
        return false;
    }

    // 删除 RouteList
    bool UnregisterRouteList(const umq_eid_t &eid)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_route_list_map.erase(eid) > 0;
    }

private:
    mutable std::mutex m_mutex;
    std::unordered_map<umq_eid_t, umq_route_list_t, UmqEidHash> m_route_list_map; // 存储可用的route_list列表
};

class SocketFd : public ::SocketFd, public FallbackTcpMgr, public Statistics::StatsMgr {
public:
    enum error_code {
        OK,
        UMQ_ERROR,
        FATAL_ERROR
    };

    SocketFd(int fd, int event_fd) : ::SocketFd(fd), StatsMgr(fd)
    {
        QBUF_LIST_INIT(&m_tx.m_head_buf);
        QBUF_LIST_INIT(&m_tx.m_tail_buf);
        QBUF_LIST_INIT(&m_rx.m_umq_buf_cache_head);
        QBUF_LIST_INIT(&m_rx.m_umq_buf_cache_tail);
        m_tx_window_capacity = Context::GetContext()->GetTxDepth();
        m_rx_window_capacity = Context::GetContext()->GetRxDepth();
        m_tx.m_window_size = m_tx_window_capacity;
        m_rx.m_refill_threshold = REFILL_THRESHOLD;
        m_tx.m_handle_threshold = HANDLE_THRESHOLD;
        m_tx.m_retrieve_threshold = RETRIEVE_THRESHOLD;
        m_tx.m_report_threshold = REPORT_THRESHOLD;
        m_rx.m_readv_unlimited = Context::GetContext()->GetReadvUnlimited();
        if (Context::GetContext()->GetTraceEnable()) {
            m_context_trace_enable = true;
        }
        m_event_fd = event_fd;
        m_rx.m_remaining_size = 0;
    }

    SocketFd(int fd, uint64_t protocol_negotiation, uint32_t protocol_negotiation_recv_size) :
        ::SocketFd(fd), StatsMgr(fd)
    {
        m_tx.m_protocol_negotiation = protocol_negotiation;
        m_tx.m_protocol_negotiation_recv_size = protocol_negotiation_recv_size;
        m_tx_use_tcp = true;
    }

    virtual ~SocketFd()
    {
        UnbindAndFlushRemoteUmq();
        DestroyLocalUmq();
        if (m_event_fd >= 0) {
            OsAPiMgr::GetOriginApi()->close(m_event_fd);
            m_event_fd = -1;
        }

        if (rxQueue != nullptr) {
            delete rxQueue;
            rxQueue = nullptr;
        }

        if (share_jfr_rx_epoll_event != nullptr && !share_jfr_rx_epoll_event->IsAddEpollEvent()) {
            delete share_jfr_rx_epoll_event;
            share_jfr_rx_epoll_event = nullptr;
        }

        if (m_context_trace_enable) {
            SubMConnCount();
            if (m_peer_info.type_fd == 1) {
                SubMActiveConnCount();
            }
        }
    }
    ALWAYS_INLINE const std::string& GetPeerIp() const { return m_peer_info.peer_ip; }
    ALWAYS_INLINE const umq_eid_t& GetPeerEid() const { return m_peer_info.peer_eid; }
    ALWAYS_INLINE int GetPeerFd() const { return m_peer_info.peer_fd; }
    ALWAYS_INLINE int GetEventFd(void)
    {
        return m_event_fd;
    }

    ALWAYS_INLINE uint64_t GetLocalUmqHandle(void)
    {
        return m_local_umqh;
    }

    ALWAYS_INLINE uint64_t GetMainUmqHandle(void)
    {
        return m_main_umqh;
    }

    /**
     * @brief 从sockaddr结构体提取IP地址字符串
     * @param address 指向sockaddr结构体的指针
     * @return 成功返回IP地址字符串，失败返回空字符串
     */
    ALWAYS_INLINE std::string ExtractIpFromSockAddr(const struct sockaddr *address)
    {
        if (address == nullptr) {
            return "";
        }

        char ip_str[INET6_ADDRSTRLEN] = {0};
        const char* result = nullptr;

        if (address->sa_family == AF_INET) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)address;
            result = inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
            m_peer_info.peer_ip = ip_str;
        } else if (address->sa_family == AF_INET6) {
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)address;
            result = inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
            m_peer_info.peer_ip = ip_str;
        }

        return (result != nullptr) ? std::string(ip_str) : "";
    }

    ALWAYS_INLINE int ProtocolMatching(int fd)
    {
        uint64_t protocol_negotiation = 0;
        ssize_t protocol_negotiation_recv_size = 0;
        int ret = ValidateProtocol(fd, protocol_negotiation, protocol_negotiation_recv_size);
        Context *context = Context::GetContext();
        if (ret > 0 && !context->AutoFallbackTCP()) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to accept as protocol dismatch, Peer IP:%s\n",
                GetPeerIp().c_str());
            OsAPiMgr::GetOriginApi()->close(fd);
            return -1;
        }
        if (ret > 0) {
            /* IF the protocol negotiation verification fails, it is still necessary to create a socket fd object
            * to store the protocol negotiation information, so that the received information can be reported to
            * the user when readv is called. */
            SocketFd *socket_fd_obj = nullptr;
            try {
                socket_fd_obj = new SocketFd(fd, protocol_negotiation, (uint32_t)protocol_negotiation_recv_size);
                Fd<::SocketFd>::OverrideFdObj(fd, socket_fd_obj);
                RPC_ADPT_VLOG_WARN("Auto fallback to TCP,Peer IP:%s, fd: %d\n", GetPeerIp().c_str(), fd);
            } catch (std::exception& e) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "%s\n", e.what());
                OsAPiMgr::GetOriginApi()->close(fd);
                return -1;
            }
        }
        return ret;
    }

    ALWAYS_INLINE void ProcessUBConnection(int fd, UbSem* pSem)
    {
        bool is_blocking = IsBlocking(fd);
        if (is_blocking) {
            // set non_blocking to apply timeout by chrono(send/recv can be returned immediately)
            SetNonBlocking(fd);
        }

        int ret = ProtocolMatching(fd);
        if (ret == 0 && DoAccept(fd) != 0) {
            RPC_ADPT_VLOG_WARN("Fatal error occurred,Peer IP:%s, fd: %d fallback to TCP/IP", GetPeerIp().c_str(), fd);
            /* Clear messages that already exist on the TCP link to prevent
                * dirty messages from affecting user data transmission */
            FlushSocketMsg(fd);
        } else if (ret < 0) {
            pSem->post();
            return;
        }

        if (is_blocking) {
            // reset
            SetBlocking(fd);
        }

        if (m_context_trace_enable) {
            m_peer_info.type_fd = 0;
            UpdateTraceStats(StatsMgr::CONN_COUNT, 1);
        }
        pSem->post();
    }

    ALWAYS_INLINE int Accept(struct sockaddr *address, socklen_t *address_len)
    {
        int retCode = 0;
        TRACE_DELAY_AUTO(BRPC_ACCEPT_CALL, retCode);
        int fd = OsAPiMgr::GetOriginApi()->accept(m_fd, address, address_len);
        if (fd >= 0 && address != nullptr) {
            SocketFd* socket_fd_obj = static_cast<SocketFd*>(Fd<::SocketFd>::GetFdObj(fd));
            if (socket_fd_obj) {
                // 使用提取的接口获取IP地址
                std::string peer_ip = ExtractIpFromSockAddr(address);
                // 对端fd就是accept返回的fd
                m_peer_info.peer_fd = fd;
            }
        }
        retCode = fd;
        if (m_tx_use_tcp || m_rx_use_tcp) {
            return fd;
        }

        if (fd < 0) {
            /*
            * 1. 若全连接队列不为空：
            * a. 正常情况下，返回非负整数的fd，tcp连接已完成，则执行DoAccept，且需要等待ub连接完成再返回，
            * b. 异常情况下，比如内存不足、文件描述符达到系统上限、客户端异常中止连接等，保持原错误码直接返回上层，由上层应用决定后续动作
            * 2. 若全连接队列为空：
            * a. fd为非阻塞，则返回-1，errno为EAGAIN/EWOULDBLOCK，保持原错误码直接返回上层
            * b. fd为阻塞，则等待直到有连接完成或者触发异常，比如被信号中断，返回-1，errno为EINTR，保持原错误码直接返回上层
            */
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {  // nonblocking
                char buf[NET_STR_ERROR_BUF_SIZE] = {0};
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "tcp accept failed,Peer IP:%s, fd: %d, %d, %s\n",
                    GetPeerIp().c_str(), m_fd, errno,
                        NetCommon::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
                return fd;
            }
            char buf[NET_STR_ERROR_BUF_SIZE] = {0};
            RPC_ADPT_VLOG_DEBUG("tcp accept need try again, fd: %d, %d, %s\n",
                m_fd, errno, NetCommon::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
            return fd;
        }

        auto manager = UbLockManager::instance();
        auto sem = manager.createSem();
        sem->init(0, 0);

        auto& threadPool = UBThreadPool::GetInstance();

        // submit to thread pool for asynchronous processing
        threadPool.Submit([this, fd, pSem = sem.get()]() {
            this->ProcessUBConnection(fd, pSem);
        });
        sem->wait();
        return fd;
    }

    int ConnectExchangeEid(umq_eid_t *connEid){
        Context *context = Context::GetContext();
        if(!context->IsBonding()){
            return 0;
        }
        umq_eid_t localEid = context->GetDevSrcEid();
        if (SendSocketData(m_fd, &localEid, sizeof(umq_eid_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_eid_t)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send local eid message in connect,Peer IP:%s, fd: %d\n",
                              GetPeerIp().c_str(), m_fd);
            return -1;
        }

        umq_eid_t remoteEid;
        if (RecvSocketData(
            m_fd, &remoteEid, sizeof(umq_eid_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_eid_t)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to receive remote eid message in connect,Peer IP:%s, fd: %d\n",
                              GetPeerIp().c_str(), m_fd);
            return -1;
        }
        // 保存对端EID
        m_peer_info.peer_eid = remoteEid;

        *connEid = context->GetDevSrcEid();
        
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (enable_share_jfr || localEid != remoteEid) {
            dev_schedule_policy peerSchedulePolicy;
            if (RecvSocketData(m_fd, &peerSchedulePolicy, sizeof(dev_schedule_policy), CONTROL_PLANE_TIMEOUT_MS) !=
                sizeof(dev_schedule_policy)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to receive remote schedule policy in connect,Peer IP:%s, fd: %d\n",
                                  GetPeerIp().c_str(), m_fd);
                return -1;
            }

            dev_schedule_policy schedulePolicy = context->GetDevSchedulePolicy();
            if (SendSocketData(m_fd, &schedulePolicy, sizeof(dev_schedule_policy), CONTROL_PLANE_TIMEOUT_MS) !=
                sizeof(dev_schedule_policy)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send local policy in connect,Peer IP:%s, fd: %d\n",
                                  GetPeerIp().c_str(), m_fd);
                return -1;
            }

            if (peerSchedulePolicy == schedulePolicy && schedulePolicy == dev_schedule_policy::CPU_AFFINITY) {
                RPC_ADPT_VLOG_WARN("Use consistent schedule policy CPU_AFFINITY in connect,Peer IP:%s, fd: %d\n",
                                   GetPeerIp().c_str(), m_fd);
                // 使用亲和策略需要发送socketId
                int mProcessSocketId = context->GetProcessSocketId();
                if (SendSocketData(m_fd, &mProcessSocketId, sizeof(int), CONTROL_PLANE_TIMEOUT_MS) != sizeof(int)) {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                      "Failed to send local socket id in connect,Peer IP:%s, fd: %d\n",
                                      GetPeerIp().c_str(), m_fd);
                    return -1;
                }
            }
          
            umq_route_t connRoute;
            if (RecvSocketData(
                m_fd, &connRoute, sizeof(umq_route_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_route_t)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to receive remote eid message in connect,Peer IP:%s, fd: %d\n",
                                  GetPeerIp().c_str(), m_fd);
                return -1;
            }

            if (CheckDevAdd(connRoute.dst) != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to add dev in connect,Peer IP:%s, fd: %d\n",
                                  GetPeerIp().c_str(), m_fd);
                return -1;
            }
            // 保存对端EID
            m_peer_info.peer_eid = connRoute.src;
            *connEid = connRoute.dst;
        }

        return 0;
    }

    int ConnectExchangeTransMode()
    {
        Context *context = Context::GetContext();

        ub_trans_mode localTransMode = context->GetUbTransMode();
        if (SendSocketData(m_fd, &localTransMode, sizeof(ub_trans_mode), CONTROL_PLANE_TIMEOUT_MS)
            != sizeof(ub_trans_mode)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to send local TransMode message in connect,Peer eid:" EID_FMT
                              ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }
        ub_trans_mode remoteTransMode;
        if (RecvSocketData(m_fd, &remoteTransMode, sizeof(ub_trans_mode), CONTROL_PLANE_TIMEOUT_MS)
            != sizeof(ub_trans_mode)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to receive remote TransMode message in connect,Peer eid:" EID_FMT
                              ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }

        if (localTransMode != remoteTransMode) {
            if (remoteTransMode < localTransMode) {
                context->SetUbTransMode(remoteTransMode);
            } else {
                context->SetUbTransMode(localTransMode);
            }
        }

        return 0;
    }

    int DoUbConnect(umq_eid_t &connEid)
    {
        CpMsg local_cp_msg;
        CpMsg remote_cp_msg;
        char send_sync_msg[] = UMQ_BIND_SYNC_MSG;
        char recv_sync_msg[] = UMQ_BIND_SYNC_MSG;

        int ret = CreateLocalUmq(&connEid);
        if ((ret < 0) || (ret == RETRY_NEEDED)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to create umq,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return ret;
        }

        local_cp_msg.queue_bind_info_size =
            umq_bind_info_get(m_local_umqh, local_cp_msg.queue_bind_info, UMQ_BIND_INFO_SIZE_MAX);
        if (local_cp_msg.queue_bind_info_size == 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to execute umq_bind_info_get,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return RETRY_NEEDED;
        }
        
        uint32_t len = sizeof(local_cp_msg) - sizeof(uint64_t);
        if (SendSocketData(m_fd, &local_cp_msg.queue_bind_info_size, len, CONTROL_PLANE_TIMEOUT_MS) != len) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to send local control message,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }
        RPC_ADPT_VLOG_DEBUG("send local control message, fd: %d, cp msg len: %d, bind info len: %d\n",
            m_fd, sizeof(local_cp_msg), local_cp_msg.queue_bind_info_size);
        
        if (RecvSocketData(
            m_fd, &remote_cp_msg, sizeof(remote_cp_msg), CONTROL_PLANE_TIMEOUT_MS) != sizeof(remote_cp_msg)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to receive remote control message,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }
        RPC_ADPT_VLOG_DEBUG("recv remote control message, fd: %d, cp msg len: %d, bind info len: %d\n",
            m_fd, sizeof(remote_cp_msg), remote_cp_msg.queue_bind_info_size);

        if (umq_bind(m_local_umqh, remote_cp_msg.queue_bind_info, remote_cp_msg.queue_bind_info_size) != UMQ_SUCCESS) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to execute umq_bind,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return RETRY_NEEDED;
        }
        m_bind_remote = true;

        // 1650 RC mode not support post rx right after create jetty, thus, move post rx operation after bind()
        if (PrefillRx() != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to fill rx buffer to umq,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }

        if (SendSocketData(
            m_fd, send_sync_msg, sizeof(send_sync_msg), CONTROL_PLANE_TIMEOUT_MS) != sizeof(send_sync_msg)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to send sync done message,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }

        if (RecvSocketData(
            m_fd, recv_sync_msg, sizeof(recv_sync_msg), CONTROL_PLANE_TIMEOUT_MS) != sizeof(recv_sync_msg) ||
            strcmp(recv_sync_msg, UMQ_BIND_SYNC_MSG) != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to receive sync done message,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }

        return 0;
    }

    int DoConnect(void)
    {
        uint64_t protocol_negotiation = CONTROL_PLANE_PROTOCOL_NEGOTIATION;
        if (SendSocketData(
            m_fd, &protocol_negotiation, sizeof(uint64_t), NEGOTIATE_TIMEOUT_MS) != sizeof(uint64_t)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send protocol negotiation, fd: %d\n", m_fd);
            return -1;
        }

        int ret = ProtocolMatching(m_fd);
        if (ret < 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to match protocol in connect, Peer IP:%s, fd: %d\n",
                              GetPeerIp().c_str(), m_fd);
            return ret;
        } else if (ret > 0) {
            // Failed verification then fallback to tcp and return directly
            return 0;
        }

        if (ConnectExchangeTransMode() != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to exchange TransMode in connect,Peer IP:%s, fd: %d\n",
                              GetPeerIp().c_str(), m_fd);
            return -1;
        }

        umq_eid_t connEid;
        if (ConnectExchangeEid(&connEid) < 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to exchange eid in connect,Peer IP:%s, fd: %d\n",
                              GetPeerIp().c_str(), m_fd);
            return -1;
        }

        int ackRet = DoUbConnect(connEid);
        if (ackRet != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to receive sync done message,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
        }
        if (SendSocketData(
            m_fd, &ackRet, sizeof(int), CONTROL_PLANE_TIMEOUT_MS) != sizeof(int)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send ack ret,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }

        int peerRet;
        if (RecvSocketData(
            m_fd, &peerRet, sizeof(int), CONTROL_PLANE_TIMEOUT_MS) != sizeof(int)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to receive peer ack ret,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            return -1;
        }

        // 1.用户直接指定普通设备建链，DoUbAccept等于RETRY_NEEDED，不重试
        // 2.用户指定bonding设备建链，但如果是节点内回环场景，DoUbAccept等于RETRY_NEEDED，不重试
        // 3.用户指定bonding设备建链，（跨节点场景）若使用get_route_list获得的eid建链，DoUbAccept等于RETRY_NEEDED，重试
        Context *context = Context::GetContext();
        umq_eid_t localEid = context->GetDevSrcEid();
        if ((context->IsBonding()) && (connEid != localEid)&& (ackRet == RETRY_NEEDED || peerRet == RETRY_NEEDED)) {
            UnbindAndFlushRemoteUmq();
            DestroyLocalUmq();
            // 重试
            umq_route_t otherConnRoute;
            if (RecvSocketData(
                m_fd, &otherConnRoute, sizeof(umq_route_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_route_t)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to receive remote eid message in retry connect,Peer eid:" EID_FMT
                                  ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
                return -1;
            }

            if (CheckDevAdd(otherConnRoute.dst) != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to add dev in retry connect,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
                return -1;
            }
            ackRet = DoUbConnect(otherConnRoute.dst);
            if (ackRet != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to get new connect in retry connect,Peer eid:" EID_FMT
                                  ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
                return -1;
            }
        } else {
            if (ackRet != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to get new connect in connect,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
                return -1;
            }
        }
        
        if (m_context_trace_enable) {
            InitStatsMgr();
        }

        if (context && context->GetUsePolling()) {
            Socket *sock = NULL;
            if (PollingEpoll::GetInstance().SocketCreate(&sock, m_fd, SocketType::SOCKET_TYPE_TCP_CLIENT,
                                                         m_local_umqh) != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "SocketCreate failed,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            } else {
                PollingEpoll::GetInstance().AddSocket(m_fd, sock);
            }
        }

        RPC_ADPT_VLOG_INFO("UB connection has been successfully established new fd: %d\n", m_fd);

        PrintQbufPoolInfo();

        return 0;
    }

    ALWAYS_INLINE int Connect (const struct sockaddr *address, socklen_t address_len)
    {
        int ret = 0;
        TRACE_DELAY_AUTO(BRPC_CONNECT_CALL, ret);
        ret = OsAPiMgr::GetOriginApi()->connect(m_fd, address, address_len);
        if (address != nullptr) {
            // 使用提取的接口获取IP地址
            std::string peer_ip = ExtractIpFromSockAddr(address);
            // 对端fd就是accept返回的fd
            m_peer_info.peer_fd = m_fd;
        }

        if (m_tx_use_tcp || m_rx_use_tcp) {
            return ret;
        }

        if (ret == 0) {
            RPC_ADPT_VLOG_INFO("tcp connect succeed, fd %d\n", m_fd);
        } else {
            /* fd是非阻塞套接字
            * 1. 第一次调用connect返回-1，errno为EINPROGRESS，网络正在建连；
            * 2. 若未建连状态下，第n次对fd调用connect，n>=2，返回-1，errno为EALREADY；
            * 3. 若建连成功，且当前不是第二次调connect，返回-1，errno为EISCONN；否则返回0（非阻塞套接字）
            *
            * 若ret = 0 或者errno 是EISCONN，tcp连接已完成，则执行DoConnect，且需要等待连接完成再返回，
            * 若errno是EINPROGRESS/EALREADY，fd最终会变为连接状态，则执行DoConnect，且不需要等待ub连接完成
            * 若errno是EINTR/EADDRNOTAVAIL/EHOSTUNREACH等错误码，tcp连接失败，则不执行DoConnect，保持原错误码直接返回上层，由上层应用决定后续动作
            */
            if (errno == EINPROGRESS || errno == EALREADY) {
                char buf[NET_STR_ERROR_BUF_SIZE] = {0};
                RPC_ADPT_VLOG_DEBUG("tcp connect inprogress:%s, fd %d\n",
                    NetCommon::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE), m_fd);
            } else if (errno != EISCONN) {
                char buf[NET_STR_ERROR_BUF_SIZE] = {0};
                RPC_ADPT_VLOG_NOTICE("tcp connect failed, errno %d, err msg: %s, fd %d\n", errno,
                    NetCommon::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE), m_fd);
                return ret;
            }
        }

        bool is_blocking = IsBlocking(m_fd);
        if (is_blocking) {
            // set non_blocking to apply timeout by chrono(send/recv can be returned immediately)
            SetNonBlocking(m_fd);
        }

        ret = DoConnect();
        if (ret != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to establish UB connection,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), m_fd);
            Fd<::SocketFd>::OverrideFdObj(m_fd, nullptr);
            /* Clear messages that already exist on the TCP link to prevent 
                 * dirty messages from affecting user data transmission*/
            FlushSocketMsg(m_fd);
        }

        if (is_blocking) {
            // reset
            SetBlocking(m_fd);
        }

        if (m_context_trace_enable) {
            m_peer_info.type_fd = 1;
            UpdateTraceStats(StatsMgr::CONN_COUNT, 1);
            UpdateTraceStats(StatsMgr::ACTIVE_OPEN_COUNT, 1);
        }

        return ret;
    }

    virtual void OutputStats(std::ostringstream &oss) 
    {
        StatsMgr::OutputStats(oss);
    }

    virtual void GetSocketCLIData(Statistics::CLISocketData *data)
    {
        StatsMgr::GetSocketCLIData(data);
    }

    uint64_t FloorMask()
    {
        umq_buf_block_size_t blockType = Context::GetContext()->GetIOBlockType();
        switch (blockType) {
            case BLOCK_SIZE_8K:  return SIZE_8K - MASK_DIFF;
            case BLOCK_SIZE_16K: return SIZE_16K - MASK_DIFF;
            case BLOCK_SIZE_32K: return SIZE_32K - MASK_DIFF;
            case BLOCK_SIZE_64K: return SIZE_64K - MASK_DIFF;
            default:
                return SIZE_8K - MASK_DIFF; 
        }
    }

    static const uint32_t SGE_MAX = 6;
    // currently, the upper limit of post batch for umq is 64
    static const uint32_t POST_BATCH_MAX = 64;
    /* unsolicited bytes use the same setting as brpc
     * accumulated bytes exceed UNSOLICITED_BYTES_MAX will generate a solicited interrupt event at remote */
    static const uint32_t UNSOLICITED_BYTES_MAX = 1048576;
    // defaultRX refill threshold. If RX depth less then REFILL_RX_THRESHOLD, then, threshold change to 1
    static const uint16_t REFILL_RX_THRESHOLD = 32;
    /* handle tx(poll tx cqe, set tx signaled, i.e.) when accumulated number equals to m_tx_window_capacity / 8 */
    static const uint16_t HANDLE_TX_THRESHOLD_RATIO_DIVISOR = 4;
    /* process up to m_tx_window capacity / 16 tx cqe each time */
    static const uint16_t RETRIEVE_TX_THRESHOLD_RATIO_DIVISOR = 8;
    // protocol negotiation is the 0xff + ASCII of "R" + "P" + "C" + "A" + "D" + "P" + "T"
    static const uint64_t CONTROL_PLANE_PROTOCOL_NEGOTIATION = 0xff52504341445054;
    static const uint8_t CONTROL_PLANE_PROTOCOL_NEGOTIATION_PREFIX = 0xff;
    static const uint64_t CONTROL_PLANE_PROTOCOL_NEGOTIATION_BODY = 0x52504341445054;
    static const uint32_t NEGOTIATE_TIMEOUT_MS = 10;
    // Current UB jetty handshake is synchronous that brpc acceptor can't yield from the point.
    // Ensure the connector has at most 5s to wait from server socket.
    static const uint32_t CONTROL_PLANE_TIMEOUT_MS = 20000;
    static const uint32_t DATA_PLANE_TIMEOUT_MS = 100;
    static const uint32_t POLL_TX_RETRY_MAX_CNT = 50;
    static const uint32_t FLUSH_TIMEOUT_MS = 200;
    static const uint32_t FALLBAKC_TCP_RESENT_TIMEOUT_MS = 800;
    static const uint32_t WAIT_UMQ_READY_TIMEOUT_US = 100;
    // max wait 1s for umq ready
    static const uint32_t WAIT_UMQ_READY_ROUND = 10000;

    ALWAYS_INLINE ssize_t ReadV(const struct iovec *iov, int iovcnt)
    {
        int retCode = -1;
        TRACE_DELAY_AUTO(BRPC_READV_CALL, retCode);
        if (m_rx_use_tcp) {
            ssize_t size = OsAPiMgr::GetOriginApi()->readv(m_fd, iov, iovcnt);
            retCode = size < 0 ? -1 : 0;
            return size;
        }

        if (iov == nullptr || iovcnt == 0) {
            errno = EINVAL;
            return -1;
        }

        /* if socket failed to pass protocol negotiation validation, then
         * (1) pass the received protocol negotiation as message to caller;
         * (2) when all the received message passed to caller, fallback to tcp/ip */
        ssize_t rx_total_len = OutputErrorMagicNumber(iov, iovcnt);
        if (rx_total_len > 0) {
            retCode = 0;
            return rx_total_len;
        }

        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (!enable_share_jfr && m_rx.m_get_and_ack_event) {
            if (GetAndAckEvent(UMQ_IO_RX) < 0) {
                errno = EIO;
                return -1;
            }
            m_rx.m_get_and_ack_event = false;
        }

        uint32_t max_buf_size;
        if (m_rx.m_readv_unlimited) {
            max_buf_size = UINT32_MAX;
        } else {
            max_buf_size = 0;
            for (int i = 0; i < iovcnt; i++) {
                max_buf_size += iov[i].iov_len;
            }
        }

        umq_buf_t *buf[POLL_BATCH_MAX];
        int poll_num = 0;
        if (m_rx.m_poll) {
            poll_num = GetQbuf(buf, POLL_BATCH_MAX);
            if (poll_num < 0) {
                errno = EIO;
                return -1;
            } else if (poll_num == 0) {
                /* might be useful for qps performance by
                 * (1) avoid redundant poll operations when handing cache;
                 * (2) aggregating RX requests; */
                m_rx.m_poll = false; 
            }
        }

        uint32_t polled_size = 0;
        for (int i = 0; i < poll_num; ++i) {
            // currently, umq over IB return IB cr status directly, successful = 0
            if (buf[i]->status != 0) {
                if (buf[i]->status != UMQ_FAKE_BUF_FC_UPDATE) {
                    HandleErrorRxCqe(buf[i]);
                } else {
                    m_rx.m_window_size += 1;
                    // try to wake up tx if necessary
                    bool need_fc_awake = m_tx.m_need_fc_awake.exchange(false, std::memory_order_relaxed);
                    if (need_fc_awake && eventfd_write(m_event_fd, 1) == -1) {
                        RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                          "write event fd%fd failed,Peer eid:" EID_FMT
                                          ",Peer IP:%s, fd: %d, errno: %d\n",
                                          m_event_fd, EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), errno);
                    }
                }

                QBUF_LIST_NEXT(buf[i]) = nullptr;
                umq_buf_free(buf[i]);
                continue;
            }

            m_rx.m_block_cache.Insert((char *)(buf[i]->buf_data), buf[i]->data_size);
            polled_size += buf[i]->data_size;
        }

        /* rpc adapter has replace brpc butil::iobuf::blockmem_allocate() & butil::iof::blockmem_deallocate()
         * and ensures that the starting address of the Block is aligned to an 8k boundary. */
        IOBuf::Block *out_first_block = (Brpc::IOBuf::Block *)PtrFloorToBoundary(iov[0].iov_base);
        rx_total_len = m_rx.m_block_cache.CutAndInsertAfter(max_buf_size, out_first_block);
        if (rx_total_len == 0) {
            /* m_rx.m_epoll_event_num not equals to m_rx.m_expect_epoll_event_num means another epoll event is reported
             * during readv processing procedure, set m_rx.m_poll to enable poll RX operation and set errno to EINTR
             * to let brpc retry and call readv() */
            if (!m_rx.m_epoll_event_num.compare_exchange_strong(
                m_rx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire)) {
                m_rx.m_poll = true;
                errno = EINTR;
                return -1;
            }
            bool closed = m_closed.load(std::memory_order_relaxed);
            if (closed == true) {
                retCode = 0;
                return 0;
            }

            if (RearmRxInterrupt() < 0) {
                errno = EIO;
                return -1;
            }

            /* return -1 and set errno to EAGAIN to notice user no more data to read */
            errno = EAGAIN;
            return -1;
        }

        /* Set the first block as used to prevent brpc from utilizing this block,
         * and only use it as the head of the block linked list. */
        out_first_block->size = out_first_block->cap;

        if (m_context_trace_enable) {
            UpdateTraceStats(StatsMgr::RX_PACKET_COUNT, 1);
            UpdateTraceStats(StatsMgr::RX_BYTE_COUNT, rx_total_len);
        }
        retCode = 0;
        return rx_total_len;
    }

    ALWAYS_INLINE ssize_t WriteV(const struct iovec *iov, int iovcnt)
    {
        int retCode = -1;
        TRACE_DELAY_AUTO(BRPC_WRITEV_CALL, retCode);
        if (m_tx_use_tcp) {
            ssize_t size = OsAPiMgr::GetOriginApi()->writev(m_fd, iov, iovcnt);
            retCode = size < 0 ? -1 : 0;
            return size;
        }

        if (iov == nullptr || iovcnt == 0) {
            errno = EINVAL;
            return -1;
        }

        if (m_closed.load(std::memory_order_relaxed)) {
            errno = EPIPE;
            return -1;
        }
        
        if (m_tx.m_get_and_ack_event) {
            // handle tx epollin epoll event
            do {
                if (GetAndAckEvent(UMQ_IO_TX) < 0) {
                    errno = EIO;
                    return -1;
                }
                // set poll_to_empty, means poll at least m_tx.m_retrieve_threshold TX CQE
                PollTx(m_tx.m_retrieve_threshold, true);
                /* m_tx.m_epoll_event_num not equals to m_tx.m_expect_epoll_event_num means
                 * another epoll event is reportedduring readv processing procedure */
            } while (!m_tx.m_epoll_event_num.compare_exchange_strong(
                m_tx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire));

            m_tx.m_get_and_ack_event = false;    
        } else if (m_tx.m_window_size == 0) {
            PollTx(m_tx.m_retrieve_threshold);
            if (m_tx.m_window_size == 0) {
                return DpRearmTxInterrupt();
            }
        }

        IovConverter iov_converter(iov, iovcnt);
        uint32_t input_total_len = 0;
        uint32_t batch = 0;
        uint32_t post_batch_max = m_tx.m_window_size > POST_BATCH_MAX ? POST_BATCH_MAX : m_tx.m_window_size;
        uint32_t umq_buf_cnt = 0;
        uint32_t cut_total_len = 0;
        uint16_t _unsolicited_wr_num = m_tx.m_unsolicited_wr_num;
        uint32_t _unsolicited_bytes = m_tx.m_unsolicited_bytes;
        uint16_t _unsignaled_wr_num = m_tx.m_unsignaled_wr_num;
        umq_buf_t *head_qbuf = QBUF_LIST_FIRST(&m_tx.m_head_buf);
        umq_buf_t *tail_qbuf = QBUF_LIST_FIRST(&m_tx.m_tail_buf);
        do {
            cut_total_len = 0;
            uint32_t cut_len = 0;
            uint32_t wr_left_len = BrpcIOBufSize();
            uint32_t sge_idx = 0;
            while (sge_idx++ < SGE_MAX && cut_total_len < BrpcIOBufSize() &&
                   ((cut_len = iov_converter.Cut(wr_left_len)) != 0)) {
                ++umq_buf_cnt;
                wr_left_len -= cut_len;
                cut_total_len += cut_len;
            }
            input_total_len += cut_total_len;
        } while (cut_total_len != 0 && ++batch < post_batch_max);

        umq_buf_t *tx_buf_list = umq_buf_alloc(0, umq_buf_cnt, UMQ_INVALID_HANDLE, nullptr);
        if (tx_buf_list == nullptr) {
            return DpRearmTxInterrupt();
        }

        umq_buf_t *cur_buf = tx_buf_list;
        umq_buf_t *next_buf = cur_buf;
        if (QBUF_LIST_EMPTY(&m_tx.m_head_buf)) {
            QBUF_LIST_FIRST(&m_tx.m_head_buf) = cur_buf;
        } else {
            QBUF_LIST_NEXT(QBUF_LIST_FIRST(&m_tx.m_tail_buf)) = cur_buf;
        }
        uint32_t tx_total_len = 0;
        iov_converter.Reset();
        for (uint32_t i = 0; i < batch; ++i) {
            umq_buf_t *cur_wr_first = next_buf;
            uint32_t moved_total_len = 0;
            uint32_t wr_left_len = BrpcIOBufSize();
            uint32_t sge_idx = 0;
            bool last = false;
            for (cur_buf = cur_wr_first; cur_buf && (next_buf = cur_buf->qbuf_next, 1); cur_buf = next_buf) {
                last = iov_converter.CutLast(wr_left_len, cur_buf);
                cur_buf->io_direction = UMQ_IO_TX;
                /* rpc adapter has replace brpc butil::iobuf::blockmem_allocate() & butil::iof::blockmem_deallocate()
                 * and ensures that the starting address of the Block is aligned to an 8k boundary. */
                ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur_buf->buf_data))->IncRef();
                wr_left_len -= cur_buf->data_size;
                moved_total_len += cur_buf->data_size;
                if (last || ++sge_idx >= SGE_MAX || moved_total_len >= BrpcIOBufSize()) {
                    break;
                }
            }

            tx_total_len += moved_total_len;
            cur_wr_first->total_data_size = moved_total_len;
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)cur_wr_first->qbuf_ext;
            buf_pro->opcode = UMQ_OPC_SEND;
            buf_pro->flag.value = 0;
            buf_pro->user_ctx = 0;
            if (m_tx.m_window_size == 1 || i + 1 == batch) {
                buf_pro->flag.bs.solicited_enable = 1;
            } else {
                if (m_tx.m_unsolicited_wr_num > m_tx.m_report_threshold ||
                    m_tx.m_unsolicited_bytes > UNSOLICITED_BYTES_MAX) {
                    buf_pro->flag.bs.solicited_enable = 1;
                } else {
                    ++m_tx.m_unsolicited_wr_num;
                    m_tx.m_unsolicited_bytes += moved_total_len;
                }
            }

            if (buf_pro->flag.bs.solicited_enable == 1) {
                m_tx.m_unsolicited_wr_num = 0;
                m_tx.m_unsolicited_bytes = 0;
            }

            if (++m_tx.m_unsignaled_wr_num >= m_tx.m_report_threshold) {
                buf_pro->flag.bs.complete_enable = 1;
                buf_pro->user_ctx = (uint64_t)QBUF_LIST_FIRST(&m_tx.m_head_buf);
                QBUF_LIST_FIRST(&m_tx.m_head_buf) = QBUF_LIST_NEXT(cur_buf);
                m_tx.m_unsignaled_wr_num = 0;
            }
        }

        QBUF_LIST_FIRST(&m_tx.m_tail_buf) = cur_buf;
        
        umq_buf_t *bad_qbuf = nullptr;
        int ret = umq_post(m_local_umqh, tx_buf_list, UMQ_IO_TX, &bad_qbuf);
        if (ret == UMQ_SUCCESS) {
            m_tx.m_window_size -= batch;
        } else if (bad_qbuf != nullptr) {
            if (ret == -UMQ_ERR_EAGAIN) {
                errno = EAGAIN;
                m_tx.m_need_fc_awake.store(true, std::memory_order_relaxed);
            } else {
                errno = EIO;
            }
            umq_buf_list_t head = { bad_qbuf };
            umq_buf_t *cur = nullptr;
            QBUF_LIST_FOR_EACH(cur, &head) {
                /* rpc adapter has replace brpc butil::iobuf::blockmem_allocate() &
                 * butil::iof::blockmem_deallocate()
                 * and ensures that the starting address of the Block is aligned to an 8k boundary. */
                ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur->buf_data))->DecRef();
            }

            if (bad_qbuf == tx_buf_list) {
                m_tx.m_unsolicited_wr_num = _unsolicited_wr_num;
                m_tx.m_unsolicited_bytes = _unsolicited_bytes;
                m_tx.m_unsignaled_wr_num = _unsignaled_wr_num;
                QBUF_LIST_FIRST(&m_tx.m_head_buf) =  head_qbuf;
                QBUF_LIST_FIRST(&m_tx.m_tail_buf) = tail_qbuf;
                umq_buf_free(bad_qbuf);
                tx_total_len = 0;
            } else {
                tx_total_len = HandleBadQBuf(tx_buf_list, bad_qbuf, head_qbuf,
                   _unsolicited_wr_num, _unsolicited_bytes, _unsignaled_wr_num);
            }
        }

        // After posting and before polling, the time for updating the count cna be concealed within the waiting period
        // for polling.

        if ((m_tx_window_capacity - m_tx.m_window_size) >= m_tx.m_handle_threshold) {
            PollTx(m_tx.m_retrieve_threshold);
        }

        if (m_context_trace_enable) {
            UpdateTraceStats(StatsMgr::TX_PACKET_COUNT, 1);
            UpdateTraceStats(StatsMgr::TX_BYTE_COUNT, tx_total_len);
        }

        retCode = 0;
        return tx_total_len;
    }

    ALWAYS_INLINE ssize_t Send(const void *buf, size_t len, int flags)
    {
        if (m_tx_use_tcp) {
            return OsAPiMgr::GetOriginApi()->send(m_fd, buf, len, flags);
        }

        if (buf == nullptr || len == 0) {
            errno = EINVAL;
            return -1;
        }
 
        if (m_closed.load(std::memory_order_relaxed)) {
            errno = EPIPE; // Broken pipe if connection is closed
            return -1;
        }
 
        if (m_tx.m_get_and_ack_event) {
            do {
                if (GetAndAckEvent(UMQ_IO_TX) < 0) {
                    errno = EIO;
                    return -1;
                }
                PollTx(m_tx.m_retrieve_threshold, true); // true indicates handling event
            } while (!m_tx.m_epoll_event_num.compare_exchange_strong(
                      m_tx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire));
            m_tx.m_get_and_ack_event = false;
        } else if (m_tx.m_window_size == 0) {
            PollTx(m_tx.m_retrieve_threshold);
            if (m_tx.m_window_size == 0) {
                return DpRearmTxInterrupt();
            }
        }
 
        uint32_t brpc_iobuf_size = BrpcIOBufSize();
        uint32_t num_bufs_needed = (len + brpc_iobuf_size - 1) / brpc_iobuf_size;
        uint32_t post_batch_max = (m_tx.m_window_size <= static_cast<uint32_t>(POST_BATCH_MAX)) ?
                                   m_tx.m_window_size : static_cast<uint32_t>(POST_BATCH_MAX);
        num_bufs_needed = (num_bufs_needed < post_batch_max) ? num_bufs_needed : post_batch_max;
        if (num_bufs_needed == 0) {
            errno = EAGAIN;
            return -1;
        }
 
        umq_buf_t *tx_buf_list = umq_buf_alloc(brpc_iobuf_size, num_bufs_needed, UMQ_INVALID_HANDLE, nullptr);
        if (tx_buf_list == nullptr) {
            return DpRearmTxInterrupt();
        }
 
        umq_buf_t *current_buf = tx_buf_list;
        if (QBUF_LIST_EMPTY(&m_tx.m_head_buf)) {
            QBUF_LIST_FIRST(&m_tx.m_head_buf) = current_buf;
        } else {
            QBUF_LIST_NEXT(QBUF_LIST_FIRST(&m_tx.m_tail_buf)) = current_buf;
        }
 
        const char* src_ptr = static_cast<const char*>(buf);
        size_t remaining_len = len;
        size_t copied_total = 0;
        size_t bytes_per_buf = brpc_iobuf_size;
 
        uint16_t _unsolicited_wr_num = m_tx.m_unsolicited_wr_num;
        uint32_t _unsolicited_bytes = m_tx.m_unsolicited_bytes;
        uint16_t _unsignaled_wr_num = m_tx.m_unsignaled_wr_num;
        umq_buf_t *head_qbuf = QBUF_LIST_FIRST(&m_tx.m_head_buf);
        umq_buf_t *tail_qbuf = QBUF_LIST_FIRST(&m_tx.m_tail_buf);
 
        for (uint32_t i = 0; i < num_bufs_needed && remaining_len > 0; ++i) {
            size_t copy_len = std::min(remaining_len, static_cast<size_t>(bytes_per_buf));
            if (current_buf->buf_data == nullptr) {
                umq_buf_free(tx_buf_list);
                errno = ENOMEM;
                return -1;
            }
 
            memcpy_s(current_buf->buf_data, copy_len, src_ptr, copy_len); // Copy data into UMQ buffer
            current_buf->data_size = copy_len;
            remaining_len -= copy_len;
            src_ptr += copy_len;
            copied_total += copy_len;
 
            if (i == 0) {
                current_buf->total_data_size = len;
            }
 
            // Setup UMQ buffer properties (similar to WriteV)
            current_buf->io_direction = UMQ_IO_TX;
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)current_buf->qbuf_ext;
            if (buf_pro) {
                buf_pro->opcode = UMQ_OPC_SEND;
                buf_pro->flag.value = 0;
                buf_pro->remote_sge.addr = (uint64_t)current_buf->buf_data;
                buf_pro->remote_sge.length = current_buf->data_size;
                buf_pro->remote_sge.token_id = 0;
                buf_pro->remote_sge.token_value = 0;
                buf_pro->remote_sge.mempool_id = 0;
                buf_pro->remote_sge.rsvd0 = 0;
 
                if (m_tx.m_window_size == 1 || i + 1 == num_bufs_needed) {
                    buf_pro->flag.bs.solicited_enable = 1;
                } else {
                    if (m_tx.m_unsolicited_wr_num > m_tx.m_report_threshold ||
                        m_tx.m_unsolicited_bytes > UNSOLICITED_BYTES_MAX) {
                        buf_pro->flag.bs.solicited_enable = 1;
                    } else {
                        ++m_tx.m_unsolicited_wr_num;
                        m_tx.m_unsolicited_bytes += copy_len;
                    }
                }
 
                if (buf_pro->flag.bs.solicited_enable == 1) {
                    m_tx.m_unsolicited_wr_num = 0;
                    m_tx.m_unsolicited_bytes = 0;
                }
 
                if (++m_tx.m_unsignaled_wr_num >= m_tx.m_report_threshold) {
                    buf_pro->flag.bs.complete_enable = 1;
                    buf_pro->user_ctx = (uint64_t)QBUF_LIST_FIRST(&m_tx.m_head_buf);
                    QBUF_LIST_FIRST(&m_tx.m_head_buf) = QBUF_LIST_NEXT(current_buf);
                    m_tx.m_unsignaled_wr_num = 0;
                }
            }
 
            if (i + 1 < num_bufs_needed) {
                current_buf = current_buf->qbuf_next;
            }
        }
 
        // Update tail pointer of the TX buffer list management
        QBUF_LIST_FIRST(&m_tx.m_tail_buf) = current_buf;
        umq_buf_t *bad_qbuf = nullptr;
 
        int post_result = umq_post(m_local_umqh, tx_buf_list, UMQ_IO_TX, &bad_qbuf);
        if (post_result == UMQ_SUCCESS) {
            m_tx.m_window_size -= num_bufs_needed; // Consume window slots upon successful post
        } else if (bad_qbuf != nullptr) {
            // Handle partial failure
            if (post_result == -UMQ_ERR_EAGAIN) {
                // Operation would block, UMQ queue might be temporarily full despite window check
                errno = EAGAIN;
                m_tx.m_need_fc_awake.store(true, std::memory_order_relaxed);
            } else {
                errno = EIO;
            }
 
            umq_buf_list_t failed_list = { bad_qbuf }; // Create a temporary list head
            umq_buf_t *cur_failed = nullptr;
            QBUF_LIST_FOR_EACH(cur_failed, &failed_list) {
                ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur_failed->buf_data))->DecRef();
            }
 
            if (bad_qbuf == tx_buf_list) {
                m_tx.m_unsolicited_wr_num = _unsolicited_wr_num; // Restore saved state from before loop
                m_tx.m_unsolicited_bytes = _unsolicited_bytes;
                m_tx.m_unsignaled_wr_num = _unsignaled_wr_num;
                QBUF_LIST_FIRST(&m_tx.m_head_buf) = head_qbuf;
                QBUF_LIST_FIRST(&m_tx.m_tail_buf) = tail_qbuf;
                umq_buf_free(bad_qbuf); // Free the failed list starting from the first bad buffer
                copied_total = 0; // Nothing was successfully sent
            } else {
                copied_total = HandleBadQBuf(tx_buf_list, bad_qbuf, head_qbuf,
                                             _unsolicited_wr_num, _unsolicited_bytes, _unsignaled_wr_num);
            }
 
            return static_cast<ssize_t>(copied_total);
        } else {
            errno = EIO;
            return -1;
        }
 
        if ((m_tx_window_capacity - m_tx.m_window_size) >= m_tx.m_handle_threshold) {
            PollTx(m_tx.m_retrieve_threshold);
        }
 
        return static_cast<ssize_t>(copied_total);
 
    }
 
    ALWAYS_INLINE ssize_t Recv(void *buf, size_t len, int flags)
    {
        if (m_rx_use_tcp) {
            return OsAPiMgr::GetOriginApi()->recv(m_fd, buf, len, flags);
        }
 
        if (buf == nullptr || len == 0) {
            errno = EINVAL;
            return -1;
        }
 
        struct iovec single_iov = { .iov_base = buf, .iov_len = len };
        ssize_t rx_total_len = OutputErrorMagicNumber(&single_iov, 1);
        if (rx_total_len > 0) {
            return rx_total_len;
        }
 
        if (m_rx.m_get_and_ack_event) {
            if (GetAndAckEvent(UMQ_IO_RX) < 0) {
                errno = EIO;
                return -1;
            }
            m_rx.m_get_and_ack_event = false;
        }

        size_t remaining_user_buf = len; // Remaining space in user buffer
        char* user_buf_ptr = static_cast<char*>(buf); // Use a pointer to track position in user buffer
        size_t copied_buf = 0;

        while (remaining_user_buf > 0 && m_rx.m_remaining_size > 0) {
            umq_buf_t *cur_buf = QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_head);
            if (cur_buf == nullptr) {
                break;
            }
            if (cur_buf->data_size <= remaining_user_buf) {
                memcpy_s(user_buf_ptr + copied_buf, remaining_user_buf, cur_buf->buf_data, cur_buf->data_size);
                m_rx.m_remaining_size -= cur_buf->data_size;
                remaining_user_buf -= cur_buf->data_size;
                copied_buf += cur_buf->data_size;
                umq_buf_t *next_buf = QBUF_LIST_NEXT(cur_buf);
                umq_buf_free(cur_buf);
                QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_head) = next_buf;
            } else {
                memcpy_s(user_buf_ptr + copied_buf, remaining_user_buf, cur_buf->buf_data, remaining_user_buf);
                m_rx.m_remaining_size -= remaining_user_buf;
                cur_buf->buf_data = static_cast<char*>(cur_buf->buf_data) + remaining_user_buf;
                cur_buf->data_size -= remaining_user_buf;
                remaining_user_buf = 0;
                break;
            }
        }

        if (remaining_user_buf == 0) {
            return len;
        }

        umq_buf_t *buf_array[POLL_BATCH_MAX];
        int poll_num = 0;
        while (poll_num == 0) {
            poll_num = UmqPollAndRefillRx(buf_array, POLL_BATCH_MAX);
            if (poll_num < 0) {
                errno = EIO;
                return -1;
            } else if (poll_num == 0) {
                m_rx.m_poll = false; 
            }
        }

        if (poll_num != 0) {
            for (int i = 0; i < poll_num - 1; ++i) {
                QBUF_LIST_NEXT(buf_array[i]) = buf_array[i + 1];
            }
            if (QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_head) == nullptr) {
                QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_head) = buf_array[0];
                QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_tail) = buf_array[poll_num - 1];
            } else {
                QBUF_LIST_NEXT(QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_tail)) = buf_array[0];
                QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_tail) = buf_array[poll_num - 1];
            }
        }

        for (int i = 0; i < poll_num; ++i) {
            if (buf_array[i]->status != 0) {
                if (buf_array[i]->status != UMQ_BUF_FLOW_CONTROL_UPDATE) {
                    RPC_ADPT_VLOG_DEBUG("RX CQE is invalid, status: %d\n", buf_array[i]->status);
                    QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                    umq_buf_free(buf_array[i]);
                    continue;
                } else {
                    // try to wake up tx if necessary
                    bool need_fc_awake = m_tx.m_need_fc_awake.exchange(false, std::memory_order_relaxed);
                    if (need_fc_awake && eventfd_write(m_event_fd, 1) == -1) {
                        RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "write event fd%fd failed, errno: %d\n", m_event_fd,
                                          errno);
                    }

                    if (buf_array[i]->total_data_size == 0) {
                        QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                        umq_buf_free(buf_array[i]);
                        continue;
                    }
                }
            }

            if (remaining_user_buf > 0) {
                if (buf_array[i]->data_size <= remaining_user_buf) {
                    memcpy_s(user_buf_ptr + copied_buf, remaining_user_buf, buf_array[i]->buf_data,
                             buf_array[i]->data_size);
                    remaining_user_buf -= buf_array[i]->data_size;
                    copied_buf += buf_array[i]->data_size;
                    umq_buf_t *next_buf = QBUF_LIST_NEXT(buf_array[i]);
                    umq_buf_free(buf_array[i]);
                    QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_head) = next_buf;
                } else {
                    memcpy_s(user_buf_ptr + copied_buf, remaining_user_buf, buf_array[i]->buf_data, remaining_user_buf);
                    m_rx.m_remaining_size += buf_array[i]->data_size - remaining_user_buf;
                    buf_array[i]->buf_data = static_cast<char*>(buf_array[i]->buf_data) + remaining_user_buf;
                    buf_array[i]->data_size -= remaining_user_buf;
                    remaining_user_buf = 0;
                }
            } else {
                m_rx.m_remaining_size += buf_array[i]->data_size;
            }
        }

        if (m_rx.m_remaining_size != 0) {
            QBUF_LIST_FIRST(&m_rx.m_umq_buf_cache_tail) = buf_array[poll_num - 1];
        }

        if (remaining_user_buf > 0) {
            // Check for epoll event num mismatch (similar to ReadV)
            m_rx.m_poll = true;
            if (!m_rx.m_epoll_event_num.compare_exchange_strong(
                        m_rx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire)) {
                m_rx.m_poll = true;
                errno = EINTR;
                return -1;
            }
 
            bool closed = m_closed.load(std::memory_order_relaxed);
            if (closed == true) {
                return 0;
            }
 
            if (RearmRxInterrupt() < 0) {
                errno = EIO;
                return -1;
            }
 
            errno = EAGAIN;
            return -1;
        }

        return len;
    }

    ALWAYS_INLINE ssize_t Read(void *buf, size_t nbyte)
    {
        if (m_rx_use_tcp) {
            return OsAPiMgr::GetOriginApi()->read(m_fd, buf, nbyte);
        }

        if (buf == nullptr || nbyte == 0) {
            errno = EINVAL;
            return -1;
        }

        if (m_closed.load(std::memory_order_relaxed)) {
            errno = EPIPE; // Broken pipe if connection is closed
            return -1;
        }

        struct iovec single_iov = { .iov_base = buf, .iov_len = nbyte };
        ssize_t rx_total_len = OutputErrorMagicNumber(&single_iov, 1);
        if (rx_total_len > 0) {
            return rx_total_len;
        }
        
        if (m_rx.m_get_and_ack_event) {
            if (GetAndAckEvent(UMQ_IO_RX) < 0) {
                errno = EIO;
                return -1;
            }
            m_rx.m_get_and_ack_event = false;
        }

        uint32_t max_buf_size;
        if (m_rx.m_readv_unlimited) {
            max_buf_size = UINT32_MAX;
        } else {
            max_buf_size = static_cast<uint32_t>(nbyte);
            if (max_buf_size != nbyte) {
                errno = EINVAL;
                return -1;
            }
        }

        bool is_blocking = IsBlocking(m_fd);
        umq_buf_t *buf_array[POLL_BATCH_MAX];
        int poll_num = 0;

        while (true) {
            poll_num = UmqPollAndRefillRx(buf_array, POLL_BATCH_MAX);
            if (poll_num < 0) {
                errno = EIO;
                return -1;
            } else if (poll_num > 0) {
                break;
            } else { // poll_num == 0
                if (!is_blocking) {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                      "Read: Non-blocking mode, no data available, setting errno = EAGAIN\n");
                    errno = EAGAIN;
                    return -1;
                } else {
                    RPC_ADPT_VLOG_DEBUG("Read: Blocking mode, no data, polling again...\n");
                }
            }
        }

        // Process Polled Buffers and Copy Directly
        rx_total_len = 0;
        char* user_buf_ptr = static_cast<char*>(buf);
        size_t remaining_user_buf = nbyte;

        if (poll_num > 0) {
            for (int i = 0; i < poll_num; ++i) {
                if (remaining_user_buf == 0) {
                    RPC_ADPT_VLOG_DEBUG("Read: User buffer is full, stopping processing of further buffers\n");
                    QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                    umq_buf_free(buf_array[i]);
                    continue;
                }
                if (buf_array[i]->status != 0) {
                    if (buf_array[i]->status != UMQ_FAKE_BUF_FC_UPDATE) {
                        RPC_ADPT_VLOG_DEBUG("RX CQE is invalid, status: %d\n", buf_array[i]->status);
                        QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                        umq_buf_free(buf_array[i]);
                        continue;
                    } else {
                        m_rx.m_window_size += 1;
                        // Handle flow control update
                        bool need_fc_awake = m_tx.m_need_fc_awake.exchange(false, std::memory_order_relaxed);
                        if (need_fc_awake && eventfd_write(m_event_fd, 1) == -1) {
                            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "write event fd %d failed, errno: %d\n", m_event_fd,
                                              errno);
                        }

                        QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                        umq_buf_free(buf_array[i]);
                        continue;
                    }
                }

                size_t data_size_to_copy = buf_array[i]->data_size;

                // Check if user buffer has enough space
                if (remaining_user_buf < data_size_to_copy) {
                    data_size_to_copy = remaining_user_buf;
                }

                if (data_size_to_copy > 0) {
                    memcpy_s(user_buf_ptr, data_size_to_copy, buf_array[i]->buf_data, data_size_to_copy);
                    rx_total_len += data_size_to_copy;
                    user_buf_ptr += data_size_to_copy;
                    remaining_user_buf -= data_size_to_copy;
                }

                QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                umq_buf_free(buf_array[i]);
            }
        }

        if (rx_total_len == 0) {
            if (!m_rx.m_epoll_event_num.compare_exchange_strong(
                 m_rx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire)) {
                m_rx.m_poll = true;
                errno = EINTR;
                return -1;
            }

            bool closed = m_closed.load(std::memory_order_relaxed);
            if (closed == true) {
                return 0;
            }

            if (RearmRxInterrupt() < 0) {
                errno = EIO;
                return -1;
            }

            errno = EAGAIN;
            return -1;
        }

        return rx_total_len;
    }

    ALWAYS_INLINE ssize_t Write(const void *buf, size_t nbyte)
    {
        if (m_rx_use_tcp) {
            return OsAPiMgr::GetOriginApi()->write(m_fd, buf, nbyte);
        }

        if (buf == nullptr || nbyte == 0) {
            errno = EINVAL;
            return -1;
        }

        if (m_closed.load(std::memory_order_relaxed)) {
            errno = EPIPE; // Broken pipe if connection is closed
            return -1;
        }

        if (m_tx.m_get_and_ack_event) {
            do {
                if (GetAndAckEvent(UMQ_IO_TX) < 0) {
                    errno = EIO;
                    return -1;
                }
                PollTx(m_tx.m_retrieve_threshold, true); // true indicates handling event
            } while (!m_tx.m_epoll_event_num.compare_exchange_strong(
                      m_tx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire));
            m_tx.m_get_and_ack_event = false;
        } else if (m_tx.m_window_size == 0) {
            PollTx(m_tx.m_retrieve_threshold);
            if (m_tx.m_window_size == 0) {
                return DpRearmTxInterrupt();
            }
        }

        uint32_t brpc_iobuf_size = BrpcIOBufSize();
        uint32_t num_bufs_needed = (nbyte + brpc_iobuf_size - 1) / brpc_iobuf_size;
        uint32_t post_batch_max = (m_tx.m_window_size <= static_cast<uint32_t>(POST_BATCH_MAX)) ?
                                   m_tx.m_window_size : static_cast<uint32_t>(POST_BATCH_MAX);
        num_bufs_needed = (num_bufs_needed < post_batch_max) ? num_bufs_needed : post_batch_max;
        if (num_bufs_needed == 0) {
            errno = EAGAIN;
            return -1;
        }

        umq_buf_t *tx_buf_list = umq_buf_alloc(brpc_iobuf_size, num_bufs_needed, UMQ_INVALID_HANDLE, nullptr);
        if (tx_buf_list == nullptr) {
            return DpRearmTxInterrupt();
        }
        
        umq_buf_t *current_buf = tx_buf_list;

        const char* src_ptr = static_cast<const char*>(buf);
        size_t remaining_len = nbyte;
        size_t copied_total = 0;
        size_t bytes_per_buf = brpc_iobuf_size;

        uint16_t _unsolicited_wr_num = m_tx.m_unsolicited_wr_num;
        uint32_t _unsolicited_bytes = m_tx.m_unsolicited_bytes;
        uint16_t _unsignaled_wr_num = m_tx.m_unsignaled_wr_num;
        umq_buf_t *head_qbuf = QBUF_LIST_FIRST(&m_tx.m_head_buf);
        umq_buf_t *tail_qbuf = QBUF_LIST_FIRST(&m_tx.m_tail_buf);

        for (uint32_t i = 0; i < num_bufs_needed && remaining_len > 0; ++i) {
            size_t copy_len = std::min(remaining_len, static_cast<size_t>(bytes_per_buf));
            if (current_buf->buf_data == nullptr) {
                umq_buf_free(tx_buf_list);
                errno = ENOMEM;
                return -1;
            }
 
            memcpy_s(current_buf->buf_data, copy_len, src_ptr, copy_len); // Copy data into UMQ buffer
            current_buf->data_size = copy_len;
            remaining_len -= copy_len;
            src_ptr += copy_len;
            copied_total += copy_len;
 
            if (i == 0) {
                current_buf->total_data_size = nbyte;
            }

            // Setup UMQ buffer properties (similar to WriteV)
            current_buf->io_direction = UMQ_IO_TX;
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)current_buf->qbuf_ext;
            if (buf_pro) {
                buf_pro->opcode = UMQ_OPC_SEND;
                buf_pro->flag.value = 0;
                buf_pro->remote_sge.addr = (uint64_t)current_buf->buf_data;
                buf_pro->remote_sge.length = current_buf->data_size;
                buf_pro->remote_sge.token_id = 0;
                buf_pro->remote_sge.token_value = 0;
                buf_pro->remote_sge.mempool_id = 0;
                buf_pro->remote_sge.rsvd0 = 0;
 
                if (m_tx.m_window_size == 1 || i + 1 == num_bufs_needed) {
                    buf_pro->flag.bs.solicited_enable = 1;
                } else {
                    if (m_tx.m_unsolicited_wr_num > m_tx.m_report_threshold ||
                        m_tx.m_unsolicited_bytes > UNSOLICITED_BYTES_MAX) {
                        buf_pro->flag.bs.solicited_enable = 1;
                    } else {
                        ++m_tx.m_unsolicited_wr_num;
                        m_tx.m_unsolicited_bytes += copy_len;
                    }
                }
 
                if (buf_pro->flag.bs.solicited_enable == 1) {
                    m_tx.m_unsolicited_wr_num = 0;
                    m_tx.m_unsolicited_bytes = 0;
                }

                if (++m_tx.m_unsignaled_wr_num >= m_tx.m_report_threshold) {
                    buf_pro->flag.bs.complete_enable = 1;
                    buf_pro->user_ctx = (uint64_t)QBUF_LIST_FIRST(&m_tx.m_head_buf);
                    QBUF_LIST_FIRST(&m_tx.m_head_buf) = QBUF_LIST_NEXT(current_buf);
                    m_tx.m_unsignaled_wr_num = 0;
                }
            }
 
            if (i + 1 < num_bufs_needed) {
                current_buf = current_buf->qbuf_next;
            }
        }

        // Update tail pointer of the TX buffer list management
        QBUF_LIST_FIRST(&m_tx.m_tail_buf) = current_buf;
        umq_buf_t *bad_qbuf = nullptr;
 
        int post_result = umq_post(m_local_umqh, tx_buf_list, UMQ_IO_TX, &bad_qbuf);
        if (post_result == UMQ_SUCCESS) {
            m_tx.m_window_size -= num_bufs_needed; // Consume window slots upon successful post
        } else if (bad_qbuf != nullptr) {
            // Handle partial failure
            if (post_result == -UMQ_ERR_EAGAIN) {
                // Operation would block, UMQ queue might be temporarily full despite window check
                errno = EAGAIN;
                m_tx.m_need_fc_awake.store(true, std::memory_order_relaxed);
            } else {
                errno = EIO;
            }
 
            umq_buf_list_t failed_list = { bad_qbuf }; // Create a temporary list head
            umq_buf_t *cur_failed = nullptr;
            QBUF_LIST_FOR_EACH(cur_failed, &failed_list) {
                ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur_failed->buf_data))->DecRef();
            }
 
            if (bad_qbuf == tx_buf_list) {
                m_tx.m_unsolicited_wr_num = _unsolicited_wr_num; // Restore saved state from before loop
                m_tx.m_unsolicited_bytes = _unsolicited_bytes;
                m_tx.m_unsignaled_wr_num = _unsignaled_wr_num;
                QBUF_LIST_FIRST(&m_tx.m_head_buf) = head_qbuf;
                QBUF_LIST_FIRST(&m_tx.m_tail_buf) = tail_qbuf;
 
                umq_buf_free(bad_qbuf); // Free the failed list starting from the first bad buffer
                copied_total = 0; // Nothing was successfully sent
            } else {
                copied_total = HandleBadQBuf(tx_buf_list, bad_qbuf, head_qbuf,
                                             _unsolicited_wr_num, _unsolicited_bytes, _unsignaled_wr_num);
            }
 
            return static_cast<ssize_t>(copied_total);
        } else {
            errno = EIO;
            return -1;
        }
 
        if ((m_tx_window_capacity - m_tx.m_window_size) >= m_tx.m_handle_threshold) {
            PollTx(m_tx.m_retrieve_threshold);
        }

        return static_cast<ssize_t>(copied_total);
    }

    ALWAYS_INLINE ssize_t SendTo(const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
                                 socklen_t addrlen)
    {
        if (m_tx_use_tcp) {
            return OsAPiMgr::GetOriginApi()->sendto(m_fd, buf, len, flags, dest_addr, addrlen);
        }

        if (buf == nullptr || len == 0) {
            errno = EINVAL;
            return -1;
        }
 
        if (m_closed.load(std::memory_order_relaxed)) {
            errno = EPIPE; // Broken pipe if connection is closed
            return -1;
        }
 
        if (m_tx.m_get_and_ack_event) {
            do {
                if (GetAndAckEvent(UMQ_IO_TX) < 0) {
                    errno = EIO;
                    return -1;
                }
                PollTx(m_tx.m_retrieve_threshold, true); // true indicates handling event
            } while (!m_tx.m_epoll_event_num.compare_exchange_strong(
                      m_tx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire));
            m_tx.m_get_and_ack_event = false;
        } else if (m_tx.m_window_size == 0) {
            PollTx(m_tx.m_retrieve_threshold);
            if (m_tx.m_window_size == 0) {
                return DpRearmTxInterrupt();
            }
        }
 
        uint32_t brpc_iobuf_size = BrpcIOBufSize();
        uint32_t num_bufs_needed = (len + brpc_iobuf_size - 1) / brpc_iobuf_size;
        uint32_t post_batch_max = (m_tx.m_window_size <= static_cast<uint32_t>(POST_BATCH_MAX)) ?
                                   m_tx.m_window_size : static_cast<uint32_t>(POST_BATCH_MAX);
        num_bufs_needed = (num_bufs_needed < post_batch_max) ? num_bufs_needed : post_batch_max;
        if (num_bufs_needed == 0) {
            errno = EAGAIN;
            return -1;
        }
 
        umq_buf_t *tx_buf_list = umq_buf_alloc(brpc_iobuf_size, num_bufs_needed, UMQ_INVALID_HANDLE, nullptr);
        if (tx_buf_list == nullptr) {
            return DpRearmTxInterrupt();
        }
 
        umq_buf_t *current_buf = tx_buf_list;
        if (QBUF_LIST_EMPTY(&m_tx.m_head_buf)) {
            QBUF_LIST_FIRST(&m_tx.m_head_buf) = current_buf;
        } else {
            QBUF_LIST_NEXT(QBUF_LIST_FIRST(&m_tx.m_tail_buf)) = current_buf;
        }
 
        const char* src_ptr = static_cast<const char*>(buf);
        size_t remaining_len = len;
        size_t copied_total = 0;
        size_t bytes_per_buf = brpc_iobuf_size;
 
        uint16_t _unsolicited_wr_num = m_tx.m_unsolicited_wr_num;
        uint32_t _unsolicited_bytes = m_tx.m_unsolicited_bytes;
        uint16_t _unsignaled_wr_num = m_tx.m_unsignaled_wr_num;
        umq_buf_t *head_qbuf = QBUF_LIST_FIRST(&m_tx.m_head_buf);
        umq_buf_t *tail_qbuf = QBUF_LIST_FIRST(&m_tx.m_tail_buf);
 
        for (uint32_t i = 0; i < num_bufs_needed && remaining_len > 0; ++i) {
            size_t copy_len = std::min(remaining_len, static_cast<size_t>(bytes_per_buf));
            if (current_buf->buf_data == nullptr) {
                umq_buf_free(tx_buf_list);
                errno = ENOMEM;
                return -1;
            }
 
            memcpy_s(current_buf->buf_data, copy_len, src_ptr, copy_len); // Copy data into UMQ buffer
            current_buf->data_size = copy_len;
            remaining_len -= copy_len;
            src_ptr += copy_len;
            copied_total += copy_len;
 
            if (i == 0) {
                current_buf->total_data_size = len;
            }
 
            // Setup UMQ buffer properties (similar to WriteV)
            current_buf->io_direction = UMQ_IO_TX;
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)current_buf->qbuf_ext;
            if (buf_pro) {
                buf_pro->opcode = UMQ_OPC_SEND;
                buf_pro->flag.value = 0;
                buf_pro->remote_sge.addr = (uint64_t)current_buf->buf_data;
                buf_pro->remote_sge.length = current_buf->data_size;
                buf_pro->remote_sge.token_id = 0;
                buf_pro->remote_sge.token_value = 0;
                buf_pro->remote_sge.mempool_id = 0;
                buf_pro->remote_sge.rsvd0 = 0;
 
                if (m_tx.m_window_size == 1 || i + 1 == num_bufs_needed) {
                    buf_pro->flag.bs.solicited_enable = 1;
                } else {
                    if (m_tx.m_unsolicited_wr_num > m_tx.m_report_threshold ||
                        m_tx.m_unsolicited_bytes > UNSOLICITED_BYTES_MAX) {
                        buf_pro->flag.bs.solicited_enable = 1;
                    } else {
                        ++m_tx.m_unsolicited_wr_num;
                        m_tx.m_unsolicited_bytes += copy_len;
                    }
                }
 
                if (buf_pro->flag.bs.solicited_enable == 1) {
                    m_tx.m_unsolicited_wr_num = 0;
                    m_tx.m_unsolicited_bytes = 0;
                }

                if (++m_tx.m_unsignaled_wr_num >= m_tx.m_report_threshold) {
                    buf_pro->flag.bs.complete_enable = 1;
                    buf_pro->user_ctx = (uint64_t)QBUF_LIST_FIRST(&m_tx.m_head_buf);
                    QBUF_LIST_FIRST(&m_tx.m_head_buf) = QBUF_LIST_NEXT(current_buf);
                    m_tx.m_unsignaled_wr_num = 0;
                }
            }
 
            if (i + 1 < num_bufs_needed) {
                current_buf = current_buf->qbuf_next;
            }
        }
 
        // Update tail pointer of the TX buffer list management
        QBUF_LIST_FIRST(&m_tx.m_tail_buf) = current_buf;
        umq_buf_t *bad_qbuf = nullptr;
 
        int post_result = umq_post(m_local_umqh, tx_buf_list, UMQ_IO_TX, &bad_qbuf);
        if (post_result == UMQ_SUCCESS) {
            m_tx.m_window_size -= num_bufs_needed; // Consume window slots upon successful post
        } else if (bad_qbuf != nullptr) {
            // Handle partial failure
            if (post_result == -UMQ_ERR_EAGAIN) {
                // Operation would block, UMQ queue might be temporarily full despite window check
                errno = EAGAIN;
                m_tx.m_need_fc_awake.store(true, std::memory_order_relaxed);
            } else {
                errno = EIO;
            }
 
            umq_buf_list_t failed_list = { bad_qbuf }; // Create a temporary list head
            umq_buf_t *cur_failed = nullptr;
            QBUF_LIST_FOR_EACH(cur_failed, &failed_list) {
                ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur_failed->buf_data))->DecRef();
            }
 
            if (bad_qbuf == tx_buf_list) {
                m_tx.m_unsolicited_wr_num = _unsolicited_wr_num; // Restore saved state from before loop
                m_tx.m_unsolicited_bytes = _unsolicited_bytes;
                m_tx.m_unsignaled_wr_num = _unsignaled_wr_num;
                QBUF_LIST_FIRST(&m_tx.m_head_buf) = head_qbuf;
                QBUF_LIST_FIRST(&m_tx.m_tail_buf) = tail_qbuf;
 
                umq_buf_free(bad_qbuf); // Free the failed list starting from the first bad buffer
                copied_total = 0; // Nothing was successfully sent
            } else {
                copied_total = HandleBadQBuf(tx_buf_list, bad_qbuf, head_qbuf,
                                             _unsolicited_wr_num, _unsolicited_bytes, _unsignaled_wr_num);
            }
 
            return static_cast<ssize_t>(copied_total);
        } else {
            errno = EIO;
            return -1;
        }
 
        if ((m_tx_window_capacity - m_tx.m_window_size) >= m_tx.m_handle_threshold) {
            PollTx(m_tx.m_retrieve_threshold);
        }
 
        return static_cast<ssize_t>(copied_total);
    }
    
    ALWAYS_INLINE ssize_t RecvFrom(void *buf, size_t len, int flags, struct sockaddr *src_addr,
                                   socklen_t *addrlen)
    {
        if (m_rx_use_tcp) {
            return OsAPiMgr::GetOriginApi()->recvfrom(m_fd, buf, len, flags, src_addr, addrlen);
        }

        if (buf == nullptr || len == 0) {
            errno = EINVAL;
            return -1;
        }
 
        struct iovec single_iov = { .iov_base = buf, .iov_len = len };
        ssize_t rx_total_len = OutputErrorMagicNumber(&single_iov, 1);
        if (rx_total_len > 0) {
            return rx_total_len;
        }
 
        if (m_rx.m_get_and_ack_event) {
            if (GetAndAckEvent(UMQ_IO_RX) < 0) {
                errno = EIO;
                return -1;
            }
            m_rx.m_get_and_ack_event = false;
        }
 
        uint32_t max_buf_size;
        if (m_rx.m_readv_unlimited) {
            max_buf_size = UINT32_MAX;
        } else {
            max_buf_size = static_cast<uint32_t>(len);
            if (max_buf_size != len) {
                errno = EINVAL;
                return -1;
            }
        }
 
        bool is_blocking = IsBlocking(m_fd);
        umq_buf_t *buf_array[POLL_BATCH_MAX];
        int poll_num = 0;
 
        while (true) {
            poll_num = UmqPollAndRefillRx(buf_array, POLL_BATCH_MAX);
            if (poll_num < 0) {
                errno = EIO;
                return -1; // Error occurred during polling
            } else if (poll_num > 0) {
                break;
            } else { // poll_num == 0
                if (!is_blocking) {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                      "Recv: Non-blocking mode, no data available, setting errno = EAGAIN\n");
                    errno = EAGAIN;
                    return -1;
                } else {
                    RPC_ADPT_VLOG_DEBUG("Recv: Blocking mode, no data, polling again...\n");
                }
            }
        }
 
        // Process Polled Buffers and Copy Directly (only executed if poll_num > 0)
        rx_total_len = 0; // Total bytes copied to user buffer
        char* user_buf_ptr = static_cast<char*>(buf); // Use a pointer to track position in user buffer
        size_t remaining_user_buf = len; // Remaining space in user buffer
 
        if (poll_num > 0) {
            for (int i = 0; i < poll_num; ++i) {
                if (buf_array[i]->status != 0) {
                    if (buf_array[i]->status != UMQ_FAKE_BUF_FC_UPDATE) {
                        RPC_ADPT_VLOG_DEBUG("RX CQE is invalid, status: %d\n", buf_array[i]->status);
                        QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                        umq_buf_free(buf_array[i]);
                        continue; // Skip this invalid buffer
                    } else {
                        m_rx.m_window_size += 1;
                        // Handle flow control update
                        bool need_fc_awake = m_tx.m_need_fc_awake.exchange(false, std::memory_order_relaxed);
                        if (need_fc_awake && eventfd_write(m_event_fd, 1) == -1) {
                            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "write event fd %d failed, errno: %d\n", m_event_fd,
                                              errno);
                        }

                        QBUF_LIST_NEXT(buf_array[i]) = nullptr;
                        umq_buf_free(buf_array[i]);
                        continue;  // No data in this FC update packet
                    }
                }
 
                size_t data_size_to_copy = buf_array[i]->data_size;
 
                // Check if user buffer has enough space for this chunk
                if (remaining_user_buf < data_size_to_copy) {
                    data_size_to_copy = remaining_user_buf; // Copy only what fits
                }
 
                if (data_size_to_copy > 0) {
                    // Copy data directly from UMQ buffer to user buffer
                    memcpy_s(user_buf_ptr, data_size_to_copy, buf_array[i]->buf_data, data_size_to_copy);
                    rx_total_len += data_size_to_copy;
                    user_buf_ptr += data_size_to_copy;
                    remaining_user_buf -= data_size_to_copy;
                }
 
                // Free the UMQ buffer after copying its data
                QBUF_LIST_NEXT(buf_array[i]) = nullptr; // Ensure list termination if needed by umq_buf_free
                umq_buf_free(buf_array[i]); // Free the UMQ buffer structure and its associated data area
 
                // If user buffer is full, stop processing more buffers in this call
                if (remaining_user_buf == 0) {
                    RPC_ADPT_VLOG_DEBUG("Recv: User buffer is full, stopping processing of further buffers\n");
                    break;
                }
            }
        }
 
        if (rx_total_len == 0) {
            // Check for epoll event num mismatch (similar to ReadV)
            if (!m_rx.m_epoll_event_num.compare_exchange_strong(
                 m_rx.m_expect_epoll_event_num, 0, std::memory_order_release, std::memory_order_acquire)) {
                m_rx.m_poll = true;
                errno = EINTR;
                return -1;
            }
 
            bool closed = m_closed.load(std::memory_order_relaxed);
            if (closed == true) {
                return 0;
            }
 
            if (RearmRxInterrupt() < 0) {
                errno = EIO;
                return -1;
            }
 
            errno = EAGAIN;
            return -1;
        }
 
        return rx_total_len;
    }

    ALWAYS_INLINE int Fcntl(int fd, int cmd, unsigned long int arg)
    {
        // arg can be either struct flock or int
        int ret { 0 };

        switch (cmd) {
            case F_SETFL: // Set file status flags (O_NONBLOCK, etc.)
                ret = OsAPiMgr::GetOriginApi()->fcntl(m_fd, cmd, arg);
                if (ret == 0) {
                    // Update m_isblocking based on the origin fd blocking state
                    m_isblocking = IsBlocking(m_fd);
                } else {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "fcntl set fd %d failed, ret is %d, errno %d\n", m_fd, ret,
                                      errno);
                }
                break;
            case F_GETOWN: // Get process ID or process group ID receiving SIGIO/SIGURG signals
            case F_GETFL:  // Get file status flags
            case F_GETFD:  // Get file descriptor flags
                ret = OsAPiMgr::GetOriginApi()->fcntl(m_fd, cmd, arg);
                break;
            case F_DUPFD:          // Duplicate file descriptor using the lowest available fd >= arg
            case F_DUPFD_CLOEXEC:  // Duplicate file descriptor and set FD_CLOEXEC flag
            case F_SETOWN:         // Set process ID or process group ID for SIGIO/SIGURG signals
            case F_SETLK:          // Set file lock (non-blocking)
            case F_SETLKW:         // Set file lock (blocking)
            case F_GETLK:          // Get file lock information
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "fcntl fail, fd %d, cmd %d is not supported\n", m_fd, cmd);
                break;
            default:
                RPC_ADPT_VLOG_WARN("fcntl, fd %d, cmd %d may be not supported\n", m_fd, cmd);
                ret = OsAPiMgr::GetOriginApi()->fcntl(m_fd, cmd, arg);
                break;
        }
        return ret;
    }

    ALWAYS_INLINE int Fcntl64(int fd, int cmd, unsigned long int arg)
    {
        // arg can be either struct flock or int
        int ret { 0 };

        switch (cmd) {
            case F_SETFL:
                ret = OsAPiMgr::GetOriginApi()->fcntl64(m_fd, cmd, arg);
                if (ret == 0) {
                    // Update m_isblocking based on the origin fd blocking state
                    m_isblocking = IsBlocking(m_fd);
                } else {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "fcntl64 set fd %d failed, ret is %d, errno %d\n", m_fd, ret,
                                      errno);
                }
                break;
            case F_GETOWN: // Get process ID or process group ID receiving SIGIO/SIGURG signals
            case F_GETFL:  // Get file status flags
            case F_GETFD:  // Get file descriptor flags
                ret = OsAPiMgr::GetOriginApi()->fcntl64(m_fd, cmd, arg);
                break;
            case F_DUPFD:          // Duplicate file descriptor using the lowest available fd >= arg
            case F_DUPFD_CLOEXEC:  // Duplicate file descriptor and set FD_CLOEXEC flag
            case F_SETFD:          // Set file descriptor flags
            case F_SETOWN:         // Set process ID or process group ID for SIGIO/SIGURG signals
            case F_SETLK:          // Set file lock (non-blocking)
            case F_SETLKW:         // Set file lock (blocking)
            case F_GETLK:          // Get file lock information
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "fcntl64 fail, fd %d, cmd %d is not supported\n", m_fd, cmd);
                break;
            default:
                RPC_ADPT_VLOG_WARN("fcntl64, fd %d, cmd %d may be not supported\n", m_fd, cmd);
                ret = OsAPiMgr::GetOriginApi()->fcntl64(m_fd, cmd, arg);
                break;
        }
        return ret;
    }

    ALWAYS_INLINE int Ioctl(int fd, unsigned long request, unsigned long int arg)
    {
        int ret { 0 };

        if (request == FIONBIO) {
            ret = OsAPiMgr::GetOriginApi()->ioctl(m_fd, request, arg);
            if (ret == 0) {
                // set m_isblocking base on origin fd blocking state
                m_isblocking = IsBlocking(m_fd);
            } else {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "ioctl set fd %d FIONBIO failed, ret is %d, errno %d\n", m_fd,
                                  ret, errno);
            }
        } else {
            RPC_ADPT_VLOG_WARN("ioctl set fd %d, request %d may be not supported\n", m_fd, request);
            ret = OsAPiMgr::GetOriginApi()->ioctl(m_fd, request, arg);
        }
        return ret;
    }

    ALWAYS_INLINE int SetSockOpt(int fd, int level, int optname, const void *optval, socklen_t optlen)
    {
        RPC_ADPT_VLOG_INFO("SetSockOpt set fd %d, level %d, optname %d\n", m_fd, level, optname);
        return OsAPiMgr::GetOriginApi()->setsockopt(fd, level, optname, optval, optlen);
    }

    ALWAYS_INLINE void NewOriginEpollError()
    {
        m_closed.store(true, std::memory_order_relaxed);
    }

    ALWAYS_INLINE void NewOriginEpollIn(bool use_polling = false)
    {
        m_rx.m_epoll_in_msg_recv_size = 
            OsAPiMgr::GetOriginApi()->recv(m_fd, (void *)&m_rx.m_epoll_in_msg, sizeof(uint8_t), MSG_NOSIGNAL);
        if (m_rx.m_epoll_in_msg_recv_size == 0) {
            m_closed.store(true, std::memory_order_relaxed);
        } else if (!use_polling) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Unexpected EPOLLIN event through TCP\n");
        }    
    }

    ALWAYS_INLINE void NewRxEpollIn()
    {
        if (m_rx.m_epoll_event_num.fetch_add(1, std::memory_order_acq_rel) == 0) {
            m_rx.m_get_and_ack_event = true;
            m_rx.m_poll = true;
            m_rx.m_expect_epoll_event_num = 1;
        }
    }

    ALWAYS_INLINE void NewTxEpollIn()
    {
        if (m_tx.m_epoll_event_num.fetch_add(1, std::memory_order_acq_rel) == 0) {
            m_tx.m_get_and_ack_event = true;
            m_tx.m_expect_epoll_event_num = 1;
        }
    }

    ALWAYS_INLINE void NewTxEpollInEventFd()
    {
        if (m_tx.m_epoll_event_num.fetch_add(1, std::memory_order_acq_rel) == 0) {
            m_tx.m_expect_epoll_event_num = 1;
        }
    }

    ALWAYS_INLINE int RearmShareJfrRxInterrupt()
    {
        umq_interrupt_option_t rx_option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_RX };
        return umq_rearm_interrupt(m_main_umqh, false, &rx_option);
    }

    ALWAYS_INLINE int RearmRxInterrupt()
    {
        umq_interrupt_option_t rx_option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_RX };
        return umq_rearm_interrupt(m_local_umqh, false, &rx_option);
    }

    ALWAYS_INLINE int RearmTxInterrupt()
    {
        umq_interrupt_option_t tx_option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_TX };
        return umq_rearm_interrupt(m_local_umqh, true, &tx_option);
    }

    int PrefillRx()
    {
        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (enable_share_jfr && !m_need_prefill_rx) {
            return 0;
        }

        uint64_t umq_handle = enable_share_jfr ? m_main_umqh : m_local_umqh;
        m_need_prefill_rx = false;
        uint32_t left_post_rx_num = m_rx_window_capacity;
        uint32_t cur_post_rx_num = 0;
        umq_alloc_option_t option = { UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE, sizeof(IOBuf::Block) };
        do {
            cur_post_rx_num = left_post_rx_num > POST_BATCH_MAX ? POST_BATCH_MAX : left_post_rx_num;
            umq_buf_t *rx_buf_list = umq_buf_alloc(BrpcIOBufSize(), cur_post_rx_num, UMQ_INVALID_HANDLE, &option);
            if (rx_buf_list == nullptr) {
                RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to allocate RX buffer, RX depth: %u\n",
                                  m_rx_window_capacity);
                return -1;
            }

            umq_buf_t *bad_qbuf = nullptr;
            if (umq_post(umq_handle, rx_buf_list, UMQ_IO_RX, &bad_qbuf) != UMQ_SUCCESS) {
                RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to post RX buffer, RX depth: %u\n", m_rx_window_capacity);
                m_rx.m_window_size += HandleBadQBuf(rx_buf_list, bad_qbuf);
                return -1;
            }
            m_rx.m_window_size += cur_post_rx_num;
            RPC_ADPT_VLOG_DEBUG("Post RX depth: %u\n", cur_post_rx_num);
        } while ((left_post_rx_num -= cur_post_rx_num) > 0);

        uint32_t poll_cnt = 0;
        do {
            PollTx(m_tx.m_retrieve_threshold);
            if (umq_state_get(m_local_umqh) != QUEUE_STATE_IDLE) {
                break;
            }
            usleep(WAIT_UMQ_READY_TIMEOUT_US);
        } while (poll_cnt++ < WAIT_UMQ_READY_ROUND);

        if (umq_state_get(m_local_umqh) != QUEUE_STATE_READY) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Wait umq to be ready failed, umq state %d\n",
                              umq_state_get(m_local_umqh));
            return -1;
        }

        return 0;
    }

    ALWAYS_INLINE bool GetBindRemote(void)
    {
        return m_bind_remote;
    }

    ALWAYS_INLINE void SetBindRemote(bool input)
    {
        m_bind_remote = input;
    }

    // 逻辑关闭, 实际关闭得等到 read/readv 读取到 EOF.
    ALWAYS_INLINE void Close()
    {
        // 快速退出, 如果 brpc-adapter 正好在 readv/writev 中可以不经过一次 epoll_wait.
        m_closed.store(true, std::memory_order_relaxed);

        // brpc 总是会关注 EPOLLIN 事件, 将读端关闭会产生一次 epoll 事件, 之后 brpc 会尝试从 m_fd 读
        // 取数据, 预期返回 0 表示 EOF. 之后 brpc 会自动处理 socket 的关闭.
        OsAPiMgr::GetOriginApi()->shutdown(m_fd, SHUT_RD);
        RPC_ADPT_VLOG_DEBUG("closing socket fd=%d\n", m_fd);
    }

    // 收端异常 CQE 错误处理.
    void HandleErrorRxCqe(umq_buf_t *buf);

    // 发端异常 CQE 错误处理.
    void HandleErrorTxCqe(umq_buf_t *buf);

    void *operator new(std::size_t size)
    {
        void *ptr = nullptr;
        if (posix_memalign(&ptr, CACHE_LINE_ALIGNMENT, size) != 0){
            throw std::bad_alloc();
        }

        return ptr;
    }

    void operator delete(void* ptr) noexcept
    {
        free(ptr);
    }

    ALWAYS_INLINE int UmqPollAndRefillRx(umq_buf_t **buf, uint32_t max_buf_size)
    {
        Brpc::Context *context = Brpc::Context::GetContext();
        bool use_polling = context == nullptr ? false : context->GetUsePolling();
        int poll_num = use_polling ? PollingEpoll::GetInstance().GetAndPopQbuf(m_local_umqh, buf) :
                                     umq_poll(m_local_umqh, UMQ_IO_RX, buf, max_buf_size);
        if (poll_num < 0 || (poll_num == 0 && m_rx.m_window_size == 0)) {
            return -1;
        }

        m_rx.m_window_size -= static_cast<uint16_t>(poll_num);
        if (static_cast<uint16_t>(m_rx_window_capacity - m_rx.m_window_size) > m_rx.m_refill_threshold) {
            umq_alloc_option_t option = { UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE, sizeof(IOBuf::Block) };
            umq_buf_t *rx_buf_list = umq_buf_alloc(BrpcIOBufSize(), m_rx.m_refill_threshold, UMQ_INVALID_HANDLE,
                                                   &option);
            /* do nothing when failure occurs during refilling RX,
             * try to switch to tcp/ip until poll_num & m_rx.m_window_size both equal to zero */
            if (rx_buf_list != nullptr) {
                umq_buf_t *bad_qbuf = nullptr;
                if (umq_post(m_local_umqh, rx_buf_list, UMQ_IO_RX, &bad_qbuf) == UMQ_SUCCESS) {
                    m_rx.m_window_size += m_rx.m_refill_threshold;
                } else if ((m_rx.m_window_size += HandleBadQBuf(rx_buf_list, bad_qbuf)) == 0) {
                    return -1;
                }
            }
        }

        return poll_num;
    }

    int AddQbuf(umq_buf_t *qbuf)
    {
        if (rxQueue == nullptr || rxQueue->Enqueue(qbuf) != 0) {
            return -1;
        }

        return 0;
    }

    void SetShareJfrRxEpollEvent(ShareJfrRxEpollEvent *epoll_event)
    {
        share_jfr_rx_epoll_event = epoll_event;
    }

    ShareJfrRxEpollEvent *GetShareJfrRxEpollEvent() const
    {
        return share_jfr_rx_epoll_event;
    }

private:
    struct CpMsg {
        uint64_t protocol_negotiation = CONTROL_PLANE_PROTOCOL_NEGOTIATION;
        uint64_t queue_bind_info_size;
        uint8_t queue_bind_info[UMQ_BIND_INFO_SIZE_MAX];
    };

    int GetAndPopQbuf(umq_buf_t **buf, uint32_t max_buf_size)
    {
        if (rxQueue == nullptr) {
            return -1;
        }

        uint32_t i = 0;
        while (!rxQueue->IsEmpty() && i < max_buf_size) {
            if (rxQueue->Dequeue(&buf[i]) != 0) {
                return i + 1;
            }
            i++;
        }

        return i;
    }

    uint64_t GetOrCreateMainUmq(umq_create_option_t *cfg, umq_eid_t *localEid)
    {
        std::vector<uint64_t> main_umqs;
        if (!EidUmqTable::Get(*localEid, main_umqs)) {
            m_need_prefill_rx = true;
            return umq_create(cfg);
        }

        if (main_umqs.empty()) {
            return UMQ_INVALID_HANDLE;
        }

        return main_umqs.front();
    }

    uint64_t CreateSubUmq(umq_create_option_t *cfg, umq_eid_t *localEid)
    {
        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (!enable_share_jfr) {
            return umq_create(cfg);
        }

        uint64_t main_umq = GetOrCreateMainUmq(cfg, localEid);
        if (main_umq == UMQ_INVALID_HANDLE) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to create main umq\n");
            return UMQ_INVALID_HANDLE;
        }

        cfg->create_flag |= UMQ_CREATE_FLAG_SHARE_RQ | UMQ_CREATE_FLAG_UMQ_CTX | UMQ_CREATE_FLAG_SUB_UMQ;
        cfg->share_rq_umqh = main_umq;
        cfg->umq_ctx = (uint64_t)m_fd;
        uint64_t sub_umq = umq_create(cfg);
        if (sub_umq == UMQ_INVALID_HANDLE) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to create sub umq\n");
            return UMQ_INVALID_HANDLE;
        }

        EidUmqTable::Add(*localEid, main_umq);
        MainSubUmqTable::Add(main_umq, sub_umq);

        m_main_umqh = main_umq;
        uint64_t share_jfr_rx_queue_depth = context == nullptr ? DEFAULT_SHARE_JFR_RX_QUEUE_DEPTH :
                                                                 context->GetShareJfrRxQueueDepth();
        rxQueue = new QbufQueue<umq_buf_t *>(share_jfr_rx_queue_depth);
        return sub_umq;
    }

    int GetDevEid(char *dev_name, uint32_t eid_idx, umq_eid_t *eid)
    {
        umq_dev_info_t umq_dev_info = {};
        int ret = umq_dev_info_get(dev_name, UMQ_TRANS_MODE_UB, &umq_dev_info);
        if (ret != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to get device information\n");
            return -1;
        }

        for (uint32_t i = 0; i < umq_dev_info.ub.eid_cnt; ++i) {
            if (umq_dev_info.ub.eid_list[i].eid_index == eid_idx) {
                *eid = umq_dev_info.ub.eid_list[i].eid;
                return 0;
            }
        }

        return -1;
    }

    int CreateLocalUmq(umq_eid_t *connEid)
    {
        if (m_local_umqh != UMQ_INVALID_HANDLE) {
            return EEXIST;
        }

        Context *context = Context::GetContext();
        if (context->IsBonding() && connEid == nullptr){
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to use eid, because eid is null\n");
            return -1;
        }
        umq_create_option_t queue_cfg;
        memset_s(&queue_cfg, sizeof(queue_cfg), 0, sizeof(queue_cfg));
        queue_cfg.trans_mode = context->GetTransMode();
        queue_cfg.create_flag = UMQ_CREATE_FLAG_TX_DEPTH | UMQ_CREATE_FLAG_RX_DEPTH |
                                UMQ_CREATE_FLAG_RX_BUF_SIZE | UMQ_CREATE_FLAG_TX_BUF_SIZE |
                                UMQ_CREATE_FLAG_QUEUE_MODE | UMQ_CREATE_FLAG_TP_MODE |
                                UMQ_CREATE_FLAG_TP_TYPE | UMQ_CREATE_FLAG_UMQ_CTX;
        queue_cfg.rx_depth = context->GetRxDepth();
        queue_cfg.tx_depth = context->GetTxDepth();
        queue_cfg.rx_buf_size = BrpcIOBufSize();
        queue_cfg.tx_buf_size = BrpcIOBufSize();
        queue_cfg.mode = UMQ_MODE_INTERRUPT;
        // 共享 JFR、AE 事件依赖 umq_ctx.
        queue_cfg.umq_ctx = m_fd;

        int n = snprintf_s(queue_cfg.name, UMQ_NAME_MAX_LEN, UMQ_NAME_MAX_LEN - 1, "fd: %d", m_fd);
        if ((((int)UMQ_NAME_MAX_LEN - 1) < n) || (n < 0)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to set umq name\n");
            return -1;
        }

        umq_eid_t localEid;
        if (context->GetDevIpStr() != nullptr) {
            if (context->IsDevIpv6()) {
                queue_cfg.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_IPV6;
                if (strcpy_s(queue_cfg.dev_info.ipv6.ip_addr, UMQ_IPV6_SIZE, context->GetDevIpStr()) != EOK) {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to strcpy_s device ipv6 address\n");
                    return -1;
                } 
            } else {
                queue_cfg.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_IPV4;
                if (strcpy_s(queue_cfg.dev_info.ipv4.ip_addr, UMQ_IPV4_SIZE, context->GetDevIpStr()) != EOK) {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to strcpy_s device ipv4 address\n");
                    return -1;
                }     
            }
        } else if (context -> GetDevNameStr() != nullptr) {
            if (strcpy_s(queue_cfg.dev_info.dev.dev_name, UMQ_DEV_NAME_SIZE, context->GetDevNameStr()) != EOK) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to strcpy_s device name\n");
                return -1;
            }
            if(!context->IsBonding()){
                queue_cfg.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
                queue_cfg.dev_info.dev.eid_idx = context->GetEidIdx();

                if (GetDevEid(queue_cfg.dev_info.dev.dev_name, context->GetEidIdx(), &localEid) != 0) {
                    RPC_ADPT_VLOG_WARN("Failed to get eid by dev name:%s and eid index:%d \n", context->GetDevNameStr(),
                                       context->GetEidIdx());
                }
            } else {
                // init use bonding dev
                queue_cfg.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
                queue_cfg.dev_info.eid.eid = *connEid;
                localEid = *connEid;
            }
        } else {
            if (strcpy_s(queue_cfg.dev_info.dev.dev_name, UMQ_DEV_NAME_SIZE, "bonding_dev_0") != EOK) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to strcpy_s device name\n");
                return -1;
            }
            if (context->IsBonding()) {
                queue_cfg.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
                queue_cfg.dev_info.eid.eid = *connEid;
            }
        }

        ub_trans_mode trans_mode = context->GetUbTransMode();
        if (trans_mode == RC_TP) {
            queue_cfg.tp_mode = UMQ_TM_RC;
            queue_cfg.tp_type = UMQ_TP_TYPE_RTP;
        } else if (trans_mode == RM_TP) {
            queue_cfg.tp_mode = UMQ_TM_RM;
            queue_cfg.tp_type = UMQ_TP_TYPE_RTP;
        } else if (trans_mode == RM_CTP) {
            queue_cfg.tp_mode = UMQ_TM_RM;
            queue_cfg.tp_type = UMQ_TP_TYPE_CTP;
        } else if (trans_mode == RC_CTP) {
            queue_cfg.tp_mode = UMQ_TM_RC;
            queue_cfg.tp_type = UMQ_TP_TYPE_CTP;
        }
 	 
        m_local_umqh = CreateSubUmq(&queue_cfg, &localEid);
        if (m_local_umqh == UMQ_INVALID_HANDLE) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to execute umq_create failed\n");
            return RETRY_NEEDED;
        }

        Context::FetchAdd();

        return 0;
    }

    void UnbindAndFlushRemoteUmq()
    {
        if (!m_bind_remote) {
            return;
        }

        if (m_tx.m_event_num > 0) {
            umq_interrupt_option_t option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_TX};
            umq_ack_interrupt(m_local_umqh, m_tx.m_event_num, &option);
            m_tx.m_event_num = 0;
        }

        if (m_rx.m_event_num > 0) {
            umq_interrupt_option_t option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_RX};
            umq_ack_interrupt(m_local_umqh, m_rx.m_event_num, &option);
            m_rx.m_event_num = 0;
        }
        
        (void)umq_unbind(m_local_umqh);
        FlushTx();

        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        enable_share_jfr ? FlushRxQueue() : FlushRx();
    }

    void FlushRxQueue()
    {
        if (rxQueue == nullptr) {
            return;
        }

        while (!rxQueue->IsEmpty()) {
            umq_buf_t *buf[1];
            if (rxQueue->Dequeue(buf) != 0) {
                return;
            }
            umq_buf_free(buf[0]);
        }
    }

    void DeleteSubUmq()
    {
        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (!enable_share_jfr) {
            return;
        }

        MainSubUmqTable::RemoveSubUmq(m_main_umqh, m_local_umqh);
    }

    void DestroyLocalUmq(void)
    {
        if (m_local_umqh != UMQ_INVALID_HANDLE) {
            // need to flush
            (void)umq_destroy(m_local_umqh);
            DeleteSubUmq();
            m_local_umqh = UMQ_INVALID_HANDLE;
            Context::FetchSub();
        }
    }

    static int ValidateProtocol(int fd, uint64_t &protocol_negotiation, ssize_t &protocol_negotiation_recv_size)
    {
        protocol_negotiation_recv_size =
           RecvSocketData(fd, &protocol_negotiation, sizeof(protocol_negotiation), NEGOTIATE_TIMEOUT_MS);
        if (protocol_negotiation_recv_size <= 0) {
            return -1;
        }
        
        if (protocol_negotiation_recv_size != sizeof(protocol_negotiation) ||
            protocol_negotiation != CONTROL_PLANE_PROTOCOL_NEGOTIATION) {
            return protocol_negotiation_recv_size;
        }

        return 0;
    }

    ALWAYS_INLINE ssize_t OutputErrorMagicNumber(const struct iovec *iov, int iovcnt)
    {
        if (m_tx.m_protocol_negotiation_recv_size == 0) {
            return 0;
        }

        ssize_t rx_total_len = 0;
        int iov_idx = 0;
        do {
            size_t copy_size = iov[iov_idx].iov_len < m_tx.m_protocol_negotiation_recv_size ?
                iov[iov_idx].iov_len : m_tx.m_protocol_negotiation_recv_size;
            (void)memcpy_s(iov[iov_idx++].iov_base, copy_size,
                (char *)&m_tx.m_protocol_negotiation + m_tx.m_protocol_negotiation_offset, copy_size);
            m_tx.m_protocol_negotiation_recv_size -= copy_size;
            m_tx.m_protocol_negotiation_offset += copy_size;
            rx_total_len += copy_size;        
        } while (m_tx.m_protocol_negotiation_recv_size > 0 && iov_idx < iovcnt);

        if (m_tx.m_protocol_negotiation_recv_size == 0) {
            m_rx_use_tcp = true;
        }

        return rx_total_len;
    }

    int AcceptExchangeTransMode(int new_fd)
    {
        Context *context = Context::GetContext();
        ub_trans_mode remoteTransMode;
        if (RecvSocketData(new_fd, &remoteTransMode, sizeof(ub_trans_mode), CONTROL_PLANE_TIMEOUT_MS)
            != sizeof(ub_trans_mode)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to receive remote TransMode message in accept, fd: %d\n",
                              new_fd);
            return -1;
        }
        ub_trans_mode localTransMode = context->GetUbTransMode();
        if (SendSocketData(new_fd, &localTransMode, sizeof(ub_trans_mode), CONTROL_PLANE_TIMEOUT_MS)
            != sizeof(ub_trans_mode)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send local TransMode message in connect, fd: %d\n",
                              new_fd);
            return -1;
        }

        if (localTransMode != remoteTransMode) {
            if (remoteTransMode < localTransMode) {
                context->SetUbTransMode(remoteTransMode);
            } else {
                context->SetUbTransMode(localTransMode);
            }
        }

        return 0;
    }

    int AcceptExchangeEid(int new_fd, umq_eid_t &connEid, umq_eid_t &remoteEid, umq_route_t &connRoute)
    {
        Context *context = Context::GetContext();
        if (!context->IsBonding()) {
            return 0;
        }

        if (RecvSocketData(
            new_fd, &remoteEid, sizeof(umq_eid_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_eid_t)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to receive remote eid message in accept, fd: %d\n", new_fd);
            return -1;
        }

        umq_eid_t localEid = context->GetDevSrcEid();
        if (SendSocketData(new_fd, &localEid, sizeof(umq_eid_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_eid_t)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send local eid message in accept, fd: %d\n", new_fd);
            return -1;
        }

        // 保存对端EID
        m_peer_info.peer_eid = remoteEid;
        connEid = context->GetDevSrcEid();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (enable_share_jfr || localEid != remoteEid) {
            dev_schedule_policy schedulePolicy = context->GetDevSchedulePolicy();
            if (SendSocketData(new_fd, &schedulePolicy, sizeof(dev_schedule_policy), CONTROL_PLANE_TIMEOUT_MS) !=
                sizeof(dev_schedule_policy)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send schedule policy in accept, fd: %d\n", new_fd);
                return -1;
            }

            dev_schedule_policy peerSchedulePolicy;
            if (RecvSocketData(new_fd, &peerSchedulePolicy, sizeof(dev_schedule_policy), CONTROL_PLANE_TIMEOUT_MS) !=
                sizeof(dev_schedule_policy)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to receive remote socket id in accept, fd: %d\n", new_fd);
                return -1;
            }

            bool useRoundRobin = true;
            if (peerSchedulePolicy == schedulePolicy && schedulePolicy == dev_schedule_policy::CPU_AFFINITY) {
                RPC_ADPT_VLOG_WARN("Use consistent schedule policy CPU_AFFINITY in accept, fd: %d\n", m_fd);
                useRoundRobin = false;
                // 亲和策略需要接收socketId
                if (RecvSocketData(
                    new_fd, &mPeerSocketId, sizeof(int), CONTROL_PLANE_TIMEOUT_MS) != sizeof(int)) {
                    RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to receive remote socket id in accept, fd: %d\n",
                                      new_fd);
                    return -1;
                }
            }

            if (DoRoute(&localEid, &remoteEid, &connRoute, useRoundRobin) != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to get route list in accept, fd: %d\n", new_fd);
                return -1;
            }

            if (SendSocketData(
                new_fd, &connRoute, sizeof(umq_route_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_route_t)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send connect eid message in accept, fd: %d\n", new_fd);
                return -1;
            }
            // 保存对端EID
            m_peer_info.peer_eid = connRoute.dst;
            connEid = connRoute.src;
        }

        return 0;
    }

    void PrintQbufPoolInfo()
    {
        umq_qbuf_pool_stats_t qbuf_pool_stats;
        umq_stats_qbuf_pool_get(m_main_umqh, &qbuf_pool_stats);
        if (qbuf_pool_stats.num == 1) {
            uint64_t size_with_data = qbuf_pool_stats.qbuf_pool_info[0].available_mem.split.size_with_data;
            RPC_ADPT_VLOG_INFO("UMQ qbuf pool available buf size in data area: %lu \n", size_with_data);
        }
    }

    int DoUbAccept(int new_fd, umq_eid_t &connEid, SocketFd *socket_fd_obj)
    {
        CpMsg local_cp_msg;
        CpMsg remote_cp_msg;
        char send_sync_msg[] = UMQ_BIND_SYNC_MSG;
        char recv_sync_msg[] = UMQ_BIND_SYNC_MSG;

        int ret = socket_fd_obj->CreateLocalUmq(&connEid);
        if ((ret < 0) || (ret == RETRY_NEEDED)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to create umq\n");
            return ret;
        }

        local_cp_msg.queue_bind_info_size = umq_bind_info_get(
            socket_fd_obj->GetLocalUmqHandle(), local_cp_msg.queue_bind_info, sizeof(local_cp_msg.queue_bind_info));
        if (local_cp_msg.queue_bind_info_size == 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to execute umq_bind_info_get\n");
            return RETRY_NEEDED;
        }
        
        size_t len = sizeof(remote_cp_msg) - sizeof(uint64_t);
        if (RecvSocketData(
            new_fd, &remote_cp_msg.queue_bind_info_size, len, CONTROL_PLANE_TIMEOUT_MS) != (ssize_t)len) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to receive remote control message, fd: %d\n", new_fd);
            return -1;
        }
        RPC_ADPT_VLOG_DEBUG("recv remote control message, fd: %d, cp msg len: %d, bind info len: %d\n",
            new_fd, sizeof(remote_cp_msg), remote_cp_msg.queue_bind_info_size);

        if (SendSocketData(
            new_fd, &local_cp_msg, sizeof(local_cp_msg), CONTROL_PLANE_TIMEOUT_MS) != sizeof(local_cp_msg)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send local control message, fd: %d\n", new_fd);
            return -1;
        }
        RPC_ADPT_VLOG_DEBUG("send local control message, fd: %d, cp msg len: %d, bind info len: %d\n",
            new_fd, sizeof(local_cp_msg), local_cp_msg.queue_bind_info_size);
        
        if (umq_bind(socket_fd_obj->GetLocalUmqHandle(), remote_cp_msg.queue_bind_info,
            remote_cp_msg.queue_bind_info_size) != UMQ_SUCCESS) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to execute umq_bind\n");
            return RETRY_NEEDED;
        }
        socket_fd_obj->SetBindRemote(true);

        // 1650 RC mode not support post rx right after create jetty, thus, move post rx operation after bind()
        if (socket_fd_obj->PrefillRx() != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to fill rx buffer to umq, fd: %d\n", new_fd);
            return -1;
        }

        if (SendSocketData(
            new_fd, send_sync_msg, sizeof(send_sync_msg), CONTROL_PLANE_TIMEOUT_MS) != sizeof(send_sync_msg)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send sync done message, fd: %d\n", new_fd);
            return -1;
        }

        if (RecvSocketData(
            new_fd, recv_sync_msg, sizeof(recv_sync_msg), CONTROL_PLANE_TIMEOUT_MS) != sizeof(recv_sync_msg) ||
            strcmp(recv_sync_msg, UMQ_BIND_SYNC_MSG) != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to receive sync done message, fd: %d\n", new_fd);
            return -1;
        }

        return 0;
    }

    int DoAccept(int new_fd)
    {
        SocketFd *socket_fd_obj = nullptr;
        int event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        try {
            socket_fd_obj = new SocketFd(new_fd, event_fd);
        } catch (std::exception& e) {
            OsAPiMgr::GetOriginApi()->close(event_fd);
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "%s\n", e.what());
            return -1;
        }

        uint64_t protocol_negotiation = CONTROL_PLANE_PROTOCOL_NEGOTIATION;
        if (SendSocketData(
            new_fd, &protocol_negotiation, sizeof(uint64_t), NEGOTIATE_TIMEOUT_MS) != sizeof(uint64_t)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to protocol negotiation number, fd: %d\n", new_fd);
            return -1;
        }

        if (AcceptExchangeTransMode(new_fd) != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to exchange TransMode in accept\n");
            delete socket_fd_obj;
            return -1;
        }

        umq_eid_t connEid;
        umq_eid_t peerBondingEid;
        umq_route_t connRoute;
        if (AcceptExchangeEid(new_fd, connEid, peerBondingEid, connRoute) != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to exchange eid in accept,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), new_fd);
            delete socket_fd_obj;
            return -1;
        }
        
        int ackRet = DoUbAccept(new_fd, connEid, socket_fd_obj);
        if (SendSocketData(
            new_fd, &ackRet, sizeof(int), CONTROL_PLANE_TIMEOUT_MS) != sizeof(int)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to send ack ret,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), new_fd);
            delete socket_fd_obj;
            return -1;
        }

        int peerRet;
        if (RecvSocketData(
            new_fd, &peerRet, sizeof(int), CONTROL_PLANE_TIMEOUT_MS) != sizeof(int)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Failed to receive peer ack ret,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                              EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), new_fd);
            delete socket_fd_obj;
            return -1;
        }

        // 1.用户直接指定普通设备建链，DoUbAccept等于RETRY_NEEDED，不重试
        // 2.用户指定bonding设备建链，但如果是节点内回环场景，DoUbAccept等于RETRY_NEEDED，不重试
        // 3.用户指定bonding设备建链，但使用get_route_list获得的eid建链（跨节点场景），DoUbAccept等于RETRY_NEEDED，重试
        Context *context = Context::GetContext();
        umq_eid_t localEid = context->GetDevSrcEid();
        if ((context->IsBonding()) && (connEid != localEid)&& (ackRet == RETRY_NEEDED || peerRet == RETRY_NEEDED)) {
            // 重试
            socket_fd_obj->UnbindAndFlushRemoteUmq();
            socket_fd_obj->DestroyLocalUmq();

            umq_route_t otherConnRoute;
            if (CheckOtherRoute(otherConnRoute, peerBondingEid, connRoute) != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to get other route in retry,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), new_fd);
                delete socket_fd_obj;
                return -1;
            }
            if (SendSocketData(
                new_fd, &otherConnRoute, sizeof(umq_route_t), CONTROL_PLANE_TIMEOUT_MS) != sizeof(umq_route_t)) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to send connect eid message in retry accept,Peer eid:" EID_FMT
                                  ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), new_fd);
                delete socket_fd_obj;
                return -1;
            }

            ackRet = DoUbAccept(new_fd, otherConnRoute.src, socket_fd_obj);
            if (ackRet != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to get new connect in retry accept,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), new_fd);
                delete socket_fd_obj;
                return -1;
            }
        } else {
            if (ackRet != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                                  "Failed to get new connect in accept,Peer eid:" EID_FMT ",Peer IP:%s, fd: %d\n",
                                  EID_ARGS(GetPeerEid()), GetPeerIp().c_str(), new_fd);
                delete socket_fd_obj;
                return -1;
            }
        }

        if (m_context_trace_enable) {
            socket_fd_obj->InitStatsMgr();
        }

        // Delete existing objects and record new objects in the list.
        Fd<::SocketFd>::OverrideFdObj(new_fd, socket_fd_obj);

        if (context && context->GetUsePolling()) {
            Socket *sock = NULL;
            if (PollingEpoll::GetInstance().SocketCreate(&sock, new_fd, SocketType::SOCKET_TYPE_TCP_SERVER,
                                                         socket_fd_obj->GetLocalUmqHandle()) != 0) {
                RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "SocketCreate failed \n");
            } else {
                PollingEpoll::GetInstance().AddSocket(new_fd, sock);
            }
        }

        RPC_ADPT_VLOG_INFO("UB connection has been successfully established new fd: %d\n", new_fd);

        PrintQbufPoolInfo();

        return 0;  
    }

    ALWAYS_INLINE void *PtrFloorToBoundary(void *ptr)
    {
        return (void *)((uint64_t)ptr & ~FloorMask());
    }

    ALWAYS_INLINE void ProcessErrorTxCqe(umq_buf_t *first_qbuf)
    {
        umq_buf_t *cur_qbuf = first_qbuf;
        umq_buf_t *last_qbuf = nullptr;
        int64_t left_size = (int64_t)cur_qbuf->total_data_size;
        while (cur_qbuf != nullptr && left_size > 0) {
            left_size -= cur_qbuf->data_size;
            /* rpc adapter has replace brpc butil::iobuf::blockmeme_allocate() &
            * butil::iof::blockmem_deallocate() and ensures that the starting address
            * of the Block is aligned to an 8k boundary. */
            ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur_qbuf->buf_data))->DecRef();
            last_qbuf = cur_qbuf;
            cur_qbuf = QBUF_LIST_NEXT(cur_qbuf);
        }

        QBUF_LIST_NEXT(last_qbuf) = nullptr;
        umq_buf_free(first_qbuf);
    }

    ALWAYS_INLINE int ProcessTxCqe(umq_buf_t *start_qbuf, umq_buf_t *end_qbuf)
    {
        int wr_cnt = 0;
        umq_buf_t *cur_qbuf = start_qbuf;
        umq_buf_t *last_qbuf = nullptr;
        umq_buf_t *wr_first_buf;
        do {
            wr_first_buf = cur_qbuf;
            int64_t left_size = (int64_t)wr_first_buf->total_data_size;
            while (cur_qbuf != nullptr && left_size > 0) {
                left_size -= cur_qbuf->data_size;
                /* rpc adapter has replace brpc butil::iobuf::blockmeme_allocate() &
                * butil::iof::blockmem_deallocate() and ensures that the starting address
                * of the Block is aligned to an 8k boundary. */
                ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur_qbuf->buf_data))->DecRef();
                last_qbuf = cur_qbuf;
                cur_qbuf = QBUF_LIST_NEXT(cur_qbuf);
            }
            wr_cnt++;
        } while (cur_qbuf != nullptr && wr_first_buf != end_qbuf);

        if (wr_first_buf == nullptr) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "TX umq buffer list is in error, TX user context does not contain the right list\n");
            return -1;
        }

        QBUF_LIST_NEXT(last_qbuf) = nullptr;
        umq_buf_free(start_qbuf);

        return wr_cnt;
    }

    ALWAYS_INLINE int UmqPollTx(error_code &err_code)
    {
        umq_buf_t *buf[POLL_BATCH_MAX];
        int poll_num = umq_poll(m_local_umqh, UMQ_IO_TX, buf, POLL_BATCH_MAX);
        if (poll_num <= 0) {
            return poll_num;
        }

        int wr_cnt = 0;
        int cur_wr_cnt;
        umq_buf_t *first_qbuf = nullptr;
        for (int i = 0; i < poll_num; ++i) {
            if (buf[i] == nullptr || buf[i]->status != 0 ||
                (first_qbuf = (umq_buf_t *)((umq_buf_pro_t *)(buf[i]->qbuf_ext))->user_ctx) == nullptr) {
                
                // set err_code to true to force a quick exit from current function.
                err_code = SocketFd::UMQ_ERROR;
                
                if (buf[i] == nullptr) {
                    RPC_ADPT_VLOG_DEBUG("TX CQE is invalid, umq buffer is empty\n");
                    continue;
                }

                if (buf[i]->status != 0) {
                    HandleErrorTxCqe(buf[i]);
                    ProcessErrorTxCqe(buf[i]);
                    wr_cnt++;
                    if (m_context_trace_enable) {
                        if (buf[i]->status == UMQ_BUF_ACK_TIMEOUT_ERR) {
                            UpdateTraceStats(StatsMgr::TX_LOST_PACKET_COUNT, 1);
                        } else {
                            UpdateTraceStats(StatsMgr::TX_ERROR_PACKET_COUNT, 1);
                        }
                    }
                    continue;
                }

                RPC_ADPT_VLOG_DEBUG("TX CQE is invalid, status: %d%s\n", buf[i]->status,
                    first_qbuf == nullptr ? ", and umq buffer list is empty" : "");
                continue;
            }

            cur_wr_cnt = ProcessTxCqe(first_qbuf, buf[i]);
            if (cur_wr_cnt < 0) {
                // set err_code to true to force a quick exit from current function.
                err_code = SocketFd::FATAL_ERROR;
                return wr_cnt;
            }

            wr_cnt += cur_wr_cnt;
        }

        return wr_cnt;
    }

    ALWAYS_INLINE int DpRearmTxInterrupt()
    {
        umq_interrupt_option_t tx_option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_TX };
        if (umq_rearm_interrupt(m_local_umqh, false, &tx_option) == 0) {
            errno = EAGAIN;
            return -1;
        }

        // 1. try to switch to tcp/ip
        // 2. use EIO for now
        errno = EIO;
        return -1;
    }

    ALWAYS_INLINE void PollTx(
        uint32_t threshold, bool poll_to_empty = false, uint32_t max_retry_cnt = POLL_TX_RETRY_MAX_CNT)
    {
        uint32_t poll_total_cnt = 0;
        int poll_cnt  = 0;
        uint32_t poll_zero_cnt = 0;
        error_code err_code = SocketFd::OK;
        do {
            poll_cnt = UmqPollTx(err_code);
            if (poll_cnt < 0) {
                break;
            } else if (poll_cnt == 0) {
                poll_zero_cnt++;
            } else if (poll_zero_cnt != 0) {
                // reset poll_zero_cnt when actually get tx cqe(s)
                poll_zero_cnt = 0;
            }
            poll_total_cnt += (uint32_t)poll_cnt;
        } while ((poll_total_cnt < threshold || (poll_to_empty && poll_cnt > 0)) &&
            poll_zero_cnt < max_retry_cnt && err_code == SocketFd::OK);
        m_tx.m_window_size += poll_total_cnt;    
    } 
    
    ALWAYS_INLINE void FlushTx(uint32_t timeout_ms = FLUSH_TIMEOUT_MS)
    {
        uint16_t threshold = m_tx_window_capacity - m_tx.m_window_size;
        if (threshold <= 0) {
            return;
        }

        uint32_t poll_total_cnt = 0;
        int poll_cnt = 0;
        error_code err_code = SocketFd::OK;
        auto start = std::chrono::high_resolution_clock::now();
        do {
            if (IsTimeout(start, timeout_ms)) {
                /* If a timeout is triggered here, it would indicate a memory leak.
                 * In this case, processing of unsignaled wr should not continue. */
                RPC_ADPT_VLOG_DEBUG("Flush TX operation exceeded timeout period(%u ms)\n", timeout_ms);
                break; 
            }

            poll_cnt = UmqPollTx(err_code);
            if (poll_cnt < 0) {
                break;
            }

            poll_total_cnt += (uint32_t)poll_cnt;
        } while (::ConfigSettings::GetSocketFdTransMode() != ::ConfigSettings::SOCKET_FD_TRANS_MODE_UNSET &&
            poll_total_cnt < threshold && err_code != SocketFd::FATAL_ERROR);
        m_tx.m_window_size += poll_total_cnt;
        
        if (err_code != SocketFd::FATAL_ERROR &&
            m_tx.m_window_size < m_tx_window_capacity && m_tx.m_unsignaled_wr_num > 0) {
            uint32_t left_wr_num = m_tx_window_capacity - m_tx.m_window_size;
            umq_buf_t *cur_qbuf = QBUF_LIST_FIRST(&m_tx.m_head_buf);
            umq_buf_t *last_qbuf = nullptr;
            uint32_t cached_wr_cnt = 0;
            while (cached_wr_cnt < left_wr_num && cur_qbuf != nullptr) {
                /* unsignaled wr list:
                 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                 * |  0  |  1  |  2  |  3  |  4  |  5  |  6  | wr idx
                 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                 * |  S  |  S  |  S  |  F  |  F  |  F  |  F  | wr status: (1) S:successful; (2) F:Failed
                 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                 * Since the successful wr(0~2) did not set the signaled flag, it will not generate a cqe
                 * Therefore, it is necessary to perform a release operation through the cache list.
                 * The unsuccessful(3 ~ 6) wrs have already been released and retried via(by tcp) an
                 * exceptional cqe within the UmqPollTx() operation, so there is no need to handle these wrs
                 * again here. Consequently, only 0 ~ 2 wrs need to be processed. */
                int64_t rest_size = cur_qbuf->total_data_size;
                /* WriteV ensure total_data_size equals to the sum of all data_size, thus, do not consider
                * the situation that rest_size would not reduced to zero */
                while (cur_qbuf && rest_size > 0) {
                    rest_size -= (int64_t)cur_qbuf->data_size;
                    last_qbuf = cur_qbuf;
                    ((Brpc::IOBuf::Block *)PtrFloorToBoundary(cur_qbuf->buf_data))->DecRef();
                    cur_qbuf = QBUF_LIST_NEXT(cur_qbuf);
                }
                
                cached_wr_cnt++;
            }

            if (last_qbuf != nullptr) {
                QBUF_LIST_NEXT(last_qbuf) = nullptr;
            }

            umq_buf_free(QBUF_LIST_FIRST(&m_tx.m_head_buf));
            m_tx.m_window_size += cached_wr_cnt;
        }

        if (m_tx.m_window_size < m_tx_window_capacity) {
            RPC_ADPT_VLOG_DEBUG("Failed to flush umq(TX), leak %u wr(s) of buffer\n",
                m_tx_window_capacity - m_tx.m_window_size);
        }
    }

    ALWAYS_INLINE void FlushRx(uint32_t timeout_ms = FLUSH_TIMEOUT_MS)
    {
        m_rx.m_block_cache.Flush();

        if (m_rx.m_window_size <= 0) {
            return;
        }

        umq_buf_t *buf[POLL_BATCH_MAX];
        uint32_t poll_total_cnt = 0;
        int poll_cnt = 0;
        auto start = std::chrono::high_resolution_clock::now();
        do {
            if (IsTimeout(start, timeout_ms)) {
                RPC_ADPT_VLOG_DEBUG("Flush RX operation exceeded timeout period(%u ms)\n", timeout_ms);
                break; 
            }

            poll_cnt = umq_poll(m_local_umqh, UMQ_IO_RX, buf, POLL_BATCH_MAX);
            if (poll_cnt < 0) {
                break;
            }

            for (int i = 0; i < poll_cnt; i++) {
                if (buf[i]->status == UMQ_FAKE_BUF_FC_UPDATE) {
                    if (eventfd_write(m_event_fd, 1) == -1) {
                        RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "write event fd %d failed, errno %d\n", m_event_fd,
                                          errno);
                    }
                }
                umq_buf_free(buf[i]);
            }

            poll_total_cnt += (uint32_t)poll_cnt;
        } while (::ConfigSettings::GetSocketFdTransMode() != ::ConfigSettings::SOCKET_FD_TRANS_MODE_UNSET &&
            poll_total_cnt < m_rx.m_window_size);

        if ((m_rx.m_window_size -= poll_total_cnt) > 0) {
            RPC_ADPT_VLOG_DEBUG("Failed to flush umq(RX), leak %u piece(s) of buffer\n", m_rx.m_window_size);
        }
    }

    ALWAYS_INLINE void AckEvent(uint16_t &event_num, uint16_t add_event_num, umq_interrupt_option_t *option)
    {
        if ((event_num += add_event_num) >= GET_PER_ACK) {
            umq_ack_interrupt(m_local_umqh, event_num, option);
            event_num = 0;
        }
    }

    ALWAYS_INLINE int GetAndAckEvent(umq_io_direction_t dir)
    {
        umq_interrupt_option_t option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, dir };
        int events = umq_get_cq_event(m_local_umqh, &option);
        if (events == 0) {
            return 0;
        } else if (events < 0) {
            return -1;
        }

        AckEvent(dir == UMQ_IO_TX ? m_tx.m_event_num : m_rx.m_event_num, events, &option);

        return 0;
    }

    ALWAYS_INLINE int GetQbuf(umq_buf_t **buf, uint32_t max_buf_size)
    {
        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (!enable_share_jfr) {
            return UmqPollAndRefillRx(buf, max_buf_size);
        }

        int poll_num = GetAndPopQbuf(buf, max_buf_size);
        if (poll_num < 0) {
            return -1;
        }

        return poll_num;
    }

    ALWAYS_INLINE uint32_t HandleBadQBuf(umq_buf_t *head_qbuf, umq_buf_t *bad_qbuf, umq_buf_t *last_head_qbuf,
        uint16_t unsolicited_wr_num, uint32_t unsolicited_bytes, uint16_t unsignaled_wr_num)
    {
        umq_buf_t *cur_qbuf = head_qbuf;
        umq_buf_t *last_qbuf = nullptr;
        umq_buf_t *head_qbuf_ = last_head_qbuf;
        uint32_t wr_cnt = 0;
        uint16_t _unsolicited_wr_num = unsolicited_wr_num;
        uint32_t _unsolicited_bytes = unsolicited_bytes;
        uint16_t _unsignaled_wr_num = unsignaled_wr_num;
        uint32_t total_size = 0;

        while (cur_qbuf != bad_qbuf) {
            int64_t rest_size = cur_qbuf->total_data_size;
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)cur_qbuf->qbuf_ext;
            if (buf_pro->flag.bs.solicited_enable == 1) {
                _unsolicited_wr_num = 0;
                _unsolicited_bytes = 0;
            } else {
                _unsolicited_wr_num++;
                _unsolicited_bytes += cur_qbuf->total_data_size;
            }

            if (buf_pro->flag.bs.complete_enable == 1) {
                _unsignaled_wr_num = 0;
            } else {
                _unsignaled_wr_num++;
            }

            total_size += cur_qbuf->total_data_size;

            /* WriteV ensure total_data_size equals to the sum of all data_size, thus, do not consider
             * the situation that rest_size would not reduced to zero */
            while (cur_qbuf && rest_size > 0) {
                rest_size -= (int64_t)cur_qbuf->data_size;
                last_qbuf = cur_qbuf;
                cur_qbuf = QBUF_LIST_NEXT(cur_qbuf);
            }

            if (buf_pro->flag.bs.complete_enable == 1) {
                /* If the last successfully posted wr has 'complete_enable' set, it means no need to cache
                 * the posted qbuf list anymore, then reset head to nullptr */
                head_qbuf_ = (cur_qbuf != bad_qbuf) ? cur_qbuf : nullptr;
            }
                
            wr_cnt++;
        }
        
        m_tx.m_unsolicited_wr_num = _unsolicited_wr_num;
        m_tx.m_unsolicited_bytes = _unsolicited_bytes;
        m_tx.m_unsignaled_wr_num = _unsignaled_wr_num;
        m_tx.m_window_size -= wr_cnt;

        QBUF_LIST_FIRST(&m_tx.m_head_buf) = head_qbuf_;
        if (last_qbuf != nullptr) {
            /* If head set to nullptr, it means no need to cache the posted qbuf list anymore, reset head
             * to nullptr as well */
            QBUF_LIST_FIRST(&m_tx.m_tail_buf) = (head_qbuf_ == nullptr) ? nullptr : last_qbuf;
            QBUF_LIST_NEXT(last_qbuf) = nullptr;
        }

        umq_buf_free(bad_qbuf);
        return total_size;
    }
    
    ALWAYS_INLINE uint32_t HandleBadQBuf(umq_buf_t *head_qbuf, umq_buf_t *bad_qbuf)
    {
        umq_buf_t *cur_qbuf = head_qbuf;
        umq_buf_t *last_qbuf = nullptr;
        uint32_t wr_cnt = 0;
        while (cur_qbuf != bad_qbuf) {
            int64_t rest_size = cur_qbuf->total_data_size;
            /* WriteV ensure total_data_size equals to the sum of all data_size, thus, do not consider
             * the situation that rest_size would not reduced to zero */
            while (cur_qbuf && rest_size > 0) {
                rest_size -= (int64_t)cur_qbuf->data_size;
                last_qbuf = cur_qbuf;
                cur_qbuf = QBUF_LIST_NEXT(cur_qbuf);
            }

            wr_cnt++;
        }
        
        if (last_qbuf != nullptr) {
            QBUF_LIST_NEXT(last_qbuf) = nullptr;
        }

        umq_buf_free(bad_qbuf);
        return wr_cnt;
    }

    void GetBondingEidMapIndex(const umq_eid_t &dstEid, uint32_t &index)
    {
        if (!mEidRegistry.IsRegisteredEidIndex(dstEid)) {
            mEidRegistry.RegisterOrReplaceEidIndex(dstEid, 0);
        }

        mEidRegistry.GetEidIndex(dstEid, index);
    }

    // Round_Robin
    int GetRoundRobinConnEid(umq_route_list_t &route_list, const umq_eid_t *dstEid, umq_route_t *connRoute)
    {
        // 获取起始索引
        uint32_t startIndex = 0;
        GetBondingEidMapIndex(*dstEid, startIndex);
        
        // 确保索引在有效范围内
        startIndex = startIndex % route_list.len;

        // 从起始索引开始轮询查找
        bool found = false;
        for (uint32_t offset = 0; offset < route_list.len; ++offset) {
            uint32_t currentIndex = (startIndex + offset) % route_list.len;
            if (route_list.buf[currentIndex].flag.bs.rtp == 1) {
                *connRoute = route_list.buf[currentIndex];
                found = true;
                startIndex = (currentIndex + 1) % route_list.len;  // 更新下次起始位置
                break;
            }
        }

        // 更新下一个轮询位置
        mEidRegistry.RegisterOrReplaceEidIndex(*dstEid, startIndex);

        if (!found) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to find umq dev\n");
            return -1;
        }

        return 0;
    }

    uint32_t GetTargetChipId(const std::vector<uint32_t>& socketIds, const std::vector<uint32_t>& chipIdList,
        int processSocketId)
    {
        auto it = std::find(socketIds.begin(), socketIds.end(), processSocketId);
        if (it == socketIds.end()) {
            return UINT32_MAX;  // 错误标识
        }
        
        size_t index = std::distance(socketIds.begin(), it);
        if (index >= chipIdList.size()) {
            return UINT32_MAX;  // 索引越界
        }
        
        return chipIdList[index];
    }

    // 通过亲和性选择 Cpu_Affinity
    int GetCpuAffinityConnEid(umq_route_list_t &route_list, const umq_eid_t *dstEid, umq_route_t *connRoute,
        const std::vector<uint32_t>& socketIds, int processSocketId)
    {
        // 检查socket ID一致性。因为同平面上的两端chip_id相等，因此两端的socket id不相等，则切回轮询模式
        if (processSocketId != mPeerSocketId) {
            return GetRoundRobinConnEid(route_list, dstEid, connRoute);
        }

        // 提取 chip_id 列表
        std::set<uint32_t> uniqueChipIds;
        for (uint32_t i = 0; i < route_list.len; ++i) {
            if ((route_list.buf[i].flag.bs.rtp == 1)) {
                uniqueChipIds.insert(route_list.buf[i].chip_id);
            }
        }
        std::vector<uint32_t> chipIdList(uniqueChipIds.begin(), uniqueChipIds.end());

        // 获得对应的chip_id
        uint32_t targetChipId = GetTargetChipId(socketIds, chipIdList, processSocketId);
        if (targetChipId == UINT32_MAX) {
            return GetRoundRobinConnEid(route_list, dstEid, connRoute);
        }
   
        // 查找匹配的eid对
        for (uint32_t i = 0; i < route_list.len; ++i) {
            if ((route_list.buf[i].flag.bs.rtp == 1) && (targetChipId == route_list.buf[i].chip_id)) {
                *connRoute = route_list.buf[i];
                return 0;
            }
        }

        RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to find umq dev\n");
        return -1;
    }

    int GetConnEid(umq_route_list_t &route_list, const umq_eid_t *dstEid, umq_route_t *connRoute, bool useRoundRobin)
    {
        Context *context = Context::GetContext();
        if (!useRoundRobin) {
            int processSocketId = context->GetProcessSocketId();
            std::vector<uint32_t> socketIds = context->GetAllSocketId();
            return GetCpuAffinityConnEid(route_list, dstEid, connRoute, socketIds, processSocketId);
        }
        return GetRoundRobinConnEid(route_list, dstEid, connRoute);
    }
    
    int CheckDevAdd(const umq_eid_t &connEid)
    {
        if (mEidRegistry.IsRegisteredEid(connEid)) {
            return 0;
        }

        umq_trans_info_t trans_info;
        trans_info.trans_mode = UMQ_TRANS_MODE_UB;
        trans_info.dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
        trans_info.dev_info.eid.eid = connEid;
        int ret = umq_dev_add(&trans_info);
        if (ret != 0 && ret != -UMQ_ERR_EEXIST) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Failed to add umq dev, ret %d\n", ret);
            return -1;
        } 

        ret = Context::GetContext()->RegisterAsyncEvent(trans_info);
        if (ret < 0) {
            return ret;
        }
        
        mEidRegistry.RegisterEid(connEid);
        return 0;
    }

    int CheckOtherRoute(umq_route_t &otherConnRoute, umq_eid_t &dstEid, umq_route_t &connRoute)
    {
        if (!mRouteListRegistry.IsRegisteredRouteList(dstEid)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to check other route to connect\n");
            return -1;
        }

        umq_route_list_t routeList = {};
        if (!mRouteListRegistry.GetRouteList(dstEid, routeList)) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to get route list in map\n");
            return -1;
        }

        umq_route_list_t filteredList = {};
        uint32_t filterNum = 0;
        bool found = false;
        for (uint32_t i = 0; i< routeList.len; ++i) {
            if (routeList.buf[i].chip_id != connRoute.chip_id) {
                if (filterNum==0) {
                    otherConnRoute = routeList.buf[i];
                    found = true;
                }
                filteredList.buf[filterNum++] = routeList.buf[i];
            }
        }

        if (!found) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to find other route in map\n");
            return -1;
        }

        filteredList.len = filterNum;
        mRouteListRegistry.RegisterOrReplaceRouteList(dstEid, filteredList);

        if (CheckDevAdd(otherConnRoute.src)!=0) {
            return -1;
        }

        return 0;
    }

    int GetDevRouteList(const umq_eid_t *srcEid, const umq_eid_t *dstEid, umq_route_list_t &filteredList)
    {
        if (mRouteListRegistry.GetRouteList(*dstEid, filteredList)) {
            if (filteredList.len > 0) {
                return 0;
            }
        }
            
        umq_route_t route;
        (void)memcpy_s(&route.src, sizeof(umq_eid_t), srcEid, sizeof(umq_eid_t));
        (void)memcpy_s(&route.dst, sizeof(umq_eid_t), dstEid, sizeof(umq_eid_t));

        umq_route_list_t route_list;
        int ret = umq_get_route_list(&route, UMQ_TRANS_MODE_UB, &route_list);
        if (ret!=0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to get urma topo\n");
            return -1;
        }

        uint32_t filterNum = 0;
        for (uint32_t i = 0;i< route_list.len; ++i) {
            if (route_list.buf[i].flag.bs.rtp == 1) {
                filteredList.buf[filterNum++] = route_list.buf[i];
            }
        }
        filteredList.len = filterNum;

        if (filteredList.len == 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to get urma topo is zero\n");
            return -1;
        }

        mRouteListRegistry.RegisterOrReplaceRouteList(*dstEid, filteredList);
        return 0;
    }

    int DoRoute(const umq_eid_t *srcEid, const umq_eid_t *dstEid, umq_route_t *connRoute, bool useRoundRobin)
    {
        umq_route_list_t filteredList = {};
        if (GetDevRouteList(srcEid, dstEid, filteredList) != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to get dev route list\n");
            return -1;
        }

        if (GetConnEid(filteredList, dstEid, connRoute, useRoundRobin)!=0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to get connect eid\n");
            return -1;
        }

        if (CheckDevAdd(connRoute->src) != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Failed to check dev add\n");
            return -1;
        }

        return 0;
    }
    struct PeerInfo {
        std::string peer_ip;      // 对端IP地址
        umq_eid_t peer_eid;      // 对端EID
        int peer_fd;             // 对端socket fd
        int type_fd;             // 0 server; 1 client
    } m_peer_info;
    //common fields
    uint64_t m_local_umqh = UMQ_INVALID_HANDLE;
    uint64_t m_main_umqh = UMQ_INVALID_HANDLE;
    uint16_t m_tx_window_capacity = 0; // the capacity of TX window size 
    uint16_t m_rx_window_capacity = 0; // the capacity of RX window size
    bool m_bind_remote = false; // indicate whether to enable stats manager when umq is created and bound successfully
    bool m_context_trace_enable = false;
    bool m_need_prefill_rx = false;
    std::atomic<bool> m_closed{false};
    int m_event_fd;
    int mPeerSocketId = -1;
    static EidRegistry mEidRegistry;
    bool m_isblocking = true;
    static RouteListRegistry mRouteListRegistry;
    QbufQueue<umq_buf_t *> *rxQueue = nullptr;
    ShareJfrRxEpollEvent *share_jfr_rx_epoll_event = nullptr;

    // TX fields
    struct alignas(CACHE_LINE_ALIGNMENT) TxDataPlane {
        uint64_t m_protocol_negotiation = 0;
        uint32_t m_protocol_negotiation_recv_size = 0;
        uint32_t m_protocol_negotiation_offset = 0;
        /* m_tx.m_head_buf -> |umq_buf 0| -> |umq_buf 1| -> ... -> |umq_buf n| <- m_tx.m_tailbuf */
        umq_buf_list_t m_head_buf = {0};
        umq_buf_list_t m_tail_buf = {0};
        uint32_t m_unsolicited_bytes = 0; //length of accumulated work request without setting solicited
        uint16_t m_unsolicited_wr_num = 0; // number of accumulated work request without setting solicited
        uint16_t m_unsignaled_wr_num = 0; // number of accumulated work request without setting signaled
        uint16_t m_window_size = 0; // current window size for TX
        uint16_t m_event_num = 0;
        uint16_t m_retrieve_threshold = 0; // when the polled WRs exceeds m_tx.m_retrieve_threshold, then, stop do poll
        uint16_t m_handle_threshold = 0; // when the polled WRs exceeds m_tx.m_handle_threshold, then, stop do poll TX
        /* when the polled WRs exceeds m_tx.m_report_threshold, set signaled/solicited to report and reset counter */
        uint16_t m_report_threshold = 0;
        std::atomic<int> m_epoll_event_num{0};
        int m_expect_epoll_event_num = 0;
        bool m_get_and_ack_event = false;
        std::atomic<bool> m_need_fc_awake{false};
    } m_tx;

    // RX fields
    struct alignas(CACHE_LINE_ALIGNMENT) RxDataPlane {
        uint8_t m_epoll_in_msg = 0;
        uint8_t m_epoll_in_msg_recv_size = 0;
        uint16_t m_window_size = 0; // current window size for RX
        uint16_t m_event_num = 0;
        uint16_t m_refill_threshold = 0;
        std::atomic<int> m_epoll_event_num{0};
        int m_expect_epoll_event_num = 0;
        bool m_get_and_ack_event = false;
        bool m_poll = false;
        bool m_readv_unlimited = false;
        Brpc::BlockCache m_block_cache;
        umq_buf_list_t m_umq_buf_cache_head = {0};
        umq_buf_list_t m_umq_buf_cache_tail = {0};
        size_t m_remaining_size = 0;
    } m_rx;
};

class UmqTxEpollEvent : public ::EpollEvent {
public:
    UmqTxEpollEvent(int fd, struct epoll_event *event, int tx_interrupt_fd) :
        EpollEvent(tx_interrupt_fd, event), m_origin_fd(fd)
    {
        m_event.events = EPOLLOUT | EPOLLET;
    } 
    
    virtual ~UmqTxEpollEvent() {}

    virtual ALWAYS_INLINE int ProcessEpollEvent(struct epoll_event *input_event, struct epoll_event *output_event,
                                                bool use_polling = false) override
    {
        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_origin_fd);
        if (socket_fd_obj != nullptr) {
            socket_fd_obj->NewTxEpollIn();
        }

        return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
    }

private:
    int m_origin_fd = -1;
};

class UmqEventFdEpollEvent : public ::EpollEvent {
public:
    UmqEventFdEpollEvent(int fd, struct epoll_event *event, int tx_interrupt_fd) :
        EpollEvent(tx_interrupt_fd, event), m_origin_fd(fd)
    {
        m_event.events = EPOLLOUT | EPOLLET;
    }

    virtual ~UmqEventFdEpollEvent() {}

    virtual int AddEpollEvent(int epoll_fd)
    {
        struct epoll_event tmp_event;
        tmp_event.events = EPOLLIN;
        tmp_event.data.ptr = (void *)(uintptr_t)this;

        int ret = OsAPiMgr::GetOriginApi()->epoll_ctl(epoll_fd, EPOLL_CTL_ADD, m_fd, &tmp_event);
        if (ret != 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Origin epoll control add event fd failed, epfd: %d, fd: %d\n",
                              epoll_fd, m_fd);
            return ret;
        }

        RPC_ADPT_VLOG_DEBUG("Origin epoll control add event fd successful, epfd: %d, fd: %d\n", epoll_fd, m_fd);
        m_add_epoll_event = true;

        return 0;
    }

    virtual ALWAYS_INLINE int ProcessEpollEvent(struct epoll_event *input_event, struct epoll_event *output_event,
                                                bool use_polling = false) override
    {
        uint64_t cnt;
        if (eventfd_read(m_fd, &cnt) == -1) {
            RPC_ADPT_VLOG_WARN("read event fd %d failed, errno %d\n", m_fd, errno);
        }
        // notify tx epoll out
        input_event->events |= EPOLLOUT;

        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_origin_fd);
        if (socket_fd_obj != nullptr) {
            socket_fd_obj->NewTxEpollInEventFd();
        }

        return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
    }

private:
    int m_origin_fd = -1;
};

class UmqRxEpollEvent : public ::EpollEvent {
public:
    UmqRxEpollEvent(int fd, struct epoll_event *event, int rx_interrupt_fd) :
        EpollEvent(rx_interrupt_fd, event), m_origin_fd(fd)
    {
        m_event.events = EPOLLIN | EPOLLET;
    } 
    
    virtual ~UmqRxEpollEvent() {}

    int GetAndAckEvent()
    {
        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_origin_fd);
        if (socket_fd_obj == nullptr) {
            return -1;
        }

        umq_interrupt_option_t option = {UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_RX};
        int events = umq_get_cq_event(socket_fd_obj->GetLocalUmqHandle(), &option);
        if (events == 0) {
            return 0;
        } else if (events < 0) {
            return -1;
        }

        if ((m_event_num += events) >= GET_PER_ACK) {
            umq_ack_interrupt(socket_fd_obj->GetLocalUmqHandle(), m_event_num, &option);
            m_event_num = 0;
        }

        return 0;
    }

    virtual ALWAYS_INLINE int ProcessEpollEvent(struct epoll_event *input_event, struct epoll_event *output_event,
                                                bool use_polling = false) override
    {
        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_origin_fd);
        if (socket_fd_obj != nullptr) {
            socket_fd_obj->NewRxEpollIn();
        }

        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (socket_fd_obj == nullptr || !enable_share_jfr) {
            return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
        }

        if (GetAndAckEvent() < 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Get and ack sub umq failed, socket fd:%d \n", m_origin_fd);
            return -1;
        }

        umq_buf_t *buf[POLL_BATCH_MAX];
        int poll_num = umq_poll(socket_fd_obj->GetLocalUmqHandle(), UMQ_IO_RX, buf, POLL_BATCH_MAX);
        if (poll_num <= 0) {
            return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
        }

        for (int i = 0; i < poll_num; ++i) {
            if (buf[i]->status != 0) {
                if (buf[i]->status != UMQ_FAKE_BUF_FC_UPDATE) {
                    socket_fd_obj->HandleErrorRxCqe(buf[i]);
                }
                umq_buf_free(buf[i]);
            }
        }

        return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
    }

private:
    int m_origin_fd = -1;
    uint16_t m_event_num = 0;
};

class EpollEvent : public ::EpollEvent {
public:
    void CleanUp()
    {
        if (tx_epoll_event != nullptr) {
            delete tx_epoll_event;
            tx_epoll_event = nullptr;
        }

        if (event_fd_epoll_event != nullptr) {
            delete event_fd_epoll_event;
            event_fd_epoll_event = nullptr;
        }

        if (rx_epoll_event != nullptr) {
            delete rx_epoll_event;
            rx_epoll_event = nullptr;
        }
    }
    
    EpollEvent(int fd, struct epoll_event *event): ::EpollEvent(fd, event)
    {
        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(fd);
        if (socket_fd_obj == nullptr || !socket_fd_obj->GetBindRemote() || socket_fd_obj->UseTcp()) {
            return;
        }

        umq_interrupt_option_t tx_option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_TX };
        int tx_interrupt_fd = umq_interrupt_fd_get(socket_fd_obj->GetLocalUmqHandle(), &tx_option);
        if (tx_interrupt_fd < 0) {
            errno = EINVAL;
            throw std::runtime_error("Failed to get TX interrupt fd for umq\n");
        }

        umq_interrupt_option_t rx_option = { UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_RX };
        int rx_interrupt_fd = umq_interrupt_fd_get(socket_fd_obj->GetLocalUmqHandle(), &rx_option);
        if (rx_interrupt_fd < 0) {
            errno = EINVAL;
            throw std::runtime_error("Failed to get RX interrupt fd for umq\n");
        }

        try {
            tx_epoll_event = new UmqTxEpollEvent(fd, event, tx_interrupt_fd);
            event_fd_epoll_event = new UmqEventFdEpollEvent(fd, event, socket_fd_obj->GetEventFd());
            rx_epoll_event = new UmqRxEpollEvent(fd, event, rx_interrupt_fd);
        } catch (std::exception& e) {
            CleanUp();
            throw std::runtime_error(e.what());
        }
    }

    virtual ~EpollEvent()
    {
        CleanUp();
    }

    virtual int AddEpollEvent(int epoll_fd, bool use_polling = false) override
    {
        if (::EpollEvent::AddEpollEvent(epoll_fd, use_polling) < 0) {
            return -1;
        }

        // try best to add umq tx/rx epoll event
        if ((m_event.events & EPOLLOUT) && tx_epoll_event != nullptr) {
            if (tx_epoll_event->AddEpollEvent(epoll_fd, use_polling) < 0) {
                RPC_ADPT_VLOG_WARN("Failed to add TX interrupt fd(%d) for umq, fd: %d\n",
                    tx_epoll_event->GetFd(), m_fd);
            } else {
                RPC_ADPT_VLOG_DEBUG("Add TX interrupt fd(%d) for umq successful, fd: %d\n",
                    tx_epoll_event->GetFd(), m_fd);
            }

            SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_fd);
            if (socket_fd_obj != nullptr && socket_fd_obj->GetBindRemote() && !socket_fd_obj->TxUseTcp()) {
                if (socket_fd_obj->RearmTxInterrupt() < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to rearm TX interrupt fd(%d) for umq, fd: %d\n",
                        tx_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Rearm TX interrupt fd(%d) for umq successful, fd: %d\n",
                        tx_epoll_event->GetFd(), m_fd);
                }
            }

            if (event_fd_epoll_event != nullptr) {
                if (event_fd_epoll_event->AddEpollEvent(epoll_fd) < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to add TX event fd(%d) for umq, fd: %d\n",
                                       event_fd_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Add TX event fd(%d) for umq successful, fd: %d\n",
                                        event_fd_epoll_event->GetFd(), m_fd);
                }
            }
        }

        if ((m_event.events & EPOLLIN) && rx_epoll_event != nullptr) {
            if (rx_epoll_event->AddEpollEvent(epoll_fd, use_polling) < 0) {
                RPC_ADPT_VLOG_WARN("Failed to add RX interrupt fd(%d) for umq, fd: %d\n",
                    rx_epoll_event->GetFd(), m_fd);
            } else {
                RPC_ADPT_VLOG_DEBUG("Add RX interrupt fd(%d) for umq successful, fd: %d\n",
                    rx_epoll_event->GetFd(), m_fd);
            }

            SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_fd);
            if (socket_fd_obj != nullptr && socket_fd_obj->GetBindRemote() && !socket_fd_obj->RxUseTcp()) {
                if (socket_fd_obj->RearmRxInterrupt() < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to rearm RX interrupt fd(%d) for umq, fd: %d\n",
                        rx_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Rearm RX interrupt fd(%d) for umq successful, fd: %d\n",
                        rx_epoll_event->GetFd(), m_fd);
                }
            }
        }

        return 0;
    }

    virtual int ModEpollEvent(int epoll_fd, struct epoll_event *event, bool use_polling = false) override
    {
        if (::EpollEvent::ModEpollEvent(epoll_fd, event, use_polling) < 0) {
            return -1;
        }

        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_fd);
        if (socket_fd_obj == nullptr || !socket_fd_obj->GetBindRemote() || socket_fd_obj->UseTcp()) {
            return 0;
        }

        // try best to modify umq tx/rx epoll event
        if (tx_epoll_event != nullptr) {
            if (!tx_epoll_event->IsAddEpollEvent() && (event->events & EPOLLOUT)) {
                if (tx_epoll_event->AddEpollEvent(epoll_fd, use_polling) < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to modify(add) TX interrupt fd(%d) for umq, fd: %d\n",
                        tx_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Modify(add) TX interrupt fd(%d) for umq successful, fd: %d\n",
                        tx_epoll_event->GetFd(), m_fd);
                }
            } else if (tx_epoll_event->IsAddEpollEvent() && !(event->events & EPOLLOUT)) {
                if (tx_epoll_event->DelEpollEvent(epoll_fd, use_polling) < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to modify(delete) TX interrupt fd(%d) for umq, fd: %d\n",
                        tx_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Modify(delete) TX interrupt fd(%d) for umq successful, fd: %d\n",
                        tx_epoll_event->GetFd(), m_fd);
                }
            }

            if (!event_fd_epoll_event->IsAddEpollEvent() && (event->events & EPOLLOUT)) {
                if (event_fd_epoll_event->AddEpollEvent(epoll_fd) < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to modify(add) TX event fd(%d) for umq, fd: %d\n",
                                       event_fd_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Modify(add) TX event fd(%d) for umq successful, fd: %d\n",
                                        event_fd_epoll_event->GetFd(), m_fd);
                }
            }
        }

        if (rx_epoll_event != nullptr) {
            if (!rx_epoll_event->IsAddEpollEvent() && (event->events & EPOLLIN)) {
                if (rx_epoll_event->AddEpollEvent(epoll_fd, use_polling) < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to modify(add) RX interrupt fd(%d) for umq, fd: %d\n",
                        rx_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Modify(add) RX interrupt fd(%d) for umq successful, fd: %d\n",
                        rx_epoll_event->GetFd(), m_fd);
                }
            } else if (rx_epoll_event->IsAddEpollEvent() && !(event->events & EPOLLIN)) {
                if (rx_epoll_event->DelEpollEvent(epoll_fd, use_polling) < 0) {
                    RPC_ADPT_VLOG_WARN("Failed to modify(delete) RX interrupt fd(%d) for umq, fd: %d\n",
                        rx_epoll_event->GetFd(), m_fd);
                } else {
                    RPC_ADPT_VLOG_DEBUG("Modify(delete) RX interrupt fd(%d) for umq successful, fd: %d\n",
                        rx_epoll_event->GetFd(), m_fd);
                }
            }
        }

        return 0;
    }

    virtual int DelEpollEvent(int epoll_fd, bool use_polling = false) override
    {
        if (::EpollEvent::DelEpollEvent(epoll_fd, use_polling) < 0) {
            return -1;
        }

        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_fd);
        if (socket_fd_obj == nullptr || !socket_fd_obj->GetBindRemote() || socket_fd_obj->UseTcp()) {
            return 0;
        }

        // try best to delete umq tx/rx epoll event
        if (tx_epoll_event != nullptr &&
            tx_epoll_event->IsAddEpollEvent() && tx_epoll_event->DelEpollEvent(epoll_fd, use_polling) < 0) {
            RPC_ADPT_VLOG_WARN("Failed to delete TX interrupt fd(%d) for umq, fd: %d\n",
                tx_epoll_event->GetFd(), m_fd);
        }

        if (event_fd_epoll_event != nullptr &&
            event_fd_epoll_event->IsAddEpollEvent() && event_fd_epoll_event->DelEpollEvent(epoll_fd, use_polling) < 0) {
            RPC_ADPT_VLOG_WARN("Failed to delete TX event fd(%d) for umq, fd: %d\n",
                               tx_epoll_event->GetFd(), m_fd);
        }

        if (rx_epoll_event != nullptr &&
            rx_epoll_event->IsAddEpollEvent() && rx_epoll_event->DelEpollEvent(epoll_fd, use_polling) < 0) {
            RPC_ADPT_VLOG_WARN("Failed to delete RX interrupt fd(%d) for umq, fd: %d\n",
                rx_epoll_event->GetFd(), m_fd);
        }

        return 0;
    }

    virtual int ProcessEpollEvent(struct epoll_event *input_event, struct epoll_event *output_event,
                                  bool use_polling = false) override
    {
        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(m_fd);
        if (input_event->events & EPOLLOUT) {
            if (socket_fd_obj != nullptr && !socket_fd_obj->UseTcp()) {
                if (!socket_fd_obj->GetBindRemote() && socket_fd_obj->DoConnect() != 0) {
                    RPC_ADPT_VLOG_WARN("Fatal error occurred, fd: %d fallback to TCP/IP", m_fd);
                    Fd<::SocketFd>::OverrideFdObj(m_fd, nullptr);
                    /* Clear messages that already exist on the TCP link to prevent
                     * dirty messages from affecting user data transmission. */
                    (void)SocketFd::FlushSocketMsg(m_fd); 
                }
            } else {
                // EPOLLOUT events from original socket fd will be ignored
                return 0;
            }
        }

        if ((input_event->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) &&
            socket_fd_obj != nullptr && !socket_fd_obj->RxUseTcp() && socket_fd_obj->GetBindRemote()) {
            socket_fd_obj->NewOriginEpollError();
            return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
        }

        if ((input_event->events & EPOLLIN) &&
            socket_fd_obj != nullptr && !socket_fd_obj->RxUseTcp() && socket_fd_obj->GetBindRemote()) {
            socket_fd_obj->NewOriginEpollIn(use_polling);
            return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
        }

        return ::EpollEvent::ProcessEpollEvent(input_event, output_event, use_polling);
    }

    UmqTxEpollEvent *GetUmqTxEpollEvent()
    {
        return tx_epoll_event;
    }

    UmqRxEpollEvent *GetUmqRxEpollEvent()
    {
        return rx_epoll_event;
    }

private:
    UmqTxEpollEvent *tx_epoll_event = nullptr;
    UmqEventFdEpollEvent *event_fd_epoll_event = nullptr;
    UmqRxEpollEvent *rx_epoll_event = nullptr;
};

class EpollFd : public ::EpollFd {
public:
    EpollFd(int epoll_fd) : ::EpollFd(epoll_fd) {}
    
    virtual ~EpollFd()
    {
        for (std::pair<int, ShareJfrRxEpollEvent *> kv : m_share_jfr_epoll_event_map) {
            delete kv.second;
        }
    }

    virtual ALWAYS_INLINE int EpollCtlAdd(int fd, struct epoll_event *event, bool use_polling = false) override
    {
        if (event == nullptr) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Invalid argument, epoll event is NULL\n");
            errno = EINVAL;
            return -1;
        }

        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(fd);
        if (socket_fd_obj == nullptr) {
            return ::EpollFd::EpollCtlAdd(fd, event, use_polling);
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_epoll_event_map.count(fd) > 0) {
            RPC_ADPT_VLOG_WARN("Origin epoll control add duplicated, epfd: %d, fd: %d\n", m_fd, fd);
            EpollEvent *epoll_event = static_cast<Brpc::EpollEvent*>(m_epoll_event_map[fd]);
            if (epoll_event->DelEpollEvent(m_fd) != 0)
            {
                RPC_ADPT_VLOG_WARN("Deleting duplicated fd: %d from epfd: %d is unsuccessful\n", fd, m_fd);
            }
            delete epoll_event;
            m_epoll_event_map.erase(fd);
        }

        EpollEvent *epoll_event = nullptr;
        try {
            epoll_event = new EpollEvent(fd, event);
            CreateAndAddShareJfrEpollEvent(fd, event);
        } catch (std::exception& e) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "%s\n", e.what());
            return -1;
        }

        if (epoll_event->AddEpollEvent(m_fd, use_polling) < 0) {
            delete epoll_event;
            return -1;
        }

        m_epoll_event_map[fd] = epoll_event;

        return 0;
    }

    virtual ALWAYS_INLINE int EpollCtlMod(int fd, struct epoll_event *event, bool use_polling = false) override
    {
        if (::EpollFd::EpollCtlMod(fd, event, use_polling) < 0) {
            return -1;
        }

        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (!enable_share_jfr) {
            return 0;
        }

        int share_jfr_fd = GetShareJfrFd(fd);
        if (share_jfr_fd == 0) {
            return 0;
        }

        if (share_jfr_fd < 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Get share jfr fd failed, epfd: %d, socket fd: %d\n", m_fd, fd);
            return -1;
        }

        if (m_share_jfr_epoll_event_map.count(share_jfr_fd) == 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket,
                              "Share jfr rx epoll event not exist, epfd: %d, socket fd: %d, share jfr fd:%d \n", m_fd,
                              fd, share_jfr_fd);
            return -1;
        }

        auto share_jfr_rx_epoll_event = m_share_jfr_epoll_event_map[share_jfr_fd];
        if (share_jfr_rx_epoll_event != nullptr &&
            share_jfr_rx_epoll_event->ModEpollEvent(m_fd, event, use_polling) != 0) {
            return -1;
        }

        return 0;
    }

private:
    std::unordered_map<int, ShareJfrRxEpollEvent *> m_share_jfr_epoll_event_map;

    int GetShareJfrFd(int fd)
    {
        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(fd);
        if (socket_fd_obj == nullptr) {
            RPC_ADPT_VLOG_WARN("Get socket fd object failed, socket fd: %d\n", fd);
            return 0;
        }

        auto main_umq = socket_fd_obj->GetMainUmqHandle();
        if (main_umq == UMQ_INVALID_HANDLE) {
            RPC_ADPT_VLOG_ERR(ubsocket::UBSocket, "Get main umq handle failed, socket fd: %d\n", fd);
            return -1;
        }

        umq_interrupt_option_t rx_option = {UMQ_INTERRUPT_FLAG_IO_DIRECTION, UMQ_IO_RX};
        int share_jfr_fd = umq_interrupt_fd_get(main_umq, &rx_option);
        if (share_jfr_fd < 0) {
            RPC_ADPT_VLOG_ERR(ubsocket::UMQ_API, "Get main umq interrupt fd failed, socket fd: %d\n", fd);
            return -1;
        }

        return share_jfr_fd;
    }

    void CreateAndAddShareJfrEpollEvent(int fd, struct epoll_event *event)
    {
        Brpc::Context *context = Brpc::Context::GetContext();
        bool enable_share_jfr = context == nullptr ? true : context->EnableShareJfr();
        if (!enable_share_jfr) {
            return;
        }

        SocketFd *socket_fd_obj = (SocketFd *)Fd<::SocketFd>::GetFdObj(fd);
        if (socket_fd_obj == nullptr || !socket_fd_obj->GetBindRemote() || socket_fd_obj->UseTcp()) {
            return;
        }

        int share_jfr_fd = GetShareJfrFd(fd);
        if (share_jfr_fd < 0) {
            errno = EINVAL;
            throw std::runtime_error("Failed to get RX interrupt fd for main umq\n");
        }

        if (m_share_jfr_epoll_event_map.count(share_jfr_fd) > 0) {
            RPC_ADPT_VLOG_DEBUG("share jfr fd:%d add duplicated, epoll fd:%d \n", share_jfr_fd, m_fd);
            return;
        }

        if (!(event->events & EPOLLIN)) {
            return;
        }

        ShareJfrRxEpollEvent *share_jfr_rx_epoll_event = new ShareJfrRxEpollEvent(fd, event, share_jfr_fd, m_fd,
                                                                                  socket_fd_obj->GetMainUmqHandle());

        if (share_jfr_rx_epoll_event == nullptr) {
            return;
        }
        socket_fd_obj->SetShareJfrRxEpollEvent(share_jfr_rx_epoll_event);

        if (share_jfr_rx_epoll_event->AddEpollEvent(m_fd) < 0) {
            RPC_ADPT_VLOG_WARN("Failed to add share jfr RX interrupt fd(%d) for main umq, fd: %d\n",
                               share_jfr_rx_epoll_event->GetFd(), fd);
        } else {
            RPC_ADPT_VLOG_DEBUG("Add share jfr RX interrupt fd(%d) for main umq successful, fd: %d\n",
                                share_jfr_rx_epoll_event->GetFd(), fd);
        }

        if (socket_fd_obj->GetBindRemote() && !socket_fd_obj->RxUseTcp()) {
            if (socket_fd_obj->RearmShareJfrRxInterrupt() < 0) {
                RPC_ADPT_VLOG_WARN("Failed to rearm share jfr RX interrupt fd(%d) for main umq, fd: %d\n",
                                   share_jfr_rx_epoll_event->GetFd(), fd);
            } else {
                RPC_ADPT_VLOG_DEBUG("Rearm share jfr RX interrupt fd(%d) for main umq successful, fd: %d\n",
                                    share_jfr_rx_epoll_event->GetFd(), fd);
            }
        }

        m_share_jfr_epoll_event_map[share_jfr_fd] = share_jfr_rx_epoll_event;
    }
};
}

#endif
