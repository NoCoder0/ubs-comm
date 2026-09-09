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
#include <fcntl.h>
#include <sys/poll.h>

#include "net_monotonic.h"
#include "net_oob_ssl.h"
#include "net_rdma_sync_endpoint.h"
#include "net_rdma_async_endpoint.h"
#include "rdma_mr_dm_buf.h"
#include "rdma_mr_fixed_buf.h"
#include "net_rdma_driver_oob.h"
#include "net_oob_secure.h"

namespace ock {
namespace hcom {
constexpr uint64_t MAX_OP_TIME_US = NN_NO500000; // 500 ms

NResult NetDriverRDMAWithOob::DoInitialize()
{
    if (mWorkers.empty()) {
        NN_LOG_ERROR("Failed to do initialize in Driver " << mName << ", as mWorkers is empty");
    }

    for (auto worker : mWorkers) {
        worker->RegisterPostedHandler(std::bind(&NetDriverRDMAWithOob::SendFinished, this, std::placeholders::_1));
        worker->RegisterNewRequestHandler(std::bind(&NetDriverRDMAWithOob::NewRequest, this, std::placeholders::_1));
        worker->RegisterOneSideDoneHandler(std::bind(&NetDriverRDMAWithOob::OneSideDone, this, std::placeholders::_1));
        if (mIdleHandler != nullptr) {
            worker->RegisterIdleHandler(mIdleHandler);
        }
    }

    NResult result = NN_OK;
    // create oob
    if (mStartOobSvr) {
        if ((result = CreateListeners(mOptions.enableMultiRail)) != NN_OK) {
            NN_LOG_ERROR("RDMA failed to create listeners");
            return result;
        }
    }

    mEndPoints.reserve(NN_NO1024);

    return NN_OK;
}

void NetDriverRDMAWithOob::DoUnInitialize()
{
    if (mStarted) {
        NN_LOG_WARN("Invalid to UnInitialize driver " << mName << " which is not stopped");
        return;
    }

    if (!mOobServers.empty()) {
        mOobServers.clear();
    }
}

NResult NetDriverRDMAWithOob::DoStart()
{
    if (mStartOobSvr) {
        if (mNewEndPointHandler == nullptr) {
            NN_LOG_ERROR("Failed to do start in Driver " << mName << ", as newEndPointerHandler is null");
            return NN_INVALID_PARAM;
        }

        if (!mOptions.enableMultiRail) {
            /* set cb for listeners */
            for (auto &oobServer : mOobServers) {
                oobServer->SetNewConnCB(std::bind(&NetDriverRDMAWithOob::NewConnectionCB, this, std::placeholders::_1));
                oobServer->SetNewConnCbThreadNum(mOptions.oobConnHandleThreadCount);
                oobServer->SetNewConnCbQueueCap(mOptions.oobConnHandleQueueCap);
            }

            NResult result = StartListeners();
            if (result != NN_OK) {
                NN_LOG_ERROR("RDMA failed to start listeners");
                return result;
            }
        }
    }

    mHeartBeat = new (std::nothrow) NetHeartbeat(this, mOptions.heartBeatIdleTime, mOptions.heartBeatProbeInterval);
    if (mHeartBeat == nullptr) {
        NN_LOG_ERROR("Failed to do start in Driver " << mName << ", as new heartbeat failed");
        StopListeners();
        return NN_ERROR;
    }

    NResult result = mHeartBeat->Start();
    if (result != NN_OK) {
        delete mHeartBeat;
        mHeartBeat = nullptr;
        StopListeners();
        return result;
    }

    mNeedStopEvent = false;
    std::thread tmpEventThread(&NetDriverRDMAWithOob::RunInRdmaEventThread, this);
    mRdmaEventThread = std::move(tmpEventThread);

    while (!mEventStarted.load()) {
        usleep(NN_NO10);
    }

    return NN_OK;
}

void NetDriverRDMAWithOob::DoStop()
{
    if (mHeartBeat != nullptr) {
        mHeartBeat->Stop();
        delete mHeartBeat;
        mHeartBeat = nullptr;
    }

    mNeedStopEvent = true;
    if (mRdmaEventThread.native_handle()) {
        mRdmaEventThread.join();
    }

    StopListeners();
}

void NetDriverRDMAWithOob::DestroyEpByPortNum(int portNum)
{
    static thread_local std::vector<UBSHcomNetEndpointPtr> endPointsCopy;
    endPointsCopy.reserve(NN_NO8192);
    endPointsCopy.clear();
    {
        std::lock_guard<std::mutex> locker(mEndPointsMutex);
        for (auto iter = mEndPoints.begin(); iter != mEndPoints.end();) {
            auto asyncEp = iter->second.ToChild<NetAsyncEndpoint>();
            if (asyncEp != nullptr && asyncEp->GetRdmaEp()->Qp()->PortNum() == portNum) {
                endPointsCopy.emplace_back(iter->second);
                iter = mEndPoints.erase(iter);
            } else {
                ++iter;
            }
        }
    }

    for (auto &endPoint : endPointsCopy) {
        NN_LOG_WARN("Detect port down event, handle Ep id " << endPoint->Id() << " of driver " << mName);
        ProcessEpError(reinterpret_cast<uintptr_t>(endPoint.Get()));
    }

    NN_LOG_INFO("Destroyed all endpoints count " << endPointsCopy.size() << " by port down of driver " << mName);
    endPointsCopy.clear();
}

void NetDriverRDMAWithOob::HandlePortDown(int portNum)
{
    for (auto worker : mWorkers) {
        if (worker->PortNum() == portNum) {
            worker->Stop();
        }
    }

    DestroyEpByPortNum(portNum);
}

void NetDriverRDMAWithOob::HandlePortActive(int portNum)
{
    for (auto worker : mWorkers) {
        if (worker->PortNum() == portNum) {
            worker->Start();
        }
    }
}

void NetDriverRDMAWithOob::DestroyEpInWorker(RDMAWorker *worker)
{
    static thread_local std::vector<UBSHcomNetEndpointPtr> endPointsCopy;
    endPointsCopy.reserve(NN_NO8192);
    endPointsCopy.clear();
    {
        std::lock_guard<std::mutex> locker(mEndPointsMutex);
        for (auto iter = mEndPoints.begin(); iter != mEndPoints.end();) {
            auto asyncEp = iter->second.ToChild<NetAsyncEndpoint>();
            if (asyncEp != nullptr && asyncEp->mEp->mWorker == worker) {
                endPointsCopy.emplace_back(iter->second);
                iter = mEndPoints.erase(iter);
            } else {
                ++iter;
            }
        }
    }

    for (auto &endPoint : endPointsCopy) {
        NN_LOG_WARN("Detect CQ incorrect event, handle Ep id " << endPoint->Id() << " of driver " << mName);
        ProcessEpError(reinterpret_cast<uintptr_t>(endPoint.Get()));
    }

    NN_LOG_INFO("Destroyed all endpoints count " << endPointsCopy.size() << " in RDMA worker " <<
        worker->DetailName() << " of driver " << mName);
    endPointsCopy.clear();
}

void NetDriverRDMAWithOob::HandleCqEvent(struct ibv_async_event *event)
{
    /* when sync mode connecting, there is no worker */
    if (event->element.cq->cq_context == nullptr) {
        NN_LOG_ERROR("CQ error for CQ of driver " << mName);
    } else {
        auto worker = reinterpret_cast<RDMAWorker *>(event->element.cq->cq_context);
        NN_LOG_ERROR("CQ error for CQ with handle " << event->element.cq << " in RDMA worker " <<
            worker->DetailName() << " of driver " << mName);
        if (worker->Stop() != NN_OK) {
            NN_LOG_ERROR("Handle Cq event stop error in RDMA worker " << worker->DetailName() << " of driver " <<
                mName);
            return;
        }

        DestroyEpInWorker(worker);
        if (worker->ReInitializeCQ() != NN_OK) {
            NN_LOG_ERROR("Handle Cq event ReInitializeCQ error in RDMA worker " << worker->DetailName() <<
                " of driver " << mName);
            return;
        }
        if (worker->Start() != NN_OK) {
            NN_LOG_ERROR("Handle Cq event start error in RDMA worker " << worker->DetailName() << " of driver " <<
                mName);
            return;
        }
    }
}

static inline std::string QpDetailInfo(void *qpContext)
{
    auto qp = reinterpret_cast<RDMAQp *>(qpContext);
    std::ostringstream oss;
    oss << "[Qp name:" << qp->Name() << ", id:" << qp->Id() << "]";
    return oss.str();
}

void NetDriverRDMAWithOob::HandleAsyncEvent(struct ibv_async_event *event)
{
    switch (event->event_type) {
        /* QP events */
        case IBV_EVENT_QP_FATAL:
            NN_LOG_ERROR("QP fatal event for " << QpDetailInfo(event->element.qp->qp_context) << " of driver " <<
                mName);
            break;
        case IBV_EVENT_QP_REQ_ERR:
            NN_LOG_ERROR("QP Requester error for " << QpDetailInfo(event->element.qp->qp_context) << " of driver " <<
                mName);
            break;
        case IBV_EVENT_QP_ACCESS_ERR:
            NN_LOG_ERROR("QP access error event for " << QpDetailInfo(event->element.qp->qp_context) << " of driver " <<
                mName);
            break;
        case IBV_EVENT_COMM_EST:
            NN_LOG_ERROR("QP communication established event for " << QpDetailInfo(event->element.qp->qp_context) <<
                " of driver " << mName);
            break;
        case IBV_EVENT_SQ_DRAINED:
            NN_LOG_ERROR("QP Send Queue drained event for " << QpDetailInfo(event->element.qp->qp_context) <<
                " of driver " << mName);
            break;
        case IBV_EVENT_PATH_MIG:
            NN_LOG_ERROR("QP Path migration loaded event for " << QpDetailInfo(event->element.qp->qp_context) <<
                " of driver " << mName);
            break;
        case IBV_EVENT_PATH_MIG_ERR:
            NN_LOG_ERROR("QP Path migration error event for " << QpDetailInfo(event->element.qp->qp_context) <<
                " of driver " << mName);
            break;
        case IBV_EVENT_QP_LAST_WQE_REACHED:
            NN_LOG_ERROR("QP last WQE reached event for " << QpDetailInfo(event->element.qp->qp_context) <<
                " of driver " << mName);
            break;

        /* CQ events */
        case IBV_EVENT_CQ_ERR:
            HandleCqEvent(event);
            break;

        /* SRQ events */
        case IBV_EVENT_SRQ_ERR:
            NN_LOG_ERROR("SRQ error for SRQ of driver " << mName);
            break;
        case IBV_EVENT_SRQ_LIMIT_REACHED:
            NN_LOG_ERROR("SRQ limit reached event for SRQ of driver " << mName);
            break;

        /* Port events */
        case IBV_EVENT_PORT_ACTIVE:
            NN_LOG_ERROR("Port active event for port number " << event->element.port_num << " of driver " << mName);
            HandlePortActive(event->element.port_num);
            break;
        case IBV_EVENT_PORT_ERR:
            NN_LOG_ERROR("Port error event for port number " << event->element.port_num << " of driver " << mName);
            /* case1: The physical link is disconnected */
            /* case2: ifconfig down
                      1) QP can work normal before the event happened in CX5
                      2) QP report err in 182x */
            HandlePortDown(event->element.port_num);
            break;
        case IBV_EVENT_LID_CHANGE:
            NN_LOG_ERROR("LID change event for port number " << event->element.port_num << " of driver " << mName);
            break;
        case IBV_EVENT_PKEY_CHANGE:
            NN_LOG_ERROR("P_Key table change event for port number " << event->element.port_num << " of driver " <<
                mName);
            break;
        case IBV_EVENT_GID_CHANGE:
            NN_LOG_ERROR("GID table change event for port number " << event->element.port_num << " of driver " <<
                mName);
            mContext->UpdateGid(mMatchIp);
            break;
        case IBV_EVENT_SM_CHANGE:
            NN_LOG_ERROR("SM change event for port number " << event->element.port_num << " of driver " << mName);
            break;
        case IBV_EVENT_CLIENT_REREGISTER:
            NN_LOG_ERROR("Client reregister event for port number " << event->element.port_num << " of driver " <<
                mName);
            break;

        /* RDMA device events */
        case IBV_EVENT_DEVICE_FATAL:
            NN_LOG_ERROR("Fatal error event for device of driver " << mName);
            break;

        default:
            NN_LOG_ERROR("Unknown event " << event->event_type << " of driver " << mName);
    }
}

void NetDriverRDMAWithOob::RunInRdmaEventThread()
{
    mEventStarted.store(true);
    NN_LOG_INFO("Rdma event monitor thread for driver " << mName << " started");

    /* set thread name */
    pthread_setname_np(pthread_self(), ("RDMAEvent" + std::to_string(mIndex)).c_str());

    /* set nonblock */
    int flags = fcntl(mContext->Context()->async_fd, F_GETFL);
    int ret = fcntl(mContext->Context()->async_fd, F_SETFL, (static_cast<uint32_t>(flags)) | O_NONBLOCK);
    if (ret < 0) {
        char buf[NET_STR_ERROR_BUF_SIZE] = {0};
        NN_LOG_ERROR("Failed to change event fd of RDMA context for driver " << mName << ", error " <<
            NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
        return;
    }

    struct ibv_async_event event {};
    while (!mNeedStopEvent) {
        struct pollfd fd {};
        int timeoutMs = NN_NO100;
        fd.fd = mContext->Context()->async_fd;
        fd.events = POLLIN;
        fd.revents = 0;
        do {
            ret = poll(&fd, 1, timeoutMs);
            if (ret > 0) {
                break;
            } else if (ret < 0 && errno != EINTR) {
                char buf[NET_STR_ERROR_BUF_SIZE] = {0};
                NN_LOG_ERROR("Failed to poll event fd of RDMA context for driver " << mName << ", error " <<
                    NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
                break;
            }
            // rc == 0
        } while (!mNeedStopEvent);

        ret = HcomIbv::GetAsyncEvent(mContext->Context(), &event);
        if (ret < 0) {
            /* nothing happen when nonblock mode */
            continue;
        }

        /* ack the event, otherwise destroy cq will block */
        HcomIbv::AckAsyncEvent(&event);

        /* when fatal event happened, need stop worker first, then call ep broken to prevent race condition
           with poll cq thread */
        HandleAsyncEvent(&event);
    }
    NN_LOG_INFO("Rdma event monitor thread for driver " << mName << " exiting");
    mEventStarted.store(false);
}

NResult NetDriverRDMAWithOob::MultiRailNewConnection(OOBTCPConnection &conn)
{
    return NewConnectionCB(conn);
}

int NetDriverRDMAWithOob::NewConnectionCB(OOBTCPConnection &conn)
{
    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBServer(mSecInfoProvider, mSecInfoValidator, conn, mName,
        mOptions.secType)) != NN_OK) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    uint32_t ip = NetFunc::GetIpByFd(conn.GetFd());
    if (NN_UNLIKELY(OOBSecureProcess::SecProcessCompareEpNum(ip, conn.ListenPort(), conn.GetIpAndPort(),
        mOobServers)) != NN_OK) {
        NN_LOG_ERROR("Rdma connection num exceeds maximum");
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    int result = 0;

    // receive server worker grpno
    auto startRecvWG = NetMonotonic::TimeUs();
    ConnectHeader header {};
    void *grpnobuf = &header;
    if ((result = conn.Receive(grpnobuf, sizeof(ConnectHeader))) != 0) {
        NN_LOG_ERROR("Failed to receive specified server worker grpno from client " << mName << ", result " << result);
        return NN_ERROR;
    }

    ConnRespWithUId respWithUId{ OK, 0 };
    result = OOBSecureProcess::SecCheckConnectionHeader(header, mOptions, mEnableTls, Protocol(), mMajorVersion,
        mMinorVersion, respWithUId);
    if (result != NN_OK) {
        conn.Send(&respWithUId, sizeof(ConnRespWithUId));
        return NN_ERROR;
    }

    auto endRecvWG = NetMonotonic::TimeUs();
    auto recvWGtime = endRecvWG - startRecvWG;
    if (NN_UNLIKELY(recvWGtime > MAX_OP_TIME_US)) {
        NN_LOG_WARN("Receive group num time is too long :" << recvWGtime << " us.");
    }

    /* choose worker */
    NetWorkerLBPtr lb = nullptr;
    if (mOptions.enableMultiRail) {
        lb = mServerLb;
    } else {
        lb = conn.LoadBalancer();
    }

    NN_ASSERT_LOG_RETURN(lb.Get() != nullptr, NN_ERROR)
    uint16_t workerIndex = 0;
    if (NN_UNLIKELY(!lb->ChooseWorker(header.groupIndex, conn.GetIpAndPort(), workerIndex)) ||
        workerIndex >= mWorkers.size()) {
        NN_LOG_ERROR("Failed to find worker fit grpno " << header.groupIndex << " in " << mName << " , result " <<
            result);
        ConnRespWithUId respWithUId { WORKER_GRPNO_MISMATCH, 0 };
        conn.Send(&respWithUId, sizeof(ConnRespWithUId));
        return NN_ERROR;
    }

    NN_LOG_TRACE_INFO("Worker " << workerIndex << " is chosen in driver " << mName);
    auto worker = mWorkers[workerIndex];
    NN_ASSERT_LOG_RETURN(worker != nullptr, NN_ERROR);

    if (!worker->IsWorkStarted()) {
        NN_LOG_ERROR("Failed to connect worker group no " << header.groupIndex << " in " << mName);
        ConnRespWithUId respWithUId { WORKER_NOT_STARTED, 0 };
        conn.Send(&respWithUId, sizeof(ConnRespWithUId));
        return NN_ERROR;
    }

    // create qp
    auto startCreateQp = NetMonotonic::TimeUs();
    NN_LOG_TRACE_INFO("create and initialize qp");
    RDMAAsyncEndPoint *rep = nullptr;

    if ((result = RDMAAsyncEndPoint::Create(mName, worker, rep)) != 0) {
        NN_LOG_ERROR("Failed to create ep for new connection in Driver " << mName << " , result " << result);
        ConnRespWithUId respWithUId { SERVER_INTERNAL_ERROR, 0 };
        conn.Send(&respWithUId, sizeof(ConnRespWithUId));
        return NN_ERROR;
    }
    NetLocalAutoDecreasePtr<RDMAAsyncEndPoint> repAutoDecPtr(rep);
    if ((result = rep->Initialize()) != 0) {
        NN_LOG_ERROR("Failed to initialize ep for new connection in Driver " << mName << " , result " << result);
        ConnRespWithUId respWithUId { SERVER_INTERNAL_ERROR, 0 };
        conn.Send(&respWithUId, sizeof(ConnRespWithUId));
        return NN_ERROR;
    }

    auto id = NetUuid::GenerateUuid();
    NN_LOG_TRACE_INFO("new ep id will be set as " << id << " in driver " << mName);

    respWithUId.connResp = OK;
    respWithUId.epId = id;
    conn.Send(&respWithUId, sizeof(ConnRespWithUId));
    auto endCreateQp = NetMonotonic::TimeUs();
    auto createQpTime = endCreateQp - startCreateQp;
    if (NN_UNLIKELY(createQpTime > MAX_OP_TIME_US)) {
        NN_LOG_WARN("Create qp time is too long :" << createQpTime << " us.");
    }

    // exchange info
    NN_LOG_TRACE_INFO("get and send exchange info of ep");
    auto startExchInfo = NetMonotonic::TimeUs();
    auto prePostCount = mOptions.prePostReceiveSizePerQP;
    RDMAQpExchangeInfo info {};
    if (mHeartBeat != nullptr) {
        mHeartBeat->GetRemoteHbInfo(info);
    }
    info.maxSendWr = mOptions.qpSendQueueSize;
    info.maxReceiveWr = mOptions.qpReceiveQueueSize;
    info.receiveSegSize = mOptions.mrSendReceiveSegSize;
    info.receiveSegCount = mOptions.prePostReceiveSizePerQP;
    if (((result = rep->GetExchangeInfo(info)) != 0)) {
        NN_LOG_ERROR("Failed to get ep exchange info in Driver " << mName << ", result " << result);
        return NN_ERROR;
    }
    if (((result = conn.Send(&info, sizeof(RDMAQpExchangeInfo))) != 0)) {
        NN_LOG_ERROR("Failed to get or send ep exchange info in Driver " << mName << ", result " << result);
        return NN_ERROR;
    }
    NN_LOG_TRACE_INFO("Send exchange info success in Server " << mName);
    NN_LOG_TRACE_INFO("local ep ex info lid " << info.lid << ", qpn " << info.qpn << ", gid interface " <<
        info.gid.global.interface_id);
    void *tmp = static_cast<void *>(&info);
    if ((result = conn.Receive(tmp, sizeof(RDMAQpExchangeInfo))) != 0) {
        NN_LOG_ERROR("Failed to receive ep exchange info in Driver " << mName << ", result " << result);
        return NN_ERROR;
    }
    NN_LOG_TRACE_INFO("Recv exchange info success in Server " << mName);

    //  receive payload length
    uint32_t payloadLen = 0;
    auto tmpPayloadLen = reinterpret_cast<void *>(&payloadLen);
    if ((result = conn.Receive(tmpPayloadLen, sizeof(uint32_t))) != 0) {
        NN_LOG_ERROR("Failed to receive connection payload length in Driver " << mName << ", result " << result);
        return NN_ERROR;
    }

    if (payloadLen == 0 || payloadLen > NN_NO1024) {
        NN_LOG_ERROR("Invalid payload length " << payloadLen << ", it should be 1 ~ 1024");
        return NN_ERROR;
    }

    //  receive payload
    std::string payload;
    if (payloadLen > 0) {
        auto payChars = new (std::nothrow) char[payloadLen + NN_NO1];
        if (payChars == nullptr) {
            NN_LOG_ERROR("Failed to new payload char array in Driver " << mName << ", probably out of memory");
            return NN_NEW_OBJECT_FAILED;
        }
        NetLocalAutoFreePtr<char> autoFreePayChars(payChars, true);

        void *tmpChars = static_cast<void *>(payChars);
        if ((result = conn.Receive(tmpChars, payloadLen)) != 0) {
            NN_LOG_ERROR("Failed to receive connection payload in Driver " << mName << ", result " << result);
            return NN_ERROR;
        }

        payChars[payloadLen] = '\0';
        payload = std::string(payChars, payloadLen);
    }

    NN_LOG_TRACE_INFO("remote qp ex info lid " << info.lid << ", qpn " << info.qpn << ", gid interface " <<
        info.gid.global.interface_id << ", pre-post-receive-count " << info.receiveSegCount);
    if ((result = rep->ChangeToReady(info)) != 0) {
        NN_LOG_ERROR("Failed to change ep to ready in Driver " << mName << ", result " << result);
        return result;
    }

    auto *mrSegs = new (std::nothrow) uintptr_t[prePostCount];
    if (mrSegs == nullptr) {
        NN_LOG_ERROR("Failed to create mr address array in Driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    NetLocalAutoFreePtr<uintptr_t> segAutoDelete(mrSegs, true);

    if (!rep->GetFreeBufferN(mrSegs, prePostCount)) {
        NN_LOG_ERROR("Failed to get free mr from pool, mr is not enough");
        return NN_MALLOC_FAILED;
    }

    uint16_t i = 0;
    for (; i < prePostCount; i++) {
        if ((result = worker->PostReceive(rep->Qp(), mrSegs[i], mOptions.mrSendReceiveSegSize, rep->GetLKey())) != 0) {
            break;
        }
    }

    for (; i < prePostCount; i++) {
        rep->ReturnBuffer(mrSegs[i]);
    }

    rep->PeerIpAndPort(conn.GetIpAndPort());
    auto endExchInfo = NetMonotonic::TimeUs();
    auto exchInfoTime = endExchInfo - startExchInfo;
    if (NN_UNLIKELY(exchInfoTime > MAX_OP_TIME_US)) {
        NN_LOG_WARN("Exchange info time too long :" << exchInfoTime << " us.");
    }

    // create endpoint
    auto startCreateEp = NetMonotonic::TimeUs();
    UBSHcomNetEndpointPtr ep = new (std::nothrow) NetAsyncEndpoint(id, rep, this, worker->Index());
    if (ep.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create UBSHcomNetEndpoint in Driver " << mName << ", probably out of memory");
        // do later, remove mr for prepost
        return NN_NEW_OBJECT_FAILED;
    }

    if (mOptions.oobType == NET_OOB_UDS) {
        struct ucred remoteIds {};
        socklen_t len = sizeof(struct ucred);
        if (NN_UNLIKELY(getsockopt(conn.GetFd(), SOL_SOCKET, SO_PEERCRED, &remoteIds, &len) != 0)) {
            char buf[NET_STR_ERROR_BUF_SIZE] = {0};
            NN_LOG_ERROR("Failed to get uds ids in driver " << mName << " errno:" << errno << " error:" <<
                NetFunc::NN_GetStrError(errno, buf, NET_STR_ERROR_BUF_SIZE));
            return NN_GET_UDS_ID_INFO_FAILED;
        }
        ep->RemoteUdsIdInfo(remoteIds.pid, remoteIds.uid, remoteIds.gid);
    }

    ep->StoreConnInfo(NetFunc::GetIpByFd(conn.GetFd()), conn.ListenPort(), header.version, payload);
    auto asyncEp = ep.ToChild<NetAsyncEndpoint>();
    if (NN_UNLIKELY(asyncEp == nullptr)) {
        NN_LOG_ERROR("To child Failed");
        return NN_ERROR;
    }

    asyncEp->SetRemoteHbInfo(info.hbAddress, info.hbKey, info.hbMrSize);
    if (mEnableTls) {
        auto oobSslConn = dynamic_cast<OOBSSLConnection *>(&conn);
        if (NN_UNLIKELY(oobSslConn == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        asyncEp->EnableEncrypt(mOptions);
        asyncEp->SetSecrets(oobSslConn->Secret());
    }
    rep->Qp()->UpContext(reinterpret_cast<uintptr_t>(ep.Get()));
    ep->mDevIndex = mDevIndex;
    ep->mPeerDevIndex = mPeerDevIndex;
    ep->mBandWidth = mBandWidth;
    ep->State().Set(NEP_ESTABLISHED);
    result = mNewEndPointHandler(conn.GetIpAndPort(), ep, payload);
    if (NN_UNLIKELY(result != RR_OK)) {
        NN_LOG_ERROR("Called new end point handler failed, result " << result);
        // do later, remove mr for prepost
        return NN_ERROR;
    }

    int8_t ready = 1;
    if ((result = conn.Send(&ready, sizeof(int8_t))) != RR_OK) {
        NN_LOG_ERROR("Failed to send ready signal to client, result " << result);
        // do later, remove mr for prepost
        return NN_ERROR;
    }

    {
        std::lock_guard<std::mutex> locker(mEndPointsMutex);
        auto ret = mEndPoints.emplace(ep->Id(), ep);
        if (!ret.second) {
            NN_LOG_ERROR("Failed to emplace ep, ep Id " << ep->Id());
            return NN_ERROR;
        }
    }
    reinterpret_cast<NetAsyncEndpoint *>(ep.Get())->GetRdmaEp()->Qp()->UpId(ep->Id());
    auto endCreateEp = NetMonotonic::TimeUs();
    auto createEpTime = endCreateEp - startCreateEp;
    if (NN_UNLIKELY(createEpTime > MAX_OP_TIME_US)) {
        NN_LOG_WARN("Create endpoint time too long :" << createEpTime << " us.");
    }

    OOBSecureProcess::SecProcessAddEpNum(ip, conn.ListenPort(), conn.GetIpAndPort(), mOobServers);

    NN_LOG_INFO("New connection from " << conn.GetIpAndPort() << " established, async ep id " << ep->Id() <<
        " worker info " << worker->DetailName());
    return NN_OK;
}

NResult NetDriverRDMAWithOob::Connect(const std::string &payload, UBSHcomNetEndpointPtr &ep, uint32_t flags,
    uint8_t serverGrpNo, uint8_t clientGrpNo)
{
    if (mOptions.oobType == NET_OOB_TCP) {
        return Connect(mOobIp, mOobPort, payload, ep, flags, serverGrpNo, clientGrpNo);
    } else if (mOptions.oobType == NET_OOB_UDS) {
        return Connect(mUdsName, 0, payload, ep, flags, serverGrpNo, clientGrpNo);
    }
    return NN_ERROR;
}

NResult NetDriverRDMAWithOob::Connect(const std::string &serverUrl, const std::string &payload,
    UBSHcomNetEndpointPtr &outEp, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
    if (NN_UNLIKELY(!mInited.load())) {
        NN_LOG_ERROR("Verbs Driver " << mName << " is not initialized");
        return NN_NOT_INITIALIZED;
    }

    if (NN_UNLIKELY(!mStarted)) {
        NN_LOG_ERROR("Verbs Failed to connect on driver " << mName << " as it is not started");
        return NN_ERROR;
    }

    if (payload.size() > NN_NO1024) {
        NN_LOG_ERROR("Verbs Failed to connect server via payload size " << payload.size() << " over limit");
        return NN_INVALID_PARAM;
    }
    if (NN_UNLIKELY(NetFunc::NN_ValidateUrl(serverUrl) != NN_OK)) {
        NN_LOG_ERROR("Invalid url");
        return NN_PARAM_INVALID;
    }

    NetDriverOobType type;
    std::string ip;
    uint16_t port = 0;
    if (NN_UNLIKELY(ParseUrl(serverUrl, type, ip, port) != NN_OK)) {
        NN_LOG_WARN("Invalid url, url:" << serverUrl);
        return NN_INVALID_PARAM;
    }

    OOBTCPClientPtr client;
    if (mEnableTls) {
        auto oobSSLClient = new (std::nothrow)
            OOBSSLClient(type, ip, port, mTlsPrivateKeyCB, mTlsCertCB, mTlsCaCallback);
        NN_ASSERT_LOG_RETURN(oobSSLClient != nullptr, NN_NEW_OBJECT_FAILED)
        oobSSLClient->SetTlsOptions(mOptions);
        oobSSLClient->SetPSKCallback(mPskFindSessionCb, mPskUseSessionCb);
        client = oobSSLClient;
    } else {
        client = new (std::nothrow) OOBTCPClient(mOptions.oobType, ip, port);
        NN_ASSERT_LOG_RETURN(client.Get() != nullptr, NN_NEW_OBJECT_FAILED)
    }

    /* all kind of drivers can connect to peer to get an ep */
    if ((flags & NET_EP_SELF_POLLING) || (flags & NET_EP_EVENT_POLLING)) {
        return ConnectSyncEp(client, payload, outEp, flags, serverGrpNo, ctx);
    }

    return Connect(client, payload, outEp, serverGrpNo, clientGrpNo, ctx);
}

NResult NetDriverRDMAWithOob::Connect(const std::string &oobIp, uint16_t oobPort, const std::string &payload,
    UBSHcomNetEndpointPtr &outEp, uint32_t flags, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
    if (NN_UNLIKELY(!mInited.load())) {
        NN_LOG_ERROR("Verbs Driver " << mName << " is not initialized");
        return NN_NOT_INITIALIZED;
    }

    if (NN_UNLIKELY(!mStarted)) {
        NN_LOG_ERROR("Verbs Failed to connect on driver " << mName << " as it is not started");
        return NN_ERROR;
    }

    if (payload.size() > NN_NO1024) {
        NN_LOG_ERROR("Verbs Failed to connect server via payload size " << payload.size() << " over limit");
        return NN_INVALID_PARAM;
    }

    OOBTCPClientPtr client;
    if (mEnableTls) {
        auto oobSSLClient = new (std::nothrow)
            OOBSSLClient(mOptions.oobType, oobIp, oobPort, mTlsPrivateKeyCB, mTlsCertCB, mTlsCaCallback);
        NN_ASSERT_LOG_RETURN(oobSSLClient != nullptr, NN_NEW_OBJECT_FAILED)
        oobSSLClient->SetTlsOptions(mOptions);
        oobSSLClient->SetPSKCallback(mPskFindSessionCb, mPskUseSessionCb);
        client = oobSSLClient;
    } else {
        client = new (std::nothrow) OOBTCPClient(mOptions.oobType, oobIp, oobPort);
        NN_ASSERT_LOG_RETURN(client.Get() != nullptr, NN_NEW_OBJECT_FAILED)
    }

    /* all kind of drivers can connect to peer to get an ep */
    if ((flags & NET_EP_SELF_POLLING) || (flags & NET_EP_EVENT_POLLING)) {
        return ConnectSyncEp(client, payload, outEp, flags, serverGrpNo, ctx);
    }

    return Connect(client, payload, outEp, serverGrpNo, clientGrpNo, ctx);
}

NResult NetDriverRDMAWithOob::ConnectSyncEp(const OOBTCPClientPtr &client, const std::string &payload,
    UBSHcomNetEndpointPtr &outEp, uint32_t flags, uint8_t serverGrpNo, uint64_t ctx)
{
    /* try to connect to oob server */
    OOBTCPConnection *conn = nullptr;
    NResult result = NN_OK;
    if (NN_UNLIKELY((result = client->Connect(conn)) != 0)) {
        NN_LOG_ERROR("Verbs Failed to connect server via oob,result " << result);
        return result;
    }

    NetLocalAutoDecreasePtr<OOBTCPConnection> autoDecPtr(conn);
    if (client->GetOobType() == NET_OOB_TCP) {
        conn->SetIpAndPort(client->GetServerIp(), client->GetServerPort());
    } else {
        conn->SetIpAndPort(client->GetServerUdsName(), 0);
    }

    if (mOptions.enableMultiRail) {
        ConnectHeader driverHeader;
        SetDriverConnHeader(driverHeader, mBandWidth, mDevIndex);
        if (NN_UNLIKELY((result = conn->Send(&driverHeader, sizeof(ConnectHeader))) != 0)) {
            NN_LOG_ERROR("Failed to send driver info " << mName << ", Result " << result);
            return result;
        }

        ConnectHeader header{};
        void *grpnobuf = static_cast<void *>(&header);
        result = conn->Receive(grpnobuf, sizeof(ConnectHeader));
        if (NN_UNLIKELY(result != 0)) {
            NN_LOG_ERROR("Failed to receive specified device info for server, result " << result);
            return result;
        }

        if (header.devIndex >= NN_NO4) {
            NN_LOG_ERROR("Invalid devIndex " << header.devIndex << " in header, which should be in 0 ~ 3");
            return NN_ERROR;
        }
        mPeerDevIndex = header.devIndex;
    }

    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBClient(mSecInfoProvider, mSecInfoValidator, conn, mName, ctx,
        mOptions.secType))) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    RDMAPollingMode pollMode = ((flags & NET_EP_EVENT_POLLING)) ? EVENT_POLLING : BUSY_POLLING;

    uint16_t prePostCount = mOptions.prePostReceiveSizePerQP;

    // create
    RDMASyncEndpoint *rep = nullptr;
    QpOptions qpOptions(mOptions.qpSendQueueSize, mOptions.qpReceiveQueueSize, mOptions.mrSendReceiveSegSize,
        mOptions.prePostReceiveSizePerQP);
    if (NN_UNLIKELY((result =
            RDMASyncEndpoint::Create(mName, mContext, pollMode, prePostCount + NN_NO4, qpOptions, rep)) != 0)) {
        NN_LOG_ERROR("Failed to create sync ep for new connection in Driver " << mName << " , result " << result);
        return result;
    }

    NetLocalAutoDecreasePtr<RDMASyncEndpoint> repAutoDecPtr(rep);
    if (NN_UNLIKELY((result = rep->Initialize()) != 0)) {
        NN_LOG_ERROR("Failed to initialize ep for new connection in Driver " << mName << " , result " << result);
        return result;
    }

    /* send connection header */
    ConnectHeader header;
    SetConnHeader(header, mOptions.magic, mOptions.version, serverGrpNo, Protocol(), mMajorVersion,
                  mMinorVersion, mOptions.tlsVersion);

    if (NN_UNLIKELY((result = conn->Send(&header, sizeof(ConnectHeader))) != 0)) {
        NN_LOG_ERROR("Failed to send server worker grpno in Driver " << mName << ", result " << result);
        return result;
    }

    /* receive connect response and peer ep id */
    ConnRespWithUId respWithUId {};
    void *ackBuf = static_cast<void *>(&respWithUId);
    if (NN_UNLIKELY((result = conn->Receive(ackBuf, sizeof(ConnRespWithUId))) != 0)) {
        NN_LOG_ERROR("Failed receive ServerAck in Driver " << mName << ", result " << result);
        return result;
    }

    /* connect response */
    auto serverAck = respWithUId.connResp;
    switch (serverAck) {
        case MAGIC_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server magic validation " << mName << ", result " << serverAck);
            return NN_CONNECT_REFUSED;
        case WORKER_GRPNO_MISMATCH:
        case WORKER_NOT_STARTED:
            NN_LOG_ERROR("Verbs Failed to choose worker or not started " << mName << ", result " << serverAck);
            return NN_CONNECT_REFUSED;
        case PROTOCOL_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server protocol validation " << mName << ", result " << serverAck);
            return NN_CONNECT_PROTOCOL_MISMATCH;
        case SERVER_INTERNAL_ERROR:
            NN_LOG_ERROR("Verbs Server error happened, connection refused " << mName << ", result " << serverAck);
            return NN_ERROR;
        case VERSION_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server version validation " << mName << ", result " << serverAck);
            return NN_CONNECT_REFUSED;
        case TLS_VERSION_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server tls version validation " << mName << ", result " << serverAck);
            return NN_CONNECT_REFUSED;
        case OK:
            break;
        default:
            NN_LOG_ERROR("Verbs Server error happened, connection refused " << mName << ", result " << serverAck);
            return NN_ERROR;
    }

    /* peer ep id */
    auto id = respWithUId.epId;
    NN_LOG_TRACE_INFO("new ep id will be set as " << id << " in driver " << mName);

    // exchange info
    NN_LOG_TRACE_INFO("get and send exchange info of ep");
    RDMAQpExchangeInfo info {};
    if (mHeartBeat != nullptr) {
        mHeartBeat->GetRemoteHbInfo(info);
    }
    info.maxSendWr = mOptions.qpSendQueueSize;
    info.maxReceiveWr = mOptions.qpReceiveQueueSize;
    info.receiveSegSize = mOptions.mrSendReceiveSegSize;
    info.receiveSegCount = mOptions.prePostReceiveSizePerQP;
    if (NN_UNLIKELY((result = rep->GetExchangeInfo(info)) != 0)) {
        NN_LOG_ERROR("Failed to get ep exchange info in Driver " << mName << ", result " << result);
        return result;
    }
    if (NN_UNLIKELY((result = conn->Send(&info, sizeof(RDMAQpExchangeInfo))) != 0)) {
        NN_LOG_ERROR("Failed to send ep exchange info in Driver " << mName << ", result " << result);
        return result;
    }

    // send payload len
    uint32_t payloadLen = payload.length();
    if (NN_UNLIKELY((result = conn->Send(&payloadLen, sizeof(uint32_t))) != 0)) {
        NN_LOG_ERROR("Failed to send connection payload length in Driver " << mName << ", result " << result);
        return result;
    }

    // send payload
    if (payloadLen > 0) {
        auto payloadPtr = reinterpret_cast<void *>(const_cast<char *>(payload.c_str()));
        if ((result = conn->Send(payloadPtr, payloadLen)) != 0) {
            NN_LOG_ERROR("Failed to send connection payload in Driver " << mName << ", result " << result);
            return result;
        }
    }

    void *tmp = static_cast<void *>(&info);
    if (NN_UNLIKELY((result = conn->Receive(tmp, sizeof(RDMAQpExchangeInfo))) != 0)) {
        NN_LOG_ERROR("Failed to receive ep exchange info in Driver " << mName << ", result " << result);
        return result;
    }

    NN_LOG_TRACE_INFO("remote qp ex info lid " << info.lid << ", qpn " << info.qpn << ", gid interface " <<
        info.gid.global.interface_id << ", pre-post-receive-count " << info.receiveSegCount);
    if (NN_UNLIKELY((result = rep->ChangeToReady(info)) != 0)) {
        NN_LOG_ERROR("Failed to change ep to ready in Driver " << mName << ", result " << result);
        return result;
    }

    rep->PeerIpAndPort(conn->GetIpAndPort());

    auto *mrSegs = new (std::nothrow) uintptr_t[prePostCount];
    if (mrSegs == nullptr) {
        NN_LOG_ERROR("Failed to create mr address array in Driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    NetLocalAutoFreePtr<uintptr_t> segAutoDelete(mrSegs, true);

    if (NN_UNLIKELY(!rep->GetFreeBufferN(mrSegs, prePostCount))) {
        NN_LOG_ERROR("Failed to get free mr from pool, result " << result);
        return NN_ERROR;
    }

    uint16_t i = 0;
    for (; i < prePostCount; i++) {
        if ((result = rep->PostReceive(mrSegs[i], mOptions.mrSendReceiveSegSize, rep->GetLKey())) != 0) {
            // do later if failure, qp should broken at this time
            break;
        }
    }

    for (; i < prePostCount; i++) {
        rep->ReturnBuffer(mrSegs[i]);
    }

    // create endpoint
    static UBSHcomNetWorkerIndex workerIndex;
    workerIndex.driverIdx = mIndex;
    UBSHcomNetEndpointPtr ep = new (std::nothrow) NetSyncEndpoint(id, rep, this, workerIndex);
    if (NN_UNLIKELY(ep.Get() == nullptr)) {
        NN_LOG_ERROR("Failed to create UBSHcomNetEndpoint in Driver " << mName << ", probably out of memory");
        // do later: handle pre post-ed mr
        return NN_NEW_OBJECT_FAILED;
    }
    if (mEnableTls) {
        auto asyncEp = ep.ToChild<NetSyncEndpoint>();
        auto oobSslConn = dynamic_cast<OOBSSLConnection *>(conn);
        if (NN_UNLIKELY(asyncEp == nullptr || oobSslConn == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        asyncEp->EnableEncrypt(mOptions);
        asyncEp->SetSecrets(oobSslConn->Secret());
    }
    ep->StoreConnInfo(NetFunc::GetIpByFd(conn->GetFd()), conn->ListenPort(), header.version, payload);

    // receive server ready signal
    int8_t ready = -1;
    tmp = static_cast<void *>(&ready);
    result = conn->Receive(tmp, sizeof(int8_t));
    if (result != 0 || ready != 1) {
        NN_LOG_ERROR("Failed to connect to server as server not respond or return not ready, result " << result);
        // do later: handle pre post-ed mr
        return NN_ERROR;
    }

    rep->Qp()->UpContext(reinterpret_cast<uintptr_t>(ep.Get()));
    {
        std::lock_guard<std::mutex> locker(mEndPointsMutex);
        mEndPoints.emplace(id, ep);
    }

    ep->State().Set(NEP_ESTABLISHED);

    NN_LOG_INFO("New connect to tcp:" << client->GetServerIp() << ":" << client->GetServerPort() <<" or uds: " <<
        client->GetServerUdsName() << " established, sync ep id " << ep->Id());

    ep->mDevIndex = mDevIndex;
    ep->mPeerDevIndex = mPeerDevIndex;
    ep->mBandWidth = mBandWidth;
    outEp = ep;
    reinterpret_cast<NetSyncEndpoint *>(ep.Get())->GetRdmaEp()->Qp()->UpId(ep->Id());
    return NN_OK;
}

NResult NetDriverRDMAWithOob::Connect(const OOBTCPClientPtr &client, const std::string &payload,
    UBSHcomNetEndpointPtr &outEp, uint8_t serverGrpNo, uint8_t clientGrpNo, uint64_t ctx)
{
    /* try to connect to oob server */
    OOBTCPConnection *conn = nullptr;
    NResult result = NN_OK;
    if ((result = client->Connect(conn)) != 0) {
        NN_LOG_ERROR("Verbs Failed to connect server via oob, Result " << result);
        return result;
    }

    NetLocalAutoDecreasePtr<OOBTCPConnection> autoDecPtr(conn);
    if (client->GetOobType() == NET_OOB_TCP) {
        conn->SetIpAndPort(client->GetServerIp(), client->GetServerPort());
    } else {
        conn->SetIpAndPort(client->GetServerUdsName(), 0);
    }

    if (mOptions.enableMultiRail) {
        ConnectHeader driverHeader;
        SetDriverConnHeader(driverHeader, mBandWidth, mDevIndex);
        if ((result = conn->Send(&driverHeader, sizeof(ConnectHeader))) != 0) {
            NN_LOG_ERROR("Failed to send driver info " << mName << ", Result " << result);
            return result;
        }

        ConnectHeader header{};
        void *grpnobuf = &header;
        result = conn->Receive(grpnobuf, sizeof(ConnectHeader));
        if (result != 0) {
            NN_LOG_ERROR("Failed to receive specified device info for server, Result " << result);
            return result;
        }

        if (header.devIndex >= NN_NO4) {
            NN_LOG_ERROR("Invalid devIndex " << header.devIndex << " in header, which should be in 0 ~ 3");
            return NN_ERROR;
        }
        mPeerDevIndex = header.devIndex;
    }

    if (NN_UNLIKELY(OOBSecureProcess::SecProcessInOOBClient(mSecInfoProvider, mSecInfoValidator, conn, mName, ctx,
        mOptions.secType))) {
        return NN_OOB_SEC_PROCESS_ERROR;
    }

    /* send connection header & grpNo */
    auto startSendGrpNo = NetMonotonic::TimeUs();
    ConnectHeader header;
    SetConnHeader(header, mOptions.magic, mOptions.version, serverGrpNo, Protocol(), mMajorVersion,
                  mMinorVersion, mOptions.tlsVersion);
    if ((result = conn->Send(&header, sizeof(ConnectHeader))) != 0) {
        NN_LOG_ERROR("Verbs Failed to send server worker grpno in Driver " << mName << ", result " << result);
        return result;
    }

    /* receive connect response and peer ep id */
    ConnRespWithUId respWithUId {};
    void *ackBuf = static_cast<void *>(&respWithUId);
    if ((result = conn->Receive(ackBuf, sizeof(ConnRespWithUId))) != 0) {
        NN_LOG_ERROR("Verbs Failed receive ServerAck in Driver " << mName << ", result " << result);
        return result;
    }

    /* connect response */
    auto serverAck = respWithUId.connResp;
    switch (serverAck) {
        case MAGIC_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server magic validation " << mName << ", Result " << serverAck);
            return NN_CONNECT_REFUSED;
        case WORKER_GRPNO_MISMATCH:
        case WORKER_NOT_STARTED:
            NN_LOG_ERROR("Verbs Failed to choose worker or not started " << mName << ", Result " << serverAck);
            return NN_CONNECT_REFUSED;
        case PROTOCOL_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server protocol validation " << mName << ", Result " << serverAck);
            return NN_CONNECT_PROTOCOL_MISMATCH;
        case SERVER_INTERNAL_ERROR:
            NN_LOG_ERROR("Verbs Server error happened, connection refused " << mName << ", Result " << serverAck);
            return NN_ERROR;
        case VERSION_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server version validation " << mName << ", Result " << serverAck);
            return NN_CONNECT_REFUSED;
        case TLS_VERSION_MISMATCH:
            NN_LOG_ERROR("Verbs Failed to pass server tls version validation " << mName << ", Result " << serverAck);
            return NN_CONNECT_REFUSED;
        case OK:
            break;
        default:
            NN_LOG_ERROR("Verbs Server error happened, connection refused " << mName << ", Result " << serverAck);
            return NN_ERROR;
    }

    auto endSendGrpNo = NetMonotonic::TimeUs();
    auto sendGrpNoTime = endSendGrpNo - startSendGrpNo;
    if (NN_UNLIKELY(sendGrpNoTime > MAX_OP_TIME_US)) {
        NN_LOG_WARN("Verbs Send groupNo time too long: " << sendGrpNoTime << " us.");
    }

    /* peer ep id */
    auto id = respWithUId.epId;
    NN_LOG_TRACE_INFO("new ep id will be set as " << id << " in driver " << mName);

    /* create rdma ep */
    RDMAAsyncEndPoint *rep = nullptr;
    uint16_t workerIndex = 0;
    if (NN_UNLIKELY(!mClientLb->ChooseWorker(clientGrpNo, std::to_string(id), workerIndex)) ||
        workerIndex >= mWorkers.size()) {
        NN_LOG_ERROR("Failed to choose worker during connect in driver " << mName);
        return NN_ERROR;
    }

    NN_ASSERT_LOG_RETURN(workerIndex < mWorkers.size(), NN_ERROR)
    auto *worker = mWorkers[workerIndex];

    if (!worker->IsWorkStarted()) {
        NN_LOG_ERROR("Failed to connect worker group no " << clientGrpNo << " in " << mName);
        return NN_ERROR;
    }

    if ((result = RDMAAsyncEndPoint::Create(mName, worker, rep)) != 0) {
        NN_LOG_ERROR("Failed to create ep for new connection in Driver " << mName << " , result " << result);
        return result;
    }

    NetLocalAutoDecreasePtr<RDMAAsyncEndPoint> repAutoDecPtr(rep);
    if ((result = rep->Initialize()) != 0) {
        NN_LOG_ERROR("Failed to initialize ep for new connection in Driver " << mName << " , result " << result);
        return result;
    }

    /* fill and send exchange info */
    auto startExchInfo = NetMonotonic::TimeUs();
    NN_LOG_TRACE_INFO("get and send exchange info of ep");
    RDMAQpExchangeInfo info {};
    if (mHeartBeat != nullptr) {
        mHeartBeat->GetRemoteHbInfo(info);
    }
    info.maxSendWr = mOptions.qpSendQueueSize;
    info.maxReceiveWr = mOptions.qpReceiveQueueSize;
    info.receiveSegCount = mOptions.prePostReceiveSizePerQP;
    info.receiveSegSize = mOptions.mrSendReceiveSegSize;

    if (((result = rep->GetExchangeInfo(info)) != 0)) {
        NN_LOG_ERROR("Failed to get ep exchange info in Driver " << mName << ", result " << result);
        return result;
    }

    if (((result = conn->Send(&info, sizeof(RDMAQpExchangeInfo))) != 0)) {
        NN_LOG_ERROR("Failed to send ep exchange info in Driver " << mName << ", result " << result);
        return result;
    }

    auto prePostCount = mOptions.prePostReceiveSizePerQP;
    // send payload len
    uint32_t payloadLen = payload.length();
    if ((result = conn->Send(&payloadLen, sizeof(uint32_t))) != 0) {
        NN_LOG_ERROR("Failed to send connection payload length in Driver " << mName << ", result " << result);
        return result;
    }

    // send payload
    if (payloadLen > 0) {
        auto payloadPtr = reinterpret_cast<void *>(const_cast<char *>(payload.c_str()));
        if ((result = conn->Send(payloadPtr, payloadLen)) != 0) {
            NN_LOG_ERROR("Failed to send connection payload in Driver " << mName << ", Result " << result);
            return result;
        }
    }

    /* receive exchange info */
    void *tmp = static_cast<void *>(&info);
    if ((result = conn->Receive(tmp, sizeof(RDMAQpExchangeInfo))) != 0) {
        NN_LOG_ERROR("Failed to receive ep exchange info in Driver " << mName << ", result " << result <<
            ". check your header");
        return result;
    }

    /* change to ready */
    NN_LOG_TRACE_INFO("remote qp ex info lid " << info.lid << ", qpn " << info.qpn << ", gid interface " <<
        info.gid.global.interface_id << ", pre-post-receive-count " << info.receiveSegCount);
    if ((result = rep->ChangeToReady(info)) != 0) {
        NN_LOG_ERROR("Verbs Failed to change ep to ready in Driver " << mName << ", result " << result);
        return result;
    }

    rep->PeerIpAndPort(conn->GetIpAndPort());

    auto *mrSegs = new (std::nothrow) uintptr_t[prePostCount];
    if (mrSegs == nullptr) {
        NN_LOG_ERROR("Verbs Failed to create mr address array in Driver " << mName << ", probably out of memory");
        return NN_NEW_OBJECT_FAILED;
    }

    NetLocalAutoFreePtr<uintptr_t> segAutoDelete(mrSegs, true);

    if (!rep->GetFreeBufferN(mrSegs, prePostCount)) {
        NN_LOG_ERROR("Failed to get free mr from pool, result " << result);
        return NN_ERROR;
    }

    uint16_t i = 0;
    for (; i < prePostCount; i++) {
        if ((result = worker->PostReceive(rep->Qp(), mrSegs[i], mOptions.mrSendReceiveSegSize, rep->GetLKey())) != 0) {
            break;
        }
    }

    for (; i < prePostCount; i++) {
        rep->ReturnBuffer(mrSegs[i]);
    }
    auto endExchInfo = NetMonotonic::TimeUs();
    auto exchInfoTime = endExchInfo - startExchInfo;
    if (NN_UNLIKELY(exchInfoTime > MAX_OP_TIME_US)) {
        NN_LOG_WARN("Exchange Info time too long: " << exchInfoTime << " us.");
    }

    // create endpoint
    auto startCreateEp = NetMonotonic::TimeUs();
    UBSHcomNetEndpointPtr ep = new (std::nothrow) NetAsyncEndpoint(id, rep, this, worker->Index());
    if (ep.Get() == nullptr) {
        NN_LOG_ERROR("Failed to create UBSHcomNetEndpoint in Driver " << mName << ", probably out of memory");
        // do later: handle pre post-ed mr
        return NN_NEW_OBJECT_FAILED;
    }

    auto asyncEp = ep.ToChild<NetAsyncEndpoint>();
    if (NN_UNLIKELY(asyncEp == nullptr)) {
        NN_LOG_ERROR("To Child Failed");
        return NN_ERROR;
    }

    if (mEnableTls) {
        auto oobSslConn = dynamic_cast<OOBSSLConnection *>(conn);
        if (NN_UNLIKELY(oobSslConn == nullptr)) {
            NN_LOG_ERROR("dynamic cast error");
            return NN_OOB_SEC_PROCESS_ERROR;
        }
        asyncEp->EnableEncrypt(mOptions);
        asyncEp->SetSecrets(oobSslConn->Secret());
    }

    rep->Qp()->UpContext(reinterpret_cast<uintptr_t>(ep.Get()));
    ep->StoreConnInfo(NetFunc::GetIpByFd(conn->GetFd()), conn->ListenPort(), header.version, payload);
    asyncEp->SetRemoteHbInfo(info.hbAddress, info.hbKey, info.hbMrSize);

    // receive server ready signal
    int8_t ready = -1;
    tmp = static_cast<void *>(&ready);
    result = conn->Receive(tmp, sizeof(int8_t));
    if (result != 0 || ready != 1) {
        NN_LOG_ERROR("Failed to connect to server as server not responses or return not ready, result " << result);
        // do later: handle pre post-ed mr
        return NN_ERROR;
    }

    ep->State().Set(NEP_ESTABLISHED);
    {
        std::lock_guard<std::mutex> locker(mEndPointsMutex);
        auto ret = mEndPoints.emplace(ep->Id(), ep);
        if (!ret.second) {
            NN_LOG_ERROR("Failed to emplace ep, ep Id " << ep->Id());
            return NN_ERROR;
        }
    }

    NN_LOG_INFO("New connect to tcp:" << client->GetServerIp() << ":" << client->GetServerPort() <<" or uds: " <<
        client->GetServerUdsName() << " established, async ep id " << ep->Id() << " worker info " <<
        worker->DetailName());
    ep->mDevIndex = mDevIndex;
    ep->mPeerDevIndex = mPeerDevIndex;
    ep->mBandWidth = mBandWidth;
    outEp = ep;
    reinterpret_cast<NetAsyncEndpoint *>(ep.Get())->GetRdmaEp()->Qp()->UpId(ep->Id());
    auto endCreateEp = NetMonotonic::TimeUs();
    auto createEpTime = endCreateEp - startCreateEp;
    if (NN_UNLIKELY(createEpTime > MAX_OP_TIME_US)) {
        NN_LOG_WARN("Create endpoint time too long: " << createEpTime << " us.");
    }
    return NN_OK;
}

void NetDriverRDMAWithOob::ProcessErrorNewRequest(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(ctx == nullptr || ctx->qp == nullptr || ctx->qp->UpContext1() == 0)) {
        NN_LOG_ERROR("Ctx or QP or Worker is null of RequestReceived in Driver " << mName << "");
        return;
    }

    if (ctx->opType == RDMAOpContextInfo::RECEIVE) {
        ctx->qp->ReturnBuffer(ctx->mrMemAddr);
        auto worker = reinterpret_cast<RDMAWorker *>(ctx->qp->UpContext1());
        worker->ReturnOpContextInfo(ctx);
        // not receive remote data, do not call user callback
    } else {
        NN_LOG_WARN("Unreachable path");
    }
}

NResult NetDriverRDMAWithOob::SendRequestFinishedCB(RDMAOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx,
    RDMAWorker *worker)
{
    NResult result = 0;
    if (ctx->opType == RDMAOpContextInfo::SEND) {
        if (NN_UNLIKELY(memcpy_s(&(netCtx.mHeader), sizeof(UBSHcomNetTransHeader),
            reinterpret_cast<UBSHcomNetTransHeader *>(ctx->mrMemAddr), sizeof(UBSHcomNetTransHeader)) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            result = NN_INVALID_PARAM;
        }
    } else {
        netCtx.mHeader.Invalid();
    }
    netCtx.mResult = RDMAOpContextInfo::GetNResult(ctx->opResultType);
    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->qp->UpContext()));
    netCtx.mMessage = nullptr;
    netCtx.mOpType = ctx->opType == RDMAOpContextInfo::SEND ? UBSHcomNetRequestContext::NN_SENT :
        UBSHcomNetRequestContext::NN_SENT_RAW;
    netCtx.mOriginalReq = {};
    // if PostSend implement with one side memory, the lAddress should be valued with ctx->mrMemAddr.
    netCtx.mOriginalReq.lAddress = 0;
    netCtx.mOriginalReq.size = ctx->dataSize;
    netCtx.mOriginalReq.upCtxSize = ctx->upCtxSize;

    if (netCtx.mOriginalReq.upCtxSize > 0 &&
        netCtx.mOriginalReq.upCtxSize <= sizeof(RDMASendReadWriteRequest::upCtxData)) {
        if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalReq.upCtxData, NN_NO16, ctx->upCtx, ctx->upCtxSize) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            result = NN_INVALID_PARAM;
        }
    }

    // send raw no copy not use send mr buffer, so not need to return
    if (ctx->opType != RDMAOpContextInfo::SEND_RAW_NO_CP || mEnableTls) {
        if (NN_UNLIKELY(!mDriverSendMR->ReturnBuffer(ctx->mrMemAddr))) {
            NN_LOG_ERROR("Failed to return mr segment back in Driver " << mName);
        }
    }

    // return context to worker, and ctx is set null, not usable anymore
    worker->ReturnOpContextInfo(ctx);
    // call to callback
    if (result == NN_OK && NN_UNLIKELY((result = mRequestPostedHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call requestPostedHandler in Driver " << mName <<
            " return non-zero for receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " <<
            netCtx.mHeader.dataLength << "]");
    }
    netCtx.mEp.Set(nullptr);
    return result;
}

NResult NetDriverRDMAWithOob::SendRawSglFinishedCB(RDMAOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx,
    RDMAWorker *worker)
{
    NResult result = 0;
    auto sgeCtx = reinterpret_cast<RDMASgeCtxInfo *>(ctx->upCtx);
    auto sglCtx = sgeCtx->ctx;
    result = RDMAOpContextInfo::GetNResult(ctx->opResultType);
    // set context
    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->qp->UpContext()));
    netCtx.mResult = sglCtx->result < result ? result : sglCtx->result;
    netCtx.mOpType = UBSHcomNetRequestContext::NN_SENT_RAW_SGL;
    netCtx.mHeader.Invalid();
    netCtx.mMessage = nullptr;
    if (NN_UNLIKELY(memcpy_s(netCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, sglCtx->iov,
        sizeof(UBSHcomNetTransSgeIov) * sglCtx->iovCount) != NN_OK)) {
        NN_LOG_ERROR("Failed to copy request to sglCtx");
        result = NN_INVALID_PARAM;
    }
    netCtx.mOriginalSglReq.iov = netCtx.iov;
    netCtx.mOriginalSglReq.iovCount = sglCtx->iovCount;
    netCtx.mOriginalSglReq.upCtxSize = sglCtx->upCtxSize;
    if (netCtx.mOriginalSglReq.upCtxSize > 0 &&
        netCtx.mOriginalSglReq.upCtxSize <= sizeof(UBSHcomNetTransSglRequest::upCtxData)) {
        if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalSglReq.upCtxData, NN_NO16, sglCtx->upCtx, sglCtx->upCtxSize) !=
            NN_OK)) {
            NN_LOG_ERROR("Failed to copy request to sglCtx");
            result = NN_INVALID_PARAM;
        }
    }
    worker->ReturnSglContextInfo(sglCtx);
    // called to callback
    if (result == NN_OK && NN_UNLIKELY((result = mRequestPostedHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call requestPostedHandler in Driver " << mName << " return non-zero for sgl type " <<
            ctx->opType << " done");
    }
    netCtx.mEp.Set(nullptr);

    // buffer should return when encrypt
    if (mEnableTls) {
        (void)mDriverSendMR->ReturnBuffer(ctx->mrMemAddr);
    }

    worker->ReturnOpContextInfo(ctx);
    return result;
}

NResult NetDriverRDMAWithOob::SendSglInlineFinishedCB(RDMAOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx,
    RDMAWorker *worker)
{
    NResult result = 0;

    netCtx.mResult = RDMAOpContextInfo::GetNResult(ctx->opResultType);
    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->qp->UpContext()));
    netCtx.mMessage = nullptr;
    netCtx.mOpType = UBSHcomNetRequestContext::NN_SENT_SGL_INLINE;
    netCtx.mHeader.Invalid();
    netCtx.mOriginalReq = {};
    netCtx.mOriginalReq.lAddress = ctx->mrMemAddr;
    netCtx.mOriginalReq.size = ctx->dataSize;
    netCtx.mOriginalReq.upCtxSize = ctx->upCtxSize;

    if (netCtx.mOriginalReq.upCtxSize > 0 &&
        netCtx.mOriginalReq.upCtxSize <= sizeof(RDMASendReadWriteRequest::upCtxData)) {
        if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalReq.upCtxData, NN_NO16, ctx->upCtx, ctx->upCtxSize) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            result = NN_INVALID_PARAM;
        }
    }
    // return context to worker, and ctx is set null, not usable anymore
    worker->ReturnOpContextInfo(ctx);
    // call to callback
    if (result == NN_OK && NN_UNLIKELY((result = mRequestPostedHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call requestPostedHandler in Driver " << mName <<
            " return non-zero for receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " <<
            netCtx.mHeader.dataLength << "]");
    }
    netCtx.mEp.Set(nullptr);
    return result;
}

int NetDriverRDMAWithOob::SendFinishedCB(RDMAOpContextInfo *ctx)
{
    static thread_local UBSHcomNetRequestContext netCtx {};
    ctx->qp->ReturnPostSendWr();
    auto worker = reinterpret_cast<RDMAWorker *>(ctx->qp->UpContext1());

    if (ctx->opType == RDMAOpContextInfo::SEND || ctx->opType == RDMAOpContextInfo::SEND_RAW ||
        ctx->opType == RDMAOpContextInfo::SEND_RAW_NO_CP) {
        return SendRequestFinishedCB(ctx, netCtx, worker);
    } else if (ctx->opType == RDMAOpContextInfo::SEND_RAW_SGL) {
        return SendRawSglFinishedCB(ctx, netCtx, worker);
    } else if (ctx->opType == RDMAOpContextInfo::SEND_SGL_INLINE) {
        return SendSglInlineFinishedCB(ctx, netCtx, worker);
    } else {
        NN_LOG_WARN("Unreachable path");
    }

    return NN_OK;
}

void NetDriverRDMAWithOob::ProcessErrorSendFinished(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(ctx == nullptr || ctx->qp == nullptr || ctx->qp->UpContext1() == 0)) {
        NN_LOG_ERROR("Ctx or QP or Worker is null of RequestReceived in Driver " << mName << "");
        return;
    }

    SendFinishedCB(ctx);
}

int NetDriverRDMAWithOob::RWOneSideDoneCB(RDMAOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx, RDMAWorker *worker)
{
    int result = 0;
    // set context
    netCtx.mResult = RDMAOpContextInfo::GetNResult(ctx->opResultType);
    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->qp->UpContext()));
    netCtx.mOpType =
        ctx->opType == RDMAOpContextInfo::WRITE ? UBSHcomNetRequestContext::NN_WRITTEN :
        UBSHcomNetRequestContext::NN_READ;
    netCtx.mHeader.Invalid();
    netCtx.mMessage = nullptr;
    netCtx.mOriginalReq.lAddress = ctx->mrMemAddr;
    netCtx.mOriginalReq.lKey = ctx->lKey;
    netCtx.mOriginalReq.size = ctx->dataSize;
    netCtx.mOriginalReq.upCtxSize = ctx->upCtxSize;

    if (netCtx.mOriginalReq.upCtxSize > 0 &&
        netCtx.mOriginalReq.upCtxSize <= sizeof(RDMASendReadWriteRequest::upCtxData)) {
        if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalReq.upCtxData, NN_NO16, ctx->upCtx, ctx->upCtxSize) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            result = NN_INVALID_PARAM;
        }
    }

    // return context to worker and ctx is not usable anymore
    worker->ReturnOpContextInfo(ctx);

    // called to callback
    if (result == NN_OK && NN_UNLIKELY((result = mOneSideDoneHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call oneSideDoneHandler in Driver " << mName << " done");
    }
    netCtx.mEp.Set(nullptr);
    return result;
}

int NetDriverRDMAWithOob::OneSideDoneCB(RDMAOpContextInfo *ctx)
{
    int result = 0;
    static thread_local UBSHcomNetRequestContext netCtx {};
    auto worker = reinterpret_cast<RDMAWorker *>(ctx->qp->UpContext1());
    ctx->qp->ReturnOneSideWr();
    if (ctx->opType == RDMAOpContextInfo::WRITE || ctx->opType == RDMAOpContextInfo::READ) {
        return RWOneSideDoneCB(ctx, netCtx, worker);
    } else if (ctx->opType == RDMAOpContextInfo::SGL_WRITE || ctx->opType == RDMAOpContextInfo::SGL_READ) {
        auto sgeCtx = reinterpret_cast<RDMASgeCtxInfo *>(ctx->upCtx);
        auto sglCtx = sgeCtx->ctx;
        result = RDMAOpContextInfo::GetNResult(ctx->opResultType);
        sglCtx->result = sglCtx->result < result ? result : sglCtx->result;
        /* 一个完成项可能覆盖多个 iov(多SGE合并)：按 count 累加 */
        auto cover = sgeCtx->count == 0 ? 1U : static_cast<uint32_t>(sgeCtx->count);
        auto refCount = __sync_add_and_fetch(&(sglCtx->refCount), cover);
        if (refCount != sglCtx->iovCount) {
            worker->ReturnOpContextInfo(ctx);
            return NN_OK;
        }
        // set context
        netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->qp->UpContext()));
        netCtx.mResult = sglCtx->result;
        netCtx.mOpType = ctx->opType == RDMAOpContextInfo::SGL_WRITE ? UBSHcomNetRequestContext::NN_SGL_WRITTEN :
                                                                       UBSHcomNetRequestContext::NN_SGL_READ;
        netCtx.mHeader.Invalid();
        netCtx.mMessage = nullptr;
        if (NN_UNLIKELY(memcpy_s(netCtx.iov, sizeof(UBSHcomNetTransSgeIov) * NET_SGE_MAX_IOV, sglCtx->iov,
            sizeof(UBSHcomNetTransSgeIov) * sglCtx->iovCount) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            result = NN_INVALID_PARAM;
        }
        netCtx.mOriginalSglReq.iov = netCtx.iov;
        netCtx.mOriginalSglReq.iovCount = sglCtx->iovCount;
        netCtx.mOriginalSglReq.upCtxSize = sglCtx->upCtxSize;
        if (netCtx.mOriginalSglReq.upCtxSize > 0 &&
            netCtx.mOriginalSglReq.upCtxSize <= sizeof(UBSHcomNetTransSglRequest::upCtxData)) {
            if (NN_UNLIKELY(memcpy_s(netCtx.mOriginalSglReq.upCtxData, NN_NO16, sglCtx->upCtx, sglCtx->upCtxSize) !=
                NN_OK)) {
                NN_LOG_ERROR("Failed to copy req to sglCtx");
                result = NN_INVALID_PARAM;
            }
        }
        worker->ReturnSglContextInfo(sglCtx);
        // called to callback
        if (result == NN_OK && NN_UNLIKELY((result = mOneSideDoneHandler(netCtx)) != NN_OK)) {
            NN_LOG_ERROR("Call oneSideDoneHandler in Driver " << mName << " return non-zero for sgl type " <<
                ctx->opType << " done");
        }
        netCtx.mEp.Set(nullptr);
        worker->ReturnOpContextInfo(ctx);
    } else if (ctx->opType == RDMAOpContextInfo::HB_WRITE) {
        auto ep = reinterpret_cast<NetAsyncEndpoint *>(ctx->qp->UpContext());
        if (ctx->opResultType == RDMAOpContextInfo::SUCCESS) {
            ep->HbRecordCount();
        }

        worker->ReturnOpContextInfo(ctx);
    } else {
        NN_LOG_WARN("Unreachable path");
    }

    return result;
}

void NetDriverRDMAWithOob::ProcessErrorOneSideDone(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(ctx == nullptr || ctx->qp == nullptr || ctx->qp->UpContext1() == 0)) {
        NN_LOG_ERROR("Ctx or QP or Worker is null of RequestReceived in Driver " << mName << "");
        return;
    }

    OneSideDoneCB(ctx);
}

void NetDriverRDMAWithOob::ProcessEpError(uintptr_t ep)
{
    auto epPtr = reinterpret_cast<NetAsyncEndpoint *>(ep);

    bool process = false;
    if (NN_UNLIKELY(!epPtr->EPBrokenProcessed().compare_exchange_strong(process, true))) {
        NN_LOG_WARN("Ep id " << epPtr->Id() << " broken handled by other thread");
        return;
    }

    if (epPtr->State().Compare(NEP_ESTABLISHED)) {
        epPtr->State().Set(NEP_BROKEN);
    }

    auto qp = epPtr->GetRdmaEp()->Qp();
    qp->Stop();

    RDMAOpContextInfo *remainingOpCtx = nullptr;
    RDMAOpContextInfo *nextOpCtx = nullptr;
    qp->GetCtxPosted(remainingOpCtx);
    while (remainingOpCtx != nullptr) {
        ProcessErrorContext(nextOpCtx, remainingOpCtx, epPtr);
    }

    // when ep set broken, there maybe some new context add
    while (qp->GetPostedCount() != 0) {
        NN_LOG_INFO("Process remain op ctx, qp " << qp->Name());
        qp->GetCtxPosted(remainingOpCtx);
        while (remainingOpCtx != nullptr) {
            ProcessErrorContext(nextOpCtx, remainingOpCtx, epPtr);
        }
    }

    NN_LOG_WARN("Handle Ep state " << UBSHcomNEPStateToString(epPtr->State().Get()) << ", Ep id " << epPtr->Id() <<
        " , try call Ep broken handle");
    UBSHcomNetEndpointPtr netEp = reinterpret_cast<UBSHcomNetEndpoint *>(epPtr);
    OOBSecureProcess::SecProcessDelEpNum(epPtr->LocalIp(), epPtr->ListenPort(), epPtr->PeerIpAndPort(),
        mOobServers);
    mEndPointBrokenHandler(netEp);
    DestroyEndpoint(netEp);
}

void NetDriverRDMAWithOob::ProcessQPError(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(!ValidateRequestContext(ctx))) {
        return;
    }

    // get ep
    auto epPtr = reinterpret_cast<NetAsyncEndpoint *>(ctx->qp->UpContext());
    ProcessEpError(reinterpret_cast<uintptr_t>(epPtr));
}

int NetDriverRDMAWithOob::NewRequest(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(!ValidateRequestContext(ctx))) {
        return NN_ERROR;
    }

    if (NN_UNLIKELY(ctx->opResultType != RDMAOpContextInfo::SUCCESS)) {
        ProcessQPError(ctx);
        return NN_OK;
    }

    static thread_local UBSHcomNetRequestContext netCtx {};
    static thread_local UBSHcomNetMessage msg;
    auto worker = reinterpret_cast<RDMAWorker *>(ctx->qp->UpContext1());
    uint32_t immData = *reinterpret_cast<uint32_t *>(ctx->upCtx);

    if (ctx->opType == RDMAOpContextInfo::RECEIVE && immData == 0) {
        return NewReceivedRequest(ctx, netCtx, msg, worker);
    } else if (ctx->opType == RDMAOpContextInfo::RECEIVE && immData != 0) {
        return NewReceivedRawRequest(ctx, netCtx, msg, worker, immData);
    } else {
        NN_LOG_WARN("Unreachable path");
    }

    return NN_OK;
}

NResult NetDriverRDMAWithOob::NewReceivedRawRequest(RDMAOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx,
    UBSHcomNetMessage &msg, RDMAWorker *worker, uint32_t immData) const
{ /* for raw message */
    bool messageReady = true;

    auto qpUpContext = ctx->qp->UpContext();
    UBSHcomNetEndpointPtr ep = reinterpret_cast<UBSHcomNetEndpoint *>(qpUpContext);
    auto asyncEp = ep.ToChild<NetAsyncEndpoint>();
    if (NN_UNLIKELY(asyncEp == nullptr)) {
        NN_LOG_ERROR("ToChild failed");
        return NN_ERROR;
    }
    auto tmpDataAddress = reinterpret_cast<void *>(ctx->mrMemAddr);
    if (asyncEp->mIsNeedEncrypt) {
        size_t decryptRawLen = asyncEp->mAes.GetRawLen(ctx->dataSize);
        messageReady = msg.AllocateIfNeed(decryptRawLen);
        if (NN_LIKELY(messageReady)) {
            uint32_t decryptLen = 0;
            if (!asyncEp->mAes.Decrypt(asyncEp->mSecrets, tmpDataAddress, ctx->dataSize, msg.mBuf, decryptLen) ||
                decryptLen != decryptRawLen) {
                NN_LOG_ERROR("Failed to decrypt data");
                (void)worker->RePostReceive(ctx);
                return NN_DECRYPT_FAILED;
            }
            msg.mDataLen = decryptRawLen;
        }
    } else {
        msg.SetBuf(tmpDataAddress, ctx->dataSize);
        msg.mDataLen = ctx->dataSize;
    }

    int result = 0;

    if (NN_UNLIKELY(!messageReady)) {
        NN_LOG_ERROR("Failed to build UBSHcomNetRequestContext or message in Driver " << mName <<
            ", receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " << msg.mDataLen <<
            "] will be dropped");
        return NN_OK;
    }

    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(qpUpContext));
    netCtx.mMessage = &msg;
    netCtx.mOpType = UBSHcomNetRequestContext::NN_RECEIVED_RAW;
    netCtx.mOriginalReq = {};
    netCtx.mHeader.Invalid();
    netCtx.mHeader.dataLength = msg.mDataLen;
    netCtx.mHeader.seqNo = immData;

    // call to callback
    if (NN_UNLIKELY((result = mReceivedRequestHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Call receivedRequestHandler in Driver " << mName <<
            " return non-zero for receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " <<
            netCtx.mHeader.dataLength << "]");
    }

    // after repost the ctx cannot be used anymore
    if (NN_UNLIKELY((result = worker->RePostReceive(ctx)) != 0)) {
        NN_LOG_ERROR("Failed to repost receive in Driver " << mName << ", result " << result);
    }

    msg.SetBuf(nullptr, 0);
    netCtx.mMessage = nullptr;
    netCtx.mEp.Set(nullptr);

    return NN_OK;
}

NResult NetDriverRDMAWithOob::NewReceivedRequest(RDMAOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx,
    UBSHcomNetMessage &msg, RDMAWorker *worker) const
{
    bool messageReady = true;
    auto *tmpHeader = reinterpret_cast<UBSHcomNetTransHeader *>(ctx->mrMemAddr);
    auto qpUpContext = ctx->qp->UpContext();
    auto tmpDataAddress = reinterpret_cast<void *>(ctx->mrMemAddr + sizeof(UBSHcomNetTransHeader));

    UBSHcomNetEndpointPtr ep = reinterpret_cast<UBSHcomNetEndpoint *>(qpUpContext);
    auto asyncEp = ep.ToChild<NetAsyncEndpoint>();
    if (NN_UNLIKELY(asyncEp == nullptr)) {
        NN_LOG_ERROR("ToChild failed");
        return NN_ERROR;
    }

    auto rst = NetFunc::ValidateHeaderWithDataSize(*tmpHeader, ctx->dataSize);
    if (NN_UNLIKELY(rst != NN_OK)) {
        worker->RePostReceive(ctx);
        return rst;
    }

    // 非加密场景可以免拷贝
    if (!asyncEp->mIsNeedEncrypt) {
        return NewReceivedRequestWithoutCopy(ctx, netCtx, msg, worker, tmpDataAddress, tmpHeader);
    }

    uint32_t decryptRawLen = asyncEp->mAes.GetRawLen(tmpHeader->dataLength);
    messageReady = msg.AllocateIfNeed(decryptRawLen);
    if (NN_LIKELY(messageReady)) {
        uint32_t decryptLen = 0;
        if (!asyncEp->mAes.Decrypt(asyncEp->mSecrets, tmpDataAddress, tmpHeader->dataLength, msg.mBuf,
            decryptLen)) {
            NN_LOG_ERROR("Verbs Failed to decrypt data");
            (void)worker->RePostReceive(ctx);
            return NN_DECRYPT_FAILED;
        }
        if (NN_UNLIKELY(memcpy_s(&(netCtx.mHeader), sizeof(UBSHcomNetTransHeader), tmpHeader,
            sizeof(UBSHcomNetTransHeader)) != NN_OK)) {
            NN_LOG_ERROR("Failed to copy req to sglCtx");
            return NN_INVALID_PARAM;
        }
        msg.mDataLen = decryptRawLen;
    }

    int result = 0;
    if (NN_UNLIKELY((result = worker->RePostReceive(ctx)) != 0)) {
        NN_LOG_ERROR("Verbs Failed to repost receive in Driver " << mName << ", result " << result);
    }

    if (NN_UNLIKELY(!messageReady)) {
        NN_LOG_ERROR("Verbs Failed to build UBSHcomNetRequestContext or message in Driver " << mName <<
            ", receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " << msg.mDataLen <<
            "] will be dropped");
        return NN_OK;
    }

    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(qpUpContext));
    netCtx.mOpType = UBSHcomNetRequestContext::NN_RECEIVED;
    netCtx.mMessage = &msg;
    netCtx.mOriginalReq = {};
    netCtx.mHeader.dataLength = msg.mDataLen;
    netCtx.extHeaderType = tmpHeader->extHeaderType;  // 指导服务层处理

    // call to callback
    if (NN_UNLIKELY((result = mReceivedRequestHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Verbs Call receivedRequestHandler in Driver " << mName <<
            " return non-zero for receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " <<
            netCtx.mHeader.dataLength << "]");
    }

    netCtx.mEp.Set(nullptr);
    return NN_OK;
}

NResult NetDriverRDMAWithOob::NewReceivedRequestWithoutCopy(RDMAOpContextInfo *ctx, UBSHcomNetRequestContext &netCtx,
    UBSHcomNetMessage &msg, RDMAWorker *worker, void *dataAddress, UBSHcomNetTransHeader *header) const
{
    msg.SetBuf(dataAddress, header->dataLength);
    msg.mDataLen = header->dataLength;

    netCtx.mEp.Set(reinterpret_cast<UBSHcomNetEndpoint *>(ctx->qp->UpContext()));
    netCtx.mOpType = UBSHcomNetRequestContext::NN_RECEIVED;
    netCtx.mMessage = &msg;
    netCtx.mOriginalReq = {};
    netCtx.mHeader.dataLength = msg.mDataLen;
    netCtx.mHeader.seqNo = header->seqNo;
    netCtx.mHeader.opCode = header->opCode;
    netCtx.mHeader.timeout = header->timeout;
    netCtx.mHeader.flags = header->flags;
    netCtx.mHeader.headerCrc = header->headerCrc;
    netCtx.mHeader.errorCode = header->errorCode;
    netCtx.extHeaderType = header->extHeaderType;  // 指导服务层处理
    int result = 0;
    // call to callback
    if (NN_UNLIKELY((result = mReceivedRequestHandler(netCtx)) != NN_OK)) {
        NN_LOG_ERROR("Verbs Call receivedRequestHandler in Driver " << mName <<
            " return non-zero for receive message [opCode: " << netCtx.mHeader.opCode << ", dataSize " <<
            netCtx.mHeader.dataLength << "]");
    }
    msg.SetBuf(nullptr, 0);
    netCtx.mMessage = nullptr;
    netCtx.mEp.Set(nullptr);

    if (NN_UNLIKELY((result = worker->RePostReceive(ctx)) != 0)) {
        NN_LOG_ERROR("Verbs Failed to repost receive in Driver " << mName << ", result " << result);
    }

    return NN_OK;
}

int NetDriverRDMAWithOob::SendFinished(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(!ValidateRequestContext(ctx))) {
        return NN_ERROR;
    }

    if (NN_UNLIKELY(ctx->opResultType != RDMAOpContextInfo::SUCCESS)) {
        ProcessQPError(ctx);
        return NN_OK;
    }

    return SendFinishedCB(ctx);
}

int NetDriverRDMAWithOob::OneSideDone(RDMAOpContextInfo *ctx)
{
    if (NN_UNLIKELY(!ValidateRequestContext(ctx))) {
        return NN_ERROR;
    }

    if (NN_UNLIKELY(ctx->opResultType != RDMAOpContextInfo::SUCCESS)) {
        ProcessQPError(ctx);
        return NN_OK;
    }

    return OneSideDoneCB(ctx);
}
}
}
#endif
