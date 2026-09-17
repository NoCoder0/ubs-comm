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

#ifndef HCOM_RDMA_VERBS_WRAPPER_CTX_H
#define HCOM_RDMA_VERBS_WRAPPER_CTX_H
#ifdef RDMA_BUILD_ENABLED

#include "hcom_utils.h"
#include "hcom_obj_statistics.h"
#include "rdma_common.h"
#include "rdma_device_helper.h"

namespace ock {
namespace hcom {

inline uint8_t GetTrafficClass()
{
    uint8_t tc = 106;
    auto env = getenv("HCOM_QP_TRAFFIC_CLASS");
    if (env == nullptr) {
        return tc;
    }

    long tmp = 0;
    NetFunc::NN_Stol(env, tmp);
    if (tmp >= 0 && tmp < NN_NO256) {
        return static_cast<uint8_t>(tmp);
    }

    return tc;
}

inline uint8_t GetMaxRdAtomic()
{
    uint8_t rdAtomic = 1;
    auto env = getenv("HCOM_MAX_RD_ATOMIC");
    if (env == nullptr) {
        return rdAtomic;
    }

    long tmp = 0;
    NetFunc::NN_Stol(env, tmp);
    if (tmp >= 0 && tmp < NN_NO256) {
        return static_cast<uint8_t>(tmp);
    }

    return rdAtomic;
}

class RDMAContext {
public:
    static RResult Create(const std::string &name, bool useDevX, const RDMAGId &gid, RDMAContext *&ctx);

public:
    RDMAContext(const std::string &name, bool useDevX, const RDMAGId &gid)
        : mName(name), mDevIndex(gid.devIndex), mBestGid(gid), mUseDevX(useDevX)
    {
        OBJ_GC_INCREASE(RDMAContext);
    }

    ~RDMAContext()
    {
        UnInitialize();
        OBJ_GC_DECREASE(RDMAContext);
    }

    RResult Initialize();
    RResult UnInitialize();

    void UpdateGid(const std::string &matchIp);

    RDMAContext() = delete;
    RDMAContext(const RDMAContext &) = delete;
    RDMAContext &operator = (const RDMAContext &) = delete;
    RDMAContext(RDMAContext &&) = delete;
    RDMAContext &operator = (RDMAContext &&) = delete;

    std::string ToString()
    {
        std::ostringstream oss;
        oss << "RDMAContext info: mName " << mName << ", use DevX " << mUseDevX << ", mContext " << mContext <<
            ", mProtectDomain " << mProtectDomain << ", mDevIndex " << mDevIndex << ", mPortAttr " <<
            HcomIbv::PortStateStr(mPortAttr.state) << "|" << mPortAttr.lid << "|" << mPortAttr.max_mtu <<
            ", mBestGid " << mBestGid.devIndex << "|" << mBestGid.gid << "|" << mBestGid.ibvGid.global.interface_id <<
            "|" << mBestGid.RoCEVersion;
        return oss.str();
    }

    inline ibv_context *Context()
    {
        return mContext;
    }

#ifdef RDMA_CX5_BUILD_ENABLED
    inline ibv_dm *DeviceMemory()
    {
        return mDeviceMemory;
    }
#endif

    inline bool UseDevX() const
    {
        return mUseDevX;
    }
    DEFINE_RDMA_REF_COUNT_FUNCTIONS

private:
    std::string mName;
    ibv_context *mContext = nullptr;
    ibv_pd *mProtectDomain = nullptr;
#ifdef RDMA_CX5_BUILD_ENABLED
    ibv_dm *mDeviceMemory = nullptr;
#endif
    struct ibv_port_attr mPortAttr {};
    uint8_t mPortNumber = 1;
    uint16_t mDevIndex = 0;
    int mMaxSge = NET_WR_MAX_SGE;
    RDMAGId mBestGid {};
    bool mUseDevX = false;

    DEFINE_RDMA_REF_COUNT_VARIABLE;

    friend RDMAQp;
    friend RDMACq;
    friend RDMAMemoryRegion;
    friend RDMAWorker;

#ifdef RDMA_CX5_BUILD_ENABLED
    friend RDMAMlx5Qp;
    friend RDMAMlx5Cq;
    friend RDMAMlx5Worker;
#endif
};
}
}
#endif
#endif // HCOM_RDMA_VERBS_WRAPPER_CTX_H