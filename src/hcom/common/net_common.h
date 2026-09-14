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
#ifndef OCK_NET_COMMON_123424434341233_H
#define OCK_NET_COMMON_123424434341233_H

#include <atomic>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <ifaddrs.h>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <strings.h>
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <regex>
#include <arpa/inet.h>

#include "net_crc32.h"
#include "net_trace.h"
#include "net_util.h"
#include "securec.h"
#ifdef UB_BUILD_ENABLED
#include "under_api/urma/tpsa_api_dl_wrapper.h"
#endif

namespace ock {
namespace hcom {
constexpr int INVALID_FD = -1;
constexpr int16_t MAX_OPCODE = NN_NO1200;
constexpr uint32_t OOB_DEFAULT_LISTEN_PORT = 9980;
constexpr uint32_t OOB_DEFAULT_LISTEN_BACKLOG = 65535;
constexpr uint32_t MR_FIXED_POOL_DEFAULT_SEG_SIZE = 8192;
constexpr uint32_t MR_FIXED_POOL_DEFAULT_SEG_COUNT = 1024;

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

/**
 * Get struct pointer from member pointer
 */
#define GetStructRoot(_memberPtr, _type, _field) ((_type*)((char*)(_memberPtr) - offsetof(_type, _field)))

enum class NetProtocol {
    NET_TCP,
    NET_UDS,
    NET_UBC,
};

class NetFunc {
public:
    static inline uint32_t CalcHeaderCrc32(UBSHcomNetTransHeader *header)
    {
        static const uint32_t netTransHeaderlength = sizeof(UBSHcomNetTransHeader) - sizeof(uint32_t);
        return NetCrc32::CalcCrc32(reinterpret_cast<uint8_t *>(header) + sizeof(uint32_t), netTransHeaderlength);
    }

    static inline uint32_t CalcHeaderCrc32(UBSHcomNetTransHeader &header)
    {
        static const uint32_t netTransHeaderlength = sizeof(UBSHcomNetTransHeader) - sizeof(uint32_t);
        return NetCrc32::CalcCrc32(reinterpret_cast<uint8_t *>(&header) + sizeof(uint32_t), netTransHeaderlength);
    }

    static inline bool ValidateHeaderCrc32(UBSHcomNetTransHeader *header)
    {
        if (NN_UNLIKELY(header == nullptr)) {
            NN_LOG_ERROR("Invalid param, header must be correct address");
            return false;
        }
        return header->headerCrc == CalcHeaderCrc32(header);
    }

    static inline bool ValidateHeaderCrc32(UBSHcomNetTransHeader &header)
    {
        return header.headerCrc == CalcHeaderCrc32(header);
    }

    static inline NResult ValidateSeqNo(UBSHcomNetTransHeader &header, uint32_t lastSendSeqNo)
    {
        if (NN_UNLIKELY(header.seqNo != lastSendSeqNo)) {
            NN_LOG_ERROR("Received un-matched seq no " << header.seqNo << ", demand seq no "
                                                       << lastSendSeqNo);
            return NN_SEQ_NO_NOT_MATCHED;
        }

        return NN_OK;
    }

    static inline NResult ValidateHeader(UBSHcomNetTransHeader &header)
    {
        if (header.dataLength == 0 || header.dataLength > NET_SGE_MAX_SIZE) {
            NN_LOG_ERROR("Failed to validate header dataLength " << header.dataLength << " received");
            return NN_INVALID_PARAM;
        }

        if (NN_UNLIKELY(!ValidateHeaderCrc32(header))) {
            NN_LOG_ERROR("Failed to validate received header crc " << header.headerCrc);
            return NN_VALIDATE_HEADER_CRC_INVALID;
        }

        return NN_OK;
    }

    static inline NResult ValidateHeaderWithDataSize(UBSHcomNetTransHeader &header, uint32_t dataSize)
    {
        if (header.dataLength != (dataSize - sizeof(UBSHcomNetTransHeader))) {
            NN_LOG_ERROR("Failed to validate received dataLength " << header.dataLength << " in header, with dataSize "
                                                                   << dataSize);
            return NN_INVALID_PARAM;
        }

        return ValidateHeader(header);
    }

    static inline NResult ValidateHeaderWithSeqNo(UBSHcomNetTransHeader &header, uint32_t dataSize,
        uint32_t lastSendSeqNo)
    {
        NResult ret = ValidateSeqNo(header, lastSendSeqNo);
        if (ret != NN_OK) {
            return ret;
        }

        return ValidateHeaderWithDataSize(header, dataSize);
    }
    /*
     * @brief Safely close fd, if the fd is less than 0, no action
     * if fd >= 0, close it and assign to -1 atomically
     *
     * @param fd           [in] fd to be closed
     */
    static inline void NN_SafeCloseFd(int &fd)
    {
        if (NN_UNLIKELY(fd < 0)) {
            return;
        }

        auto tmpFd = fd;
        if (__sync_bool_compare_and_swap(&fd, tmpFd, INVALID_FD)) {
            close(tmpFd);
        }
    }

    static inline uint32_t GetIpByFd(int fd)
    {
        struct sockaddr_in addressIn {};
        addressIn.sin_addr.s_addr = INVALID_IP;
        socklen_t len = sizeof(addressIn);
        getsockname(fd, reinterpret_cast<struct sockaddr *>(&addressIn), &len); // UDS return INVALID_IP
        return addressIn.sin_addr.s_addr;
    }

    static inline uint32_t IpStringToUint32(const std::string &ip)
    {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
            return addr.s_addr;
        }
        NN_LOG_ERROR("Fail to change ip string to uint32_t, ip " << ip);
        return 0;
    }

    /*
     * @brief Round up one number to another
     */
    static inline uint64_t NN_RoundUpTo(uint64_t value, uint64_t align)
    {
        return ((value + align - 1) / align) * align;
    }

    /*
     * @brief Get next power of N, its index, instead of the final value
     */
    static inline uint64_t NN_PowerOfNIndex(uint64_t value, uint64_t align)
    {
        uint64_t tmp = (value + align - 1) / align;
        return tmp < NN_NO2 ? 0 : (NN_NO32 - __builtin_clz(tmp - 1));
    }

    /* NN_SplitStr */
    static void NN_SplitStr(const std::string &str, const std::string &separator, std::vector<std::string> &result)
    {
        result.clear();
        std::string::size_type pos1 = 0;
        std::string::size_type pos2 = str.find(separator);

        std::string tmpStr;
        while (pos2 != std::string::npos) {
            tmpStr = str.substr(pos1, pos2 - pos1);
            result.emplace_back(tmpStr);
            pos1 = pos2 + separator.size();
            pos2 = str.find(separator, pos1);
        }

        if (pos1 != str.length()) {
            tmpStr = str.substr(pos1);
            result.emplace_back(tmpStr);
        }
    }

    static void NN_VecStrToStr(const std::vector<std::string> &vec, const std::string &linkStr, std::string &result)
    {
        result.clear();
        for (const auto &item : vec) {
            if (NN_UNLIKELY(result.empty())) {
                result = item;
            } else {
                result += (linkStr + item);
            }
        }
    }

    static bool NN_Stol(const std::string &str, long &value)
    {
        char *remain = nullptr;
        errno = 0;
        value = std::strtol(str.c_str(), &remain, 10); // 10 is decimal digits
        if (remain == nullptr || strlen(remain) > 0 || ((value == LONG_MAX || value == LONG_MIN) && errno == ERANGE)) {
            return false;
        } else if (value == 0 && str != "0") {
            return false;
        }
        return true;
    }

    static bool NN_Stof(const std::string &str, float &value)
    {
        constexpr float epsinon = 0.000001;
        char *remain = nullptr;
        errno = 0;
        value = std::strtof(str.c_str(), &remain);
        if (remain == nullptr || strlen(remain) > 0 ||
            ((value - HUGE_VALF) >= -epsinon && (value - HUGE_VALF) <= epsinon && errno == ERANGE)) {
            return false;
        } else if ((value >= -epsinon && value <= epsinon) && (str != "0.0")) {
            return false;
        }
        return true;
    }

    static bool NN_CovertIpMask(const std::string &maskString, in_addr_t &ipByMask, in_addr_t &mask)
    {
        std::vector<std::string> ipMaskVec;
        NN_SplitStr(maskString, "/", ipMaskVec);
        if (ipMaskVec.size() != NN_NO2) {
            return false;
        }

        long maskWidth = 0;
        if (!NN_Stol(ipMaskVec[1], maskWidth)) {
            return false;
        }

        long maskOffset = NN_NO32 - maskWidth;
        if (maskOffset < 0 || maskOffset >= NN_NO32) {
            return false;
        }
        mask = static_cast<uint32_t>(0xFFFFFFFF >> maskOffset);

        auto tmp = inet_addr(ipMaskVec[0].c_str());
        if (tmp == INADDR_NONE) {
            return false;
        }

        ipByMask = tmp & mask;
        return true;
    }

    static bool NN_CovertIpWithoutPort(const std::string &ipPort, uint32_t &ip)
    {
        std::vector<std::string> ipPortVec;
        NN_SplitStr(ipPort, ":", ipPortVec);
        if (ipPortVec.size() != NN_NO2) {
            ipPortVec[0] = "999999";
        }

        auto tmp = inet_addr(ipPortVec[0].c_str());
        if (tmp == INADDR_NONE) {
            return false;
        }

        ip = tmp;
        return true;
    }

    static NResult NN_ValidateUrl(const std::string &name)
    {
        if (NN_UNLIKELY(name.length() > NN_NO100 || name.length() < NN_NO1)) {
            NN_LOG_WARN("Url length should be in 1-100");
            return NN_INVALID_PARAM;
        }
        for (char n : name) {
            if (NN_UNLIKELY((!std::isalnum(n)) &&
                            (n != '_' && n != '-' && n != '/' && n != '.' && n != ':'))) {
                NN_LOG_WARN("Url cannot contain illegal characters, only could contain alphabet, "
                            "number, -, _, ., :, /");
                return NN_INVALID_PARAM;
            }
        }
        return NN_OK;
    }

    static inline bool NN_IsUrmaEid(const std::string &s)
    {
        static const std::regex re("^([0-9a-fA-F]{4}:){7}[0-9a-fA-F]{4}$");
        bool isEid = std::regex_match(s, re);
        if (isEid) {
            NN_LOG_INFO("IP is Eid.");
        }
        return isEid;
    }
#ifdef UB_BUILD_ENABLED
    static NResult NN_EidToStr(uvs_eid_t &eid, std::string &strEid)
    {
        struct in6_addr eidIn6{};
        uint32_t size = sizeof(uint64_t); // size of uint64_t: 8
        memcpy_s(&eidIn6.s6_addr[0], size, &eid.in6.subnet_prefix, size);
        memcpy_s(&eidIn6.s6_addr[size], size, &eid.in6.interface_id, size);

        strEid.resize(INET6_ADDRSTRLEN);
        if (inet_ntop(AF_INET6, &eidIn6, &strEid[0], strEid.size()) == nullptr) {
            NN_LOG_ERROR("Failed to convert eid to string");
            return NN_INVALID_PARAM;
        }
        strEid.resize(strlen(strEid.c_str()));
        NN_LOG_INFO("Convert eid to string success.");

        return NN_OK;
    }

    static NResult NN_StrToEid(const std::string &strEid, uvs_eid_t &eid)
    {
        struct in6_addr eidIn6;
        uint32_t size = sizeof(uint64_t); // size of uint64_t: 8
        if (inet_pton(AF_INET6, strEid.c_str(), &eidIn6) != 1) {
            NN_LOG_ERROR("Failed to convert eid to in6_addr");
            return NN_INVALID_PARAM;
        }

        eid = {0};
        memcpy_s(&eid.in6.subnet_prefix, size, &eidIn6.s6_addr[0], size);
        memcpy_s(&eid.in6.interface_id, size, &eidIn6.s6_addr[size], size);
        NN_LOG_INFO("Convert string to eid success.");

        return NN_OK;
    }

    static NResult NN_GetPrimaryEid(const std::string &srcBondingEid, const std::string &dstBondingEid,
        std::string &srcPrimaryEid, std::string &dstPrimaryEid)
    {
        NN_LOG_DEBUG("srcBondingEid: " << srcBondingEid << ", dstBondingEid: " << dstBondingEid);
        uvs_route_t uvsRoute{};
        uvs_route_list_t uvsRouteList = {0};

        uvs_eid_t uSrcBondingEid = {0};
        uvs_eid_t uDstBondingEid = {0};
        NN_StrToEid(srcBondingEid, uSrcBondingEid);
        NN_StrToEid(dstBondingEid, uDstBondingEid);
        memcpy_s(&uvsRoute.src, sizeof(uvs_eid_t), &uSrcBondingEid, sizeof(uvs_eid_t));
        memcpy_s(&uvsRoute.dst, sizeof(uvs_eid_t), &uDstBondingEid, sizeof(uvs_eid_t));

        int ret = HcomTpsa::UvsGetRouteList(&uvsRoute, &uvsRouteList);
        if (ret != 0) {
            NN_LOG_ERROR("UvsGetRouteList failed, ret " << ret);
            return NN_INVALID_PARAM;
        }
        if (uvsRouteList.len == 0) {
            NN_LOG_WARN("UvsGetRouteList returned empty.");
            return NN_INVALID_PARAM;
        }

        uvs_eid_t uSrcPrimaryEid = {0};
        uvs_eid_t uDstPrimaryEid = {0};
        memcpy_s(&uSrcPrimaryEid, sizeof(uvs_eid_t), &uvsRouteList.buf[0].src, sizeof(uvs_eid_t));
        memcpy_s(&uDstPrimaryEid, sizeof(uvs_eid_t), &uvsRouteList.buf[0].dst, sizeof(uvs_eid_t));
        NN_EidToStr(uSrcPrimaryEid, srcPrimaryEid);
        NN_EidToStr(uDstPrimaryEid, dstPrimaryEid);

        NN_LOG_DEBUG("srcPrimaryEid_0: " << srcPrimaryEid << ", dstPrimaryEid_0: " << dstPrimaryEid);

        return NN_OK;
    }
#endif
    static bool NN_ConvertIpAndPort(const std::string &url, std::string &ip, uint16_t &port)
    {
        if (NN_UNLIKELY(NN_ValidateUrl(url) != NN_OK)) {
            NN_LOG_ERROR("Invalid url");
            return false;
        }
        std::string separator(":");
        std::string::size_type pos = url.find(separator);
        if (NN_UNLIKELY(pos == std::string::npos)) {
            NN_LOG_ERROR("invalid url: " << url << ", must be like 127.0.0.1:9981");
            return false;
        }

        // ipv6
        size_t colonCount = std::count(url.begin(), url.end(), ':');
        if (colonCount >= NN_NO2) {
            if (colonCount > NN_NO8) {
                NN_LOG_ERROR("Invalid IPv6 url, invalid num of ':'");
                return false;
            }

            if (url[0] == '[') {
                size_t closeBracket = url.find(']');
                if (NN_UNLIKELY(closeBracket == std::string::npos)) {
                    NN_LOG_ERROR("IPv6 address missing closing bracket ']'");
                    return false;
                }

                ip = url.substr(1, closeBracket - 1);
            } else {
                ip = url.substr(0, url.rfind(':'));
            }

            port = std::strtoul(url.substr(url.rfind(':') + 1).c_str(), nullptr, NN_NO10);
            if (NN_UNLIKELY(port == NN_NO0)) {
                NN_LOG_ERROR("Invalid port, url:" << url);
                return false;
            }
            return true;
        }

        // ipv4
        ip = url.substr(0, pos);
        port = std::strtoul(url.substr(pos + 1).c_str(), nullptr, NN_NO10);
        if (NN_UNLIKELY(port == NN_NO0)) {
            NN_LOG_ERROR("Invalid port, url:" << url);
            return false;
        }
        return true;
    }

    static bool NN_ConvertEidAndJettyId(const std::string &url, std::string &eid, uint16_t &jettyId)
    {
        std::vector<std::string> idVec;
        NN_SplitStr(url, ":", idVec);
        if (idVec.size() != NN_NO9 || url.length() <= NN_NO40) {
            return false;
        }

        eid = url.substr(0, NN_NO39);
        auto tmpId = std::strtoul(url.substr(NN_NO40, url.length()).c_str(), nullptr, NN_NO10);
        if (tmpId < NN_NO4 || tmpId > NN_NO1023) {
            NN_LOG_ERROR("Ensure the jetty id in range 4~1023");
            return false;
        }

        jettyId = tmpId;
        return true;
    }

    static bool NN_ConvertNameAndPerm(const std::string &url, std::string &name, uint16_t &perm)
    {
        if (NN_UNLIKELY(NN_ValidateUrl(url) != NN_OK)) {
            NN_LOG_ERROR("Invalid url");
            return false;
        }
        std::string separator(":");
        std::string::size_type pos = url.find(separator);
        if (NN_LIKELY(pos == std::string::npos)) {
            name = url;
            perm = 0;
            return true;
        }
        name = url.substr(0, pos);
        perm = std::strtoul(url.substr(pos + 1).c_str(), nullptr, NN_NO10);
        if (NN_UNLIKELY(perm == NN_NO0) || NN_UNLIKELY(perm == UINT16_MAX)) {
            NN_LOG_ERROR("Invalid perm, url:" << url);
            return false;
        }
        return true;
    }

    // protocal://url
    static bool NN_SplitProtoUrl(const std::string &protoUrl, NetProtocol &protocal, std::string &url)
    {
        std::string separator("://");
        std::string::size_type pos = protoUrl.find(separator);
        if (NN_UNLIKELY(pos == std::string::npos)) {
            NN_LOG_ERROR("Invalid url, must be like tcp://127.0.0.1:9981 or uds://name or ubc://eid:jettyId");
            return false;
        }

        std::string protoStr = protoUrl.substr(0, pos);
        if (protoStr == "tcp") {
            protocal = NetProtocol::NET_TCP;
        } else if (protoStr == "uds") {
            protocal = NetProtocol::NET_UDS;
        } else if (protoStr == "ubc") {
            protocal = NetProtocol::NET_UBC;
        } else {
            NN_LOG_ERROR("Unsupport url protocal");
            return false;
        }
        url = protoUrl.substr(pos + separator.size());
        return true;
    }

    static bool NN_CheckFilePrefix(std::string fileName)
    {
        char *envFilePrefixPath = ::getenv("HCOM_FILE_PATH_PREFIX");
        if (NN_UNLIKELY(envFilePrefixPath == nullptr)) {
            NN_LOG_ERROR("Check file prefix failed as env HCOM_FILE_PATH_PREFIX is not set");
            return false;
        }
        std::string filenamePrefix = fileName.substr(0, strlen(envFilePrefixPath));
        if (NN_UNLIKELY(filenamePrefix != envFilePrefixPath)) {
            NN_LOG_ERROR("Check file prefix failed as prefix does not match HCOM_FILE_PATH_PREFIX");
            return false;
        }
        return true;
    }
    /*
     * @brief Parse worker string to vector
     *
     * @param workerStr        [in] string format of workers
     * @param workerGroups     [out] vector of groups
     *
     * @return true if workStr is valid and convert successfully
     *
     * for example, workerStr is 1,3,3
     * output workerGroups will be [1,3,3] vector
     *
     * validations:
     * 1 the total count of group be less than 128
     * 2 if workerStr is empty, [1] vector will be the output
     * 3 each element is workerStr must be a digital
     * 4 each element is workerStr must be 1 to 128
     */
    static bool NN_ParseWorkersGroups(const std::string &workerStr, std::vector<uint16_t> &workerGroups)
    {
        std::vector<std::string> extractStrings;
        NN_SplitStr(workerStr, ",", extractStrings);

        NN_LOG_TRACE_INFO("worker str '" << workerStr << "', extract vector size " << extractStrings.size());
#ifdef NN_LOG_TRACE_INFO_ENABLED
        for (auto &item : extractStrings) {
            NN_LOG_TRACE_INFO("extracted item " << item);
        }
#endif

        /* if empty, make it to default, i.e. 1 group with 1 worker */
        if (workerStr.empty() || extractStrings.empty()) {
            workerGroups.clear();
            workerGroups.emplace_back(1);
            return true;
        } else if (extractStrings.size() > NN_NO128) {
            NN_LOG_ERROR("Invalid worker group setting '" << workerStr <<
                "', example '1,3,3' meaning that there are 3 groups, 1 worker in group0, 3 workers in group1 and 3 "
                "workers in group2. group size must be 1-128");
            return false;
        }

        /* validate worker config */
        long tmpCount = 0;
        workerGroups.reserve(extractStrings.size());
        for (auto &item : extractStrings) {
            if (NN_Stol(item, tmpCount) && tmpCount > 0 && tmpCount <= NN_NO128) {
                workerGroups.emplace_back(tmpCount);
                continue;
            }

            /* if invalid config group */
            NN_LOG_ERROR("Invalid worker group setting '" << workerStr <<
                "', example '1,3,3' meaning that there are 3 groups, 1 worker in group0, 3 workers in group1 and 3 "
                "workers in group2. worker size in each group must be 1-128");
            return false;
        }

        return true;
    }

    /*
     * @brief Parse cpu binding str to vector
     *
     * @param workerGroupCpusStr [in] cpu binding setting in string
     * @param workerGroupCpus    [out] output vector
     *
     * for example
     * - input: na,10-12,13-16
     * - output: [[128,0],[10,3],[13,4]]
     * -         first is start cpu id
     * -         second is cpu count
     *
     * validations:
     * 1 the total count of group be less than 128
     * 2 if workerGroupCpusStr is empty, [] vector will be the output
     * 3 each element is workerGroupCpusStr na/NA/digital-range
     */
    /* cpu id 用 uint32_t 保存。原来用 uint8_t：CPU 号 >=256 会被静默截断（绑到错的核），
       且 128 与 na 哨兵冲突。不绑核统一用 UINT32_MAX 作哨兵，与 inner options 的
       cpuIdsRange={UINT32_MAX, UINT32_MAX} 保持一致。 */
    static bool NN_ParseWorkerGroupsCpus(const std::string &workerGroupCpusStr,
        std::vector<std::pair<uint32_t, uint32_t>> &workerGroupCpus)
    {
        std::vector<std::string> extractStrings;
        NN_SplitStr(workerGroupCpusStr, ",", extractStrings);

        NN_LOG_TRACE_INFO("worker str '" << workerGroupCpusStr << "', extract vector size " << extractStrings.size());
#ifdef NN_LOG_TRACE_INFO_ENABLED
        for (auto &item : extractStrings) {
            NN_LOG_TRACE_INFO("extracted item " << item);
        }
#endif

        /* if empty */
        if (workerGroupCpusStr.empty() || extractStrings.empty()) {
            workerGroupCpus.clear();
            return true;
        } else if (extractStrings.size() > NN_NO128) {
            NN_LOG_ERROR("Invalid cpu id setting '" << workerGroupCpusStr <<
                "' for worker groups, example '10-10,11-13,na' meaning that 10 for group0, 11/12/13 for group1, no "
                "need to group2, each number must be 0-611, total group must less or equal to 128");
            return false;
        }

        /* validate */
        long tmpCpuIdStart = 0;
        long tmpCpuIdEnd = 0;
        std::vector<std::string> extractedCpuIds;
        extractedCpuIds.reserve(NN_NO4);
        workerGroupCpus.reserve(extractStrings.size());
        for (auto &item : extractStrings) {
            if (item == "na" || item == "NA") {
                workerGroupCpus.emplace_back(UINT32_MAX, 0); /* 哨兵：该组不绑核 */
                continue;
            }

            bool badConf = false;
            NN_SplitStr(item, "-", extractedCpuIds);

            /* size un-matched and invalid digital */
            if (extractedCpuIds.size() != NN_NO2) {
                badConf = true;
            } else if (!NN_Stol(extractedCpuIds[0], tmpCpuIdStart) || !NN_Stol(extractedCpuIds[1], tmpCpuIdEnd)) {
                badConf = true;
            } else if (tmpCpuIdStart < 0 || tmpCpuIdStart >= NN_NO612  || tmpCpuIdEnd < 0 || tmpCpuIdEnd >= NN_NO612) {
                badConf = true;
            } else if (tmpCpuIdStart > tmpCpuIdEnd) {
                badConf = true;
            }

            if (badConf) {
                NN_LOG_ERROR("Invalid cpu id setting '" << item << "' in '" << workerGroupCpusStr <<
                    "' for worker groups, example '10-10,11-13,na' meaning that 10 for group0, 11/12/13 for group1, no "
                    "need to group2, each number must be 0-611, total group must less or equal to 128");
                return false;
            }

            /* push the start index and count */
            workerGroupCpus.emplace_back(tmpCpuIdStart, tmpCpuIdEnd - tmpCpuIdStart + 1);
        }

        return true;
    }

    /*
     * @brief Finalize cpu binding setting
     *
     * @param workerGroups     [in] worker groups vector, for example [1,3,3]
     * @param workerGroupCpus  [in] cpu binding for worker groups, [[10,1], [11,3], [14,3]]
     * @param allowDuplicatedCpuIds [in] allow duplicated cpus id, for rdma busy polling is not allowed
     * @param flatWorkersCpus  [out] flat cpu id for workers
     *
     * @return true if ok
     */
    static bool NN_FinalizeWorkerGroupCpus(const std::vector<uint16_t> &workerGroups,
        const std::vector<std::pair<uint32_t, uint32_t>> &workerGroupCpus, bool allowDuplicatedCpuIds,
        std::vector<int16_t> &flatWorkersCpus)
    {
        if (workerGroups.empty() || workerGroups.size() < workerGroupCpus.size()) {
            NN_LOG_ERROR("Invalid worker groups which is empty or size of worker groups < cpu groups");
            return false;
        }

        /* count total workers */
        uint16_t totalWorkers = 0;
        for (auto item : workerGroups) {
            totalWorkers += item;
        }

        /* reserve and set to default -1 */
        flatWorkersCpus.reserve(totalWorkers);
        for (uint16_t i = 0; i < totalWorkers; ++i) {
            flatWorkersCpus.push_back(-1);
        }

        /* match and set cpus */
        uint16_t flatWorkerCpuIndex = 0;
        for (uint32_t i = 0; i < workerGroupCpus.size(); ++i) {
            auto &cpuPair = workerGroupCpus[i];
            auto workersInGroup = workerGroups[i];

            /* no need cpu bind（哨兵 UINT32_MAX） */
            if (cpuPair.first == UINT32_MAX) {
                flatWorkerCpuIndex += workersInGroup;
                continue;
            }

            /* invalid size */
            if (cpuPair.second > workersInGroup || (!allowDuplicatedCpuIds && cpuPair.second != workersInGroup)) {
                NN_LOG_ERROR("Invalid cpus group '" << cpuPair.first << ":" << cpuPair.second << "', the count " <<
                    cpuPair.second << " is larger than or not equal to workers number " << workersInGroup <<
                    " of group " << i);
                return false;
            }

            /* set */
            for (uint16_t j = 0; j < workersInGroup; j++) {
                flatWorkersCpus[flatWorkerCpuIndex + j] = static_cast<int16_t>(cpuPair.first + j % cpuPair.second);
            }

            /* move the index */
            flatWorkerCpuIndex += workersInGroup;
        }

        return true;
    }

    /*
     * @brief Parse worker group thread priority string to vector
     *
     * @param threadPriorityStr        [in] string format of workers thread priority
     * @param threadPriority     [out] vector of thread priority groups
     *
     * @return true if threadPriorityStr is valid and convert successfully
     *
     * for example, threadPriorityStr is -1,-10,na,9
     * output threadPriority will be [-1,-10,0,9] vector
     *
     * validations:
     * 1 the total count of thread priority be equal worker group count
     * 2 if threadPriorityStr is empty, null vector will be the output
     * 3 each element is threadPriorityStr must be a digital
     * 4 each element is threadPriorityStr must be -20 to 20
     */
    static bool NN_ParseWorkersGroupsThreadPriority(const std::string &threadPriorityStr,
        std::vector<int16_t> &threadPriority, int groupNum)
    {
        std::vector<std::string> extractStrings;
        NN_SplitStr(threadPriorityStr, ",", extractStrings);

        NN_LOG_TRACE_INFO("Worker group thread priority string '" << threadPriorityStr << "', extract vector size " <<
            threadPriority.size());
#ifdef NN_LOG_TRACE_INFO_ENABLED
        for (auto &item : extractStrings) {
            NN_LOG_TRACE_INFO("extracted item " << item);
        }
#endif

        /* if empty, make it to default, i.e. 1 group with 1 worker */
        if (threadPriorityStr.empty() || extractStrings.empty()) {
            threadPriority.clear();
            return true;
        } else if (static_cast<int>(extractStrings.size()) != groupNum) {
            NN_LOG_ERROR("Invalid worker group thread priority setting '" << threadPriorityStr <<
                "'. group size must be equal worker group number " << groupNum);
            return false;
        }

        /* validate worker config */
        long tmpCount = 0;
        threadPriority.reserve(extractStrings.size());
        for (auto &item : extractStrings) {
            if (strcmp(item.c_str(), "na") == 0) {
                threadPriority.emplace_back(0);
                continue;
            }
            if (NN_Stol(item, tmpCount) && tmpCount < NN_NO20 && tmpCount >= NN_NOF20) {
                threadPriority.emplace_back(tmpCount);
                continue;
            }

            /* if invalid config group */
            NN_LOG_ERROR("Invalid worker group thread priority setting '" << threadPriorityStr <<
                "', example '1,3,na,10' meaning that there are 4 groups, group0 set thread priority 1 , group1 set "
                "thread priority 3,group2 not set thread priority and group3 set thread priority 10"
                ". thread priority in each group must be -20~19");
            return false;
        }

        return true;
    }

    static long NN_GetLongEnv(const char *env, long min, long max, long defaultNum)
    {
        if (env == nullptr) {
            return defaultNum;
        }
        auto envString = getenv(env);
        auto result = defaultNum;
        if (envString != nullptr) {
            long tmp = 0;
            if (NetFunc::NN_Stol(envString, tmp) && tmp >= min && tmp <= max) {
                result = tmp;
            }
        }
        return result;
    }

    static char *NN_GetStrError(int errNum, char *buf, size_t bufSize)
    {
#if defined(_XOPEN_SOURCE) && defined(_POSIX_C_SOURCE) && defined(_GNU_SOURCE) && \
    (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
        strerror_r(errNum, buf, bufSize - 1);
        return buf;
#else
        return strerror_r(errNum, buf, bufSize - 1);
#endif
    }

    static NResult NN_ValidateName(const std::string &name)
    {
        if (NN_UNLIKELY(name.length() > NN_NO100 || name.length() < NN_NO1)) {
            NN_LOG_WARN("Service or Driver name length should be in 1-100");
            return NN_INVALID_PARAM;
        }
        for (char n : name) {
            if (NN_UNLIKELY((!std::isalnum(n)) && (n != '_' && n != '-'))) {
                NN_LOG_WARN("Service or Driver name cannot contain illegal characters, only could contain alphabet, "
                            "number, -, _");
                return NN_INVALID_PARAM;
            }
        }
        return NN_OK;
    }
};

class MemoryRegionChecker {
public:
    MemoryRegionChecker() = default;
    explicit MemoryRegionChecker(bool lockWhenOperates) : mLockWhenOperates(lockWhenOperates) {}

    inline NResult Validate(uint64_t key, uintptr_t address, uint64_t size)
    {
        if (NN_UNLIKELY(size == 0)) {
            NN_LOG_ERROR("size is 0");
            return NN_ERROR;
        }

        if (NN_UNLIKELY(mLockWhenOperates)) {
            pthread_rwlock_rdlock(&mRwlock);
        }
        if (NN_UNLIKELY(mRangeCache.count(key) == 0)) {
            NN_LOG_ERROR("LKey is Wrong " << key);
            if (NN_UNLIKELY(mLockWhenOperates)) {
                pthread_rwlock_unlock(&mRwlock);
            }
            return NN_ERROR;
        } else {
            auto range = mRangeCache[key];
            if (NN_UNLIKELY(mLockWhenOperates)) {
                pthread_rwlock_unlock(&mRwlock);
            }
            if (address >= range.first && address + size <= range.second) {
                return NN_OK;
            }
            NN_LOG_ERROR("Address does not match lKey, size:" << size);
            return NN_ERROR;
        }
    }

    inline bool Contains(uint64_t key)
    {
        pthread_rwlock_rdlock(&mRwlock);
        if (NN_UNLIKELY(mRangeCache.count(key) == 0)) {
            pthread_rwlock_unlock(&mRwlock);
            return false;
        } else {
            pthread_rwlock_unlock(&mRwlock);
            return true;
        }
    }

    inline NResult Register(uint64_t key, uintptr_t address, uint64_t size)
    {
        pthread_rwlock_wrlock(&mRwlock);
        if (NN_UNLIKELY(mRangeCache.count(key) > 0)) {
            pthread_rwlock_unlock(&mRwlock);
            return NN_ERROR;
        }
        mRangeCache[key] = {address, address + size};
        pthread_rwlock_unlock(&mRwlock);
        return NN_OK;
    }

    inline void UnRegister(uint64_t key)
    {
        pthread_rwlock_wrlock(&mRwlock);
        mRangeCache.erase(key);
        pthread_rwlock_unlock(&mRwlock);
    }

    inline void SetLockWhenOperates(bool shouldLock)
    {
        mLockWhenOperates = shouldLock;
    }

    inline void Reserve(uint32_t size)
    {
        mRangeCache.reserve(size);
    }

private:
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> mRangeCache;
    ::pthread_rwlock_t mRwlock {};
    bool mLockWhenOperates = false;
};

inline NResult FilterIp(const std::string &ipMask, std::vector<std::string> &outIps)
{
    in_addr_t mask = 0;
    in_addr_t inputIpByMask = 0;
    if (!NetFunc::NN_CovertIpMask(ipMask, inputIpByMask, mask)) {
        NN_LOG_ERROR("Ip mask is invalid " << ipMask <<
            ", should be something like '192.168.2.1/24', 24 means the left 24 bits will be "
            "the condition to compare");
        return NN_ERROR;
    }

    struct ifaddrs *addresses = nullptr;
    if (getifaddrs(&addresses) != 0) {
        NN_LOG_ERROR("Failed to get interface addresses");
        return NN_ERROR;
    }

    struct ifaddrs *iter = addresses;
    while (iter != nullptr) {
        if (iter->ifa_addr == nullptr ||
            iter->ifa_addr->sa_family != AF_INET ||
            ((reinterpret_cast<struct sockaddr_in *>(iter->ifa_addr))->sin_addr.s_addr & mask) != inputIpByMask) {
            iter = iter->ifa_next;
            continue;
        }

        char ipStr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &((reinterpret_cast<struct sockaddr_in *>(iter->ifa_addr))->sin_addr), ipStr,
            INET_ADDRSTRLEN);
        outIps.emplace_back(ipStr);

        iter = iter->ifa_next;
    }
    freeifaddrs(addresses);
    return NN_OK;
}

inline bool ValidateArrayOptions(const char *src, uint32_t srcLen)
{
    if (NN_UNLIKELY(src == nullptr) || NN_UNLIKELY(srcLen <= NN_NO0)) {
        return false;
    }
    for (uint32_t i = 0; i < srcLen; ++i) {
        if (src[i] == '\0') {
            return true;
        }
    }
    NN_LOG_ERROR("The array length is too long, it must less or equal to " << srcLen);
    return false;
}
}
}

#endif
