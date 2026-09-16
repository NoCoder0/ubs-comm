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

#include <cstdio>
#include <cstdlib>
#include <string>

#include "trace/htracer.h"
#include "htracer_manager.h"
#include "htracer_service.h"
#include "htracer_service_helper.h"

namespace ock {
namespace hcom {

static HTracerService *g_traceService = nullptr;
#ifdef HTRACER_ENABLED
bool TraceManager::mEnable = true;
#else
bool TraceManager::mEnable = false;
#endif

bool TraceManager::mLatencyQuantileEnable = false;

std::string TraceManager::mDumpDir = "";
std::string TraceManager::mDefaultDir = "/tmp/htrace/log";
bool TraceManager::mDumpEnable = false;
static bool HtraceEnable();
static void DumpTraceSummaryOnExit();

HTRACE_INTF g_htraceIntf = {HtraceEnable, NULL, NULL, NULL, NULL};
static bool g_htraceInit = false;

static bool HtraceEnable()
{
    return TraceManager::IsEnable() && g_htraceInit;
}

static void HtracerRegisterInterface(void)
{
    g_htraceIntf.DelayBegin = &TraceManager::DelayBegin;
    g_htraceIntf.AsyncDelayBegin = &TraceManager::AsyncDelayBegin;
    g_htraceIntf.DelayEnd = &TraceManager::DelayEnd;
    g_htraceIntf.GetCurrentTimeNs = &TraceManager::GetTimeNs;
}

int32_t HTracerInit(const std::string &serverName)
{
    if (g_traceService != nullptr) {
        return SER_OK;
    }

    HtracerRegisterInterface();

    g_traceService = new (std::nothrow) HTracerService();
    if (g_traceService == nullptr) {
        NN_LOG_WARN("[HTRACER] failed to malloc g_traceService");
        return SER_ERROR;
    }
    g_traceService->StartUp(serverName);

    auto ins = TraceManager::Instance();
    if (ins == nullptr) {
        NN_LOG_WARN("[HTRACER] init trace manager instance failed");
        g_traceService->ShutDown();
        delete g_traceService;
        g_traceService = nullptr;
        return SER_ERROR;
    }
    g_htraceInit = true;
    /* 兜底：进程退出时也汇总一次（正常路径由 driver destroy 的 HTracerExit 触发） */
    (void)std::atexit(DumpTraceSummaryOnExit);
    return SER_OK;
}

void HTracerExit(void)
{
    if (g_htraceInit) {
        /* 退出（driver destroy）时把本次 trace 汇总打印一次，避免必须用 CLI 在进程存活期间查询 */
        DumpTraceSummaryOnExit();
    }
    if (g_traceService != nullptr) {
        g_traceService->ShutDown();
        delete g_traceService;
        g_traceService = nullptr;
    }
    g_htraceInit = false;
}

/*!
 * 打印本次 trace 的汇总（每个 trace point 一行，时间单位 us），只在第一次调用时有输出。
 * 只在 tracing 打开（HCOM_ENABLE_TRACE 非 0）时有输出；分位数需先用 CLI 的 'conf -p 1' 打开，否则显示 OFF。
 */
static void DumpTraceSummaryOnExit()
{
    static bool dumped = false;
    if (dumped || !g_htraceInit || !TraceManager::IsEnable()) {
        return;
    }
    dumped = true;

    constexpr double TRACE_EXIT_DUMP_QUANTILE = 0.99;
    auto traceInfos = TracerServiceHelper::GetTraceInfos(INVALID_SERVICE_ID, TRACE_EXIT_DUMP_QUANTILE,
        TraceManager::IsLatencyQuantileEnable());
    if (traceInfos.empty()) {
        return;
    }

    std::string summary = "[HTRACER] trace summary:\n" + TTraceInfo::HeaderString() + "\n";
    for (const auto &traceInfo : traceInfos) {
        summary += "\t" + traceInfo.ToString() + "\n";
    }
    printf("%s", summary.c_str());
}

void EnableHtrace(bool enableTrace)
{
    TraceManager::SetEnable(enableTrace);
}

}
}