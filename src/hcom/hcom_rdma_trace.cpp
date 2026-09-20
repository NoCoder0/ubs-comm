// SPDX-License-Identifier: MulanPSL-2.0
#include "hcom_rdma_trace.h"
#include <algorithm>
#include <time.h>

namespace ock {
namespace hcom {
std::atomic<const UBSHcomRdmaTraceHooks *> gUBSHcomRdmaTraceHooks{nullptr};
namespace {
struct ThreadTrace {
    uint64_t generation = 0;
    int32_t rail = -1, chunk = -1;
    uint64_t epoch = 0, sequence = 0, previousPollEnd = 0;
    uint64_t emptyPolls = 0, maxGap = 0, maxCall = 0;
    UBSHcomRdmaTraceEvent batch{}, completion{};
};
thread_local ThreadTrace trace;

void Record(const UBSHcomRdmaTraceEvent &event) noexcept
{
    const auto *hooks = gUBSHcomRdmaTraceHooks.load(std::memory_order_acquire);
    if (hooks != nullptr && event.epoch != 0) hooks->record(event);
}
} // namespace

void UBSHcomRdmaTraceConfigure(const UBSHcomRdmaTraceHooks *hooks) noexcept
{
    gUBSHcomRdmaTraceHooks.store(hooks, std::memory_order_release);
}

uint64_t UBSHcomRdmaTraceNow() noexcept
{
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) return 0;
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

UBSHcomRdmaTraceOperationScope::UBSHcomRdmaTraceOperationScope(bool enabled,
    uint64_t generation, int32_t rail, int32_t chunk) noexcept : mEnabled(enabled)
{
    if (!enabled) return;
    mGeneration = trace.generation; mRail = trace.rail; mChunk = trace.chunk;
    trace.generation = generation; trace.rail = rail; trace.chunk = chunk;
}
UBSHcomRdmaTraceOperationScope::~UBSHcomRdmaTraceOperationScope()
{
    if (!mEnabled) return;
    trace.generation = mGeneration; trace.rail = mRail; trace.chunk = mChunk;
}

void UBSHcomRdmaTracePost(uint64_t epoch, uint64_t begin, uint64_t end, uint32_t qp,
    uint64_t wr, uint32_t opcode, uint32_t sges, uint64_t bytes, int status) noexcept
{
    UBSHcomRdmaTraceEvent event{};
    event.epoch = epoch; event.generation = trace.generation;
    event.rail = trace.rail; event.chunk = trace.chunk;
    event.qpNum = qp; event.wrId = wr; event.opcode = opcode;
    event.sgeCount = sges; event.bytes = bytes; event.status = status;
    event.kind = UBSHcomRdmaTraceKind::POST_BEGIN; event.timestampNs = begin;
    Record(event);
    event.kind = UBSHcomRdmaTraceKind::POST_END; event.timestampNs = end;
    Record(event);
}

void UBSHcomRdmaTracePoll(uint64_t epoch, uint64_t begin, uint64_t end,
    uint64_t cq, int count) noexcept
{
    if (trace.epoch != epoch) {
        trace.epoch = epoch; trace.previousPollEnd = 0;
        trace.emptyPolls = trace.maxGap = trace.maxCall = 0;
    }
    const uint64_t previous = trace.previousPollEnd;
    if (previous != 0 && begin >= previous) trace.maxGap = std::max(trace.maxGap, begin - previous);
    if (end >= begin) trace.maxCall = std::max(trace.maxCall, end - begin);
    trace.previousPollEnd = end;
    if (count == 0) { ++trace.emptyPolls; return; }
    UBSHcomRdmaTraceEvent event{};
    event.rail = -1; event.chunk = -1;
    event.kind = UBSHcomRdmaTraceKind::CQ_POLL_BATCH;
    event.epoch = epoch; event.timestampNs = end; event.pollBeginNs = begin;
    event.previousPollEndNs = previous; event.cqId = cq; event.batchId = ++trace.sequence;
    event.count = count > 0 ? static_cast<uint32_t>(count) : 0;
    event.status = count < 0 ? count : 0;
    event.emptyPolls = trace.emptyPolls; event.maxPollGapNs = trace.maxGap;
    event.maxPollCallNs = trace.maxCall;
    trace.batch = event;
    Record(event);
    trace.emptyPolls = trace.maxGap = trace.maxCall = 0;
}

void UBSHcomRdmaTraceCqe(uint64_t wr, uint32_t qp, uint32_t opcode, int status) noexcept
{
    UBSHcomRdmaTraceEvent event = trace.batch;
    event.kind = UBSHcomRdmaTraceKind::CQE_OBSERVED;
    event.wrId = wr; event.qpNum = qp; event.opcode = opcode; event.status = status;
    Record(event); // every WC from one poll has the same observation timestamp
}

void UBSHcomRdmaTraceDispatchScope::Start(uint64_t epoch, uint64_t wr,
    uint32_t qp, uint32_t opcode, int status) noexcept
{
    if (trace.batch.epoch != epoch) return;
    mActive = true;
    mPrevious = trace.completion;
    mEvent = trace.batch;
    mEvent.kind = UBSHcomRdmaTraceKind::CQ_DISPATCH_BEGIN;
    mEvent.timestampNs = UBSHcomRdmaTraceNow();
    mEvent.wrId = wr; mEvent.qpNum = qp; mEvent.opcode = opcode; mEvent.status = status;
    trace.completion = mEvent;
    Record(mEvent);
}
void UBSHcomRdmaTraceDispatchScope::Stop() noexcept
{
    mEvent.kind = UBSHcomRdmaTraceKind::CQ_DISPATCH_END;
    mEvent.timestampNs = UBSHcomRdmaTraceNow();
    Record(mEvent);
    trace.completion = mPrevious;
}

void UBSHcomRdmaTraceMark(UBSHcomRdmaTraceKind kind, uint64_t generation,
    int32_t rail, int32_t chunk) noexcept
{
    const uint64_t epoch = UBSHcomRdmaTraceEpoch();
    if (epoch == 0) return;
    UBSHcomRdmaTraceEvent event = trace.completion;
    event.epoch = epoch; event.kind = kind; event.timestampNs = UBSHcomRdmaTraceNow();
    event.generation = generation; event.rail = rail; event.chunk = chunk;
    Record(event);
}
} // namespace hcom
} // namespace ock
