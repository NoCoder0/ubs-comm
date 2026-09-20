// SPDX-License-Identifier: MulanPSL-2.0
#ifndef HCOM_RDMA_TRACE_H
#define HCOM_RDMA_TRACE_H

#include <atomic>
#include <cstdint>

namespace ock {
namespace hcom {

// Optional, process-local diagnostic hooks. Install before starting workers and
// remove only after they have joined. No hooks, clocks or allocations by default.
enum class UBSHcomRdmaTraceKind : uint32_t {
    POST_BEGIN, POST_END, CQ_POLL_BATCH, CQE_OBSERVED, CQ_DISPATCH_BEGIN, CQ_DISPATCH_END,
    DATA_CALLBACK_BEGIN, DATA_CALLBACK_END, NOTIFY_INCOMING, NOTIFY_HANDLER_BEGIN,
    NOTIFY_DECODED, NOTIFY_READY_PUBLISHED
};

struct UBSHcomRdmaTraceEvent {
    UBSHcomRdmaTraceKind kind;
    uint64_t epoch; // caller-defined capture window (benchmark case index)
    uint64_t timestampNs;
    uint64_t generation;
    int32_t rail;
    int32_t chunk;
    uint64_t wrId;
    uint64_t cqId;
    uint64_t batchId; // unique within the polling thread, not globally
    uint32_t qpNum;
    uint32_t opcode; // WR opcode for POST, WC opcode for CQ events
    int32_t status;
    uint32_t count;
    uint32_t sgeCount;
    uint64_t bytes;
    uint64_t pollBeginNs;
    uint64_t previousPollEndNs;
    uint64_t emptyPolls;
    uint64_t maxPollGapNs;
    uint64_t maxPollCallNs;
    uint64_t localAddress; // first SGE, POST events only
    uint64_t remoteAddress; // POST events only
};

struct UBSHcomRdmaTraceHooks {
    uint64_t (*epoch)(); // zero disables capture, including timestamp reads
    void (*record)(const UBSHcomRdmaTraceEvent &);
};

extern std::atomic<const UBSHcomRdmaTraceHooks *> gUBSHcomRdmaTraceHooks;
inline uint64_t UBSHcomRdmaTraceEpoch() noexcept
{
    const auto *hooks = gUBSHcomRdmaTraceHooks.load(std::memory_order_acquire);
    return hooks == nullptr ? 0 : hooks->epoch();
}
void UBSHcomRdmaTraceConfigure(const UBSHcomRdmaTraceHooks *hooks) noexcept;
uint64_t UBSHcomRdmaTraceNow() noexcept;
void UBSHcomRdmaTracePost(uint64_t epoch, uint64_t begin, uint64_t end, uint32_t qp,
    uint64_t wr, uint32_t opcode, uint32_t sges, uint64_t bytes, int status,
    uint64_t localAddress = 0, uint64_t remoteAddress = 0) noexcept;
void UBSHcomRdmaTracePoll(uint64_t epoch, uint64_t begin, uint64_t end,
    uint64_t cq, int count) noexcept;
void UBSHcomRdmaTraceCqe(uint64_t wr, uint32_t qp, uint32_t opcode, int status) noexcept;
void UBSHcomRdmaTraceMark(UBSHcomRdmaTraceKind kind, uint64_t generation,
    int32_t rail, int32_t chunk = -1) noexcept;

class UBSHcomRdmaTraceOperationScope {
public:
    UBSHcomRdmaTraceOperationScope(bool enabled, uint64_t generation, int32_t rail, int32_t chunk) noexcept;
    ~UBSHcomRdmaTraceOperationScope();
    UBSHcomRdmaTraceOperationScope(const UBSHcomRdmaTraceOperationScope &) = delete;
    UBSHcomRdmaTraceOperationScope &operator=(const UBSHcomRdmaTraceOperationScope &) = delete;
private:
    bool mEnabled;
    uint64_t mGeneration = 0;
    int32_t mRail = -1, mChunk = -1;
};

class UBSHcomRdmaTraceDispatchScope {
public:
    UBSHcomRdmaTraceDispatchScope(uint64_t wr, uint32_t qp, uint32_t opcode, int status) noexcept : mActive(false)
    {
        const uint64_t epoch = UBSHcomRdmaTraceEpoch();
        if (epoch != 0) Start(epoch, wr, qp, opcode, status);
    }
    ~UBSHcomRdmaTraceDispatchScope() { if (mActive) Stop(); }
    UBSHcomRdmaTraceDispatchScope(const UBSHcomRdmaTraceDispatchScope &) = delete;
    UBSHcomRdmaTraceDispatchScope &operator=(const UBSHcomRdmaTraceDispatchScope &) = delete;
private:
    void Start(uint64_t epoch, uint64_t wr, uint32_t qp, uint32_t opcode, int status) noexcept;
    void Stop() noexcept;
    bool mActive;
    // POD storage is left untouched on the disabled (measure/verify) path.
    UBSHcomRdmaTraceEvent mEvent;
    UBSHcomRdmaTraceEvent mPrevious;
};

} // namespace hcom
} // namespace ock
// Versioned unmangled entry for consumers that load libhcom.so dynamically.
// Install before workers start; uninstall only after every worker has joined.
extern "C" __attribute__((visibility("default"))) int UBSHcomRdmaTraceConfigureV1(
    const ock::hcom::UBSHcomRdmaTraceHooks *hooks, uint32_t eventSize) noexcept;
#endif
