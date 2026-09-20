// SPDX-License-Identifier: MulanPSL-2.0
// No NIC or HCOM service needed: compile with src/hcom/hcom_rdma_trace.cpp.
#include "hcom_rdma_trace.h"
#include <cassert>
#include <vector>

using namespace ock::hcom;
namespace {
uint64_t epoch = 0;
std::vector<UBSHcomRdmaTraceEvent> events;
uint64_t Epoch() { return epoch; }
void Record(const UBSHcomRdmaTraceEvent &event) { events.push_back(event); }
}

int main()
{
    const UBSHcomRdmaTraceHooks hooks{Epoch, Record};
    assert(UBSHcomRdmaTraceConfigureV1(&hooks, sizeof(UBSHcomRdmaTraceEvent) - 1) != 0);
    assert(UBSHcomRdmaTraceEpoch() == 0);
    assert(UBSHcomRdmaTraceConfigureV1(&hooks, sizeof(UBSHcomRdmaTraceEvent)) == 0);
    UBSHcomRdmaTraceMark(UBSHcomRdmaTraceKind::NOTIFY_INCOMING, 1, 0);
    assert(events.empty()); // installed but inactive: no record
    epoch = 7;
    UBSHcomRdmaTracePost(epoch, 100, 160, 42, 99, 0, 16, 10496, 0, 0x1000, 0x2000);
    assert(events.size() == 2 && events[0].timestampNs == 100 && events[1].timestampNs == 160);
    assert(events[0].sgeCount == 16 && events[0].bytes == 10496 && events[0].remoteAddress == 0x2000);
    UBSHcomRdmaTracePoll(epoch, 180, 190, 5, 0);
    UBSHcomRdmaTracePoll(epoch, 220, 230, 5, 0);
    UBSHcomRdmaTracePoll(epoch, 250, 270, 5, 2);
    const auto batch = events.back();
    assert(batch.emptyPolls == 2 && batch.maxPollGapNs == 30 && batch.maxPollCallNs == 20);
    UBSHcomRdmaTraceCqe(99, 42, 1, 0);
    UBSHcomRdmaTraceCqe(100, 42, 1, 0);
    assert(events.back().timestampNs == 270 && events.back().batchId == batch.batchId);
    {
        UBSHcomRdmaTraceDispatchScope scope(99, 42, 1, 0);
        epoch = 0; // end of capture while a dispatch is still in flight
    }
    assert(events.back().kind == UBSHcomRdmaTraceKind::CQ_DISPATCH_END && events.back().epoch == 7);
    epoch = 8;
    UBSHcomRdmaTracePoll(epoch, 300, 310, 5, 1);
    assert(events.back().emptyPolls == 0 && events.back().previousPollEndNs == 0);
    assert(UBSHcomRdmaTraceConfigureV1(nullptr, sizeof(UBSHcomRdmaTraceEvent)) == 0);
    assert(UBSHcomRdmaTraceEpoch() == 0);
    return 0;
}
