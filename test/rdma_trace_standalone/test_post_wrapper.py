#!/usr/bin/env python3
# SPDX-License-Identifier: MulanPSL-2.0
"""Compile the actual TracePostSend method against a fake verbs API, without a NIC."""

import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
header = (root / "src/hcom/transport/rdma/verbs/rdma_verbs_wrapper_qp.h").read_text(encoding="utf-8")
begin = header.index("    inline int TracePostSend(")
end = header.index("    inline RResult PostSend(", begin)
method = header[begin:end]
prefix = r"""
#include "hcom_rdma_trace.h"
#include <cassert>
#include <vector>
using namespace ock::hcom;
enum { IBV_WR_RDMA_WRITE=0, IBV_WR_RDMA_READ=4, IBV_WR_SEND_WITH_IMM=3 };
struct ibv_sge { uint64_t addr; uint32_t length; };
struct ibv_send_wr { uint64_t wr_id; int opcode, num_sge; ibv_sge *sg_list;
    ibv_send_wr *next; uint32_t send_flags; struct { struct {uint64_t remote_addr;} rdma;} wr; };
struct ibv_qp { uint32_t qp_num; };
int result=0, calls=0; ibv_send_wr *reject=nullptr;
int ibv_post_send(ibv_qp *, ibv_send_wr *, ibv_send_wr **bad) { ++calls; *bad=reject; return result; }
uint64_t epoch=0;
uint64_t Epoch() { return epoch; }
std::vector<UBSHcomRdmaTraceEvent> records;
void Record(const UBSHcomRdmaTraceEvent &e) { records.push_back(e); }
const UBSHcomRdmaTraceHooks hooks{Epoch,Record};
struct Wrapper { ibv_qp *mQP;
"""
suffix = r"""
};
int main() {
  ibv_qp qp{17}; Wrapper wrapper{&qp};
  ibv_sge sg[2]={{0x100,10},{0x200,20}};
  ibv_send_wr wr[2]{}; ibv_send_wr *bad=nullptr;
  for (int i=0;i<2;++i) { wr[i].wr_id=55+i; wr[i].opcode=IBV_WR_RDMA_WRITE;
    wr[i].num_sge=2; wr[i].sg_list=sg; wr[i].send_flags=2; wr[i].wr.rdma.remote_addr=0x300; }
  wr[0].next=&wr[1];
  UBSHcomRdmaTraceConfigure(&hooks);
  assert(wrapper.TracePostSend(wr,&bad)==0 && calls==1 && records.empty());
  epoch=1;
  assert(wrapper.TracePostSend(wr,&bad)==0 && records.size()==4);
  assert(records[0].bytes==30 && records[0].sgeCount==2 && records[0].sendFlags==2);
  assert(records[0].remoteAddress==0x300 && records[0].localAddress==0x100);
  assert(records[0].timestampNs==records[2].timestampNs && records[1].timestampNs==records[3].timestampNs);
  records.clear(); result=12; reject=&wr[1];
  assert(wrapper.TracePostSend(wr,&bad)==12 && bad==&wr[1]);
  assert(records[0].status==0 && records[0].postCallStatus==12 && records[2].status==12);
  records.clear(); reject=nullptr;
  wrapper.TracePostSend(wr,&bad);
  assert(records[0].status==12 && records[2].status==12);
  records.clear(); result=0; wr[0].next=nullptr; wr[0].opcode=IBV_WR_SEND_WITH_IMM; wr[0].send_flags=10;
  wrapper.TracePostSend(wr,&bad);
  assert(records[0].remoteAddress==0 && records[0].sendFlags==10 && records[0].bytes==30);
  UBSHcomRdmaTraceConfigure(nullptr);
}
"""
with tempfile.TemporaryDirectory(prefix="hcom-post-contract-") as directory:
    source = Path(directory) / "test.cpp"
    source.write_text(prefix + method + suffix)
    binary = Path(directory) / ("test.exe" if os.name == "nt" else "test")
    args = [
        os.environ.get("CXX", "g++"),
        "-std=c++11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I" + str(root / "src/hcom"),
        str(source),
        str(root / "src/hcom/hcom_rdma_trace.cpp"),
        "-o",
        str(binary),
    ]
    if os.name == "nt":
        args.insert(1, "-DCLOCK_MONOTONIC_RAW=CLOCK_MONOTONIC")
    subprocess.run(args, check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: actual post wrapper, disabled path, linked WRs, flags, addresses and partial errors (fake verbs)")
