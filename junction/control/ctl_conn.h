#pragma once

#include <cstdlib>

#include "control_request_generated.h"
#include "control_response_generated.h"
#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/kernel/mm.h"

namespace {

constexpr size_t kBufSize = 1024;

}  // anonymous namespace

namespace junction {

class ControlConn {
 public:
  ControlConn(rt::TCPConn &&conn) : conn_(std::move(conn)) {
    Reserve(kBufSize);
  }

  // disable copy
  ControlConn(const ControlConn &c) = delete;
  ControlConn &operator=(const ControlConn &c) = delete;

  // disable move
  ControlConn(ControlConn &&c) noexcept = delete;
  ControlConn &operator=(ControlConn &&c) noexcept = delete;

  // destructor
  ~ControlConn() = default;

  // get the request in the connection
  const ctl_schema::Request *Get() const { return request_; }

  inline static constexpr size_t kPrefixSize = sizeof(flatbuffers::uoffset_t);

  // read from the TCP connection and get the next stream
  // return true if there is a next request
  // return false if the connection is closed
  Status<void> Recv() {
    Reset();
    Status<void> ret = ReadFull(conn_, {buf_.data(), kPrefixSize});
    if (!ret) return ret;
    flatbuffers::uoffset_t msg_size =
        flatbuffers::GetPrefixedSize(reinterpret_cast<uint8_t *>(buf_.data()));
    Reserve(msg_size + kPrefixSize);
    ret = ReadFull(conn_, {buf_.data() + kPrefixSize, msg_size});
    if (!ret) return ret;
    request_ = ctl_schema::GetSizePrefixedRequest(buf_.data());
    return {};
  }

  Status<void> SendSuccess() {
    flatbuffers::FlatBufferBuilder fbb;
    auto inner = ctl_schema::CreateSuccessResponse(fbb);
    auto resp = ctl_schema::CreateResponse(
        fbb, ctl_schema::InnerResponse_genericSuccess, inner.Union());
    fbb.FinishSizePrefixed(resp);
    return Send(std::move(fbb));
  }

  Status<void> SendStats() {
    flatbuffers::FlatBufferBuilder fbb;
    auto inner = ctl_schema::CreateGetStatsResponse(fbb);
    auto resp = ctl_schema::CreateResponse(
        fbb, ctl_schema::InnerResponse_getStats, inner.Union());
    fbb.FinishSizePrefixed(resp);
    return Send(std::move(fbb));
  }

  Status<void> SendReport(const TracerReport &report) {
    flatbuffers::FlatBufferBuilder fbb;
    std::vector<flatbuffers::Offset<ctl_schema::TracePoint>> std_accessed;
    std_accessed.reserve(report.accesses_us.size());
    for (const auto &[time_us, page_addr] : report.accesses_us)
      std_accessed.emplace_back(
          ctl_schema::CreateTracePoint(fbb, time_us, page_addr));
    auto inner = ctl_schema::CreateTraceReportDirect(fbb, &std_accessed);
    auto resp = ctl_schema::CreateResponse(
        fbb, ctl_schema::InnerResponse_traceReport, inner.Union());
    fbb.FinishSizePrefixed(resp);
    return Send(std::move(fbb));
  }

  Status<void> SendError(std::string_view message) {
    flatbuffers::FlatBufferBuilder fbb;
    auto msg = fbb.CreateString(message);
    auto inner = ctl_schema::CreateErrorResponse(fbb, msg);
    auto resp = ctl_schema::CreateResponse(fbb, ctl_schema::InnerResponse_error,
                                           inner.Union());
    fbb.FinishSizePrefixed(resp);
    return Send(std::move(fbb));
  }

 private:
  void Reset() { request_ = nullptr; }
  void Reserve(size_t new_cap) { buf_.reserve(new_cap); }

  Status<void> Send(flatbuffers::FlatBufferBuilder &&fbb) {
    return WriteFull(
        conn_,
        writable_span(reinterpret_cast<const char *>(fbb.GetBufferPointer()),
                      fbb.GetSize()));
  }

  rt::TCPConn conn_;
  std::vector<std::byte> buf_;

  ctl_schema::Request const *request_{nullptr};
};

}  // namespace junction
