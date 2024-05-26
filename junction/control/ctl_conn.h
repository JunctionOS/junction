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

  // allow move
  ControlConn(ControlConn &&c) noexcept
      : conn_(std::move(c.conn_)),
        len_(c.len_),
        buf_(std::move(c.buf_)),
        request_(c.request_) {
    c.request_ = nullptr;
  }

  ControlConn &operator=(ControlConn &&c) noexcept {
    conn_ = std::move(c.conn_);
    len_ = c.len_;
    buf_ = std::move(c.buf_);
    request_ = c.request_;
    c.request_ = nullptr;
    return *this;
  }

  // destructor
  ~ControlConn() = default;

  // get the request in the connection
  const ctl_schema::Request *Get() const { return request_; }

  // read from the TCP connection and get the next stream
  // return true if there is a next request
  // return false if the connection is closed
  Status<void> Recv() {
    Reset();
    uint32_t total_message_size = 0;  // 0 == unknown
    while (true) {
      if (total_message_size != 0) Reserve(total_message_size);

      size_t to_read = total_message_size == 0 ? buf_.capacity() - len_
                                               : total_message_size - len_;
      Status<size_t> ret = conn_.Read(
          readable_span(reinterpret_cast<char *>(buf_.data() + len_), to_read));
      if (!ret)
        return MakeError(ret);
      else if (*ret == 0)
        return MakeError(EPIPE);

      len_ += *ret;

      if (total_message_size == 0) {
        total_message_size = flatbuffers::GetSizePrefixedBufferLength(
            reinterpret_cast<const uint8_t *const>(buf_.data()));
      }

      if (len_ > 0 && len_ == total_message_size) {
        break;
      }
    }

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
    for (const auto &[time_us, page_addr, str] : report.accesses_us)
      std_accessed.emplace_back(ctl_schema::CreateTracePointDirect(
          fbb, time_us, page_addr, str.c_str()));
    auto inner = ctl_schema::CreateTraceReportDirect(
        fbb, report.total_pages, report.non_zero_pages, &std_accessed);
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
  void Reset() {
    len_ = 0;
    request_ = nullptr;
  }
  void Reserve(size_t new_cap) { buf_.reserve(new_cap); }

  Status<void> Send(flatbuffers::FlatBufferBuilder &&fbb) {
    return WriteFull(
        conn_,
        writable_span(reinterpret_cast<const char *>(fbb.GetBufferPointer()),
                      fbb.GetSize()));
  }

  rt::TCPConn conn_;
  size_t len_{0};
  std::vector<std::byte> buf_;

  ctl_schema::Request const *request_{nullptr};
};

}  // namespace junction
