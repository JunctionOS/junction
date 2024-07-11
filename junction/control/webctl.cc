#include <charconv>

#include "junction/base/string.h"
#include "junction/bindings/log.h"
#include "junction/bindings/net.h"
#include "junction/bindings/thread.h"
#include "junction/control/ctl_conn.h"
#include "junction/kernel/proc.h"
#include "junction/run.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

bool HandleRun(ControlConn &c, const ctl_schema::RunRequest *req) {
  LOG(INFO) << "handling run request";

  const auto argc = req->argv()->size();
  if (argc == 0) {
    std::ostringstream error_msg;
    error_msg << "failed to run: empty argv";
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  const auto fb_argv = req->argv();

  std::vector<std::string_view> argv;
  argv.reserve(argc);

  for (size_t idx = 0; idx < argc; idx += 1) {
    argv.push_back(fb_argv->Get(idx)->string_view());
  }

  // Initialize environment and arguments
  auto [envp_s, envp_view] = BuildEnvp();
  auto proc = CreateFirstProcess(argv[0], argv, envp_view);
  if (!proc) {
    std::ostringstream error_msg;
    error_msg << "failed to run(";

    size_t idx = 0;
    for (; idx < argc - 1; idx++) {
      error_msg << argv[idx] << ", ";
    }
    error_msg << argv[idx] << "): " << proc.error();
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  if (!c.SendSuccess()) {
    LOG(WARN) << "ctl: failed to send success";
    return true;
  }

  return false;
}
bool HandleSnapshot(ControlConn &c, const ctl_schema::SnapshotRequest *req) {
  LOG(INFO) << "handling snapshot request";
  auto ret =
      GetCfg().jif()
          ? SnapshotPidToJIF(req->pid(), req->snapshot_path()->string_view(),
                             req->elf_path()->string_view())
          : SnapshotPidToELF(req->pid(), req->snapshot_path()->string_view(),
                             req->elf_path()->string_view());

  if (!ret) {
    std::ostringstream error_msg;
    error_msg << "failed to snapshot(pid=" << req->pid()
              << ", jif_path=" << req->snapshot_path()->string_view()
              << "): " << ret.error();
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  if (!c.SendSuccess()) {
    LOG(WARN) << "ctl: failed to send success";
    return true;
  }

  return false;
}
bool HandleRestore(ControlConn &c, const ctl_schema::RestoreRequest *req) {
  LOG(INFO) << "handling restore request";
  Status<std::shared_ptr<Process>> proc =
      GetCfg().jif()
          ? RestoreProcessFromJIF(req->snapshot_path()->string_view(),
                                  req->elf_path()->string_view())
          : RestoreProcessFromELF(req->snapshot_path()->string_view(),
                                  req->elf_path()->string_view());

  if (!proc) {
    std::ostringstream error_msg;
    error_msg << "failed to restore(snapshot_path="
              << req->snapshot_path()->string_view()
              << ", elf_path=" << req->elf_path()->string_view() << ") "
              << proc.error();
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  if (!c.SendSuccess()) {
    LOG(WARN) << "ctl: failed to send success";
    return true;
  }

  return false;
}
bool HandleStartTrace(ControlConn &c,
                      const ctl_schema::StartTraceRequest *req) {
  LOG(INFO) << "handling start trace request";
  std::shared_ptr<Process> proc = Process::Find(req->pid());
  if (!proc) {
    std::ostringstream error_msg;
    error_msg << "failed to start_trace(pid=" << req->pid()
              << "): process not found";
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  } else if (!proc->is_stopped()) {
    std::ostringstream error_msg;
    error_msg << "failed to stop_trace(pid=" << req->pid()
              << "): process is not stopped";
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  proc->get_mem_map().EnableTracing();

  if (!c.SendSuccess()) {
    LOG(WARN) << "ctl: failed to send success";
    return true;
  }
  return false;
}
bool HandleStopTrace(ControlConn &c, const ctl_schema::StopTraceRequest *req) {
  LOG(INFO) << "handling stop trace request";
  std::shared_ptr<Process> proc = Process::Find(req->pid());
  if (!proc) {
    std::ostringstream error_msg;
    error_msg << "failed to stop_trace(pid=" << req->pid()
              << "): process not found";
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  } else if (!proc->is_stopped()) {
    std::ostringstream error_msg;
    error_msg << "failed to stop_trace(pid=" << req->pid()
              << "): process is not stopped";
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  auto report = proc->get_mem_map().EndTracing();
  if (!report) {
    std::ostringstream error_msg;
    error_msg << "failed to stop_trace(pid=" << req->pid()
              << "): " << report.error();
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  if (!c.SendReport(std::move(*report))) {
    LOG(WARN) << "ctl: failed to send success";
    return true;
  }
  return false;
}
bool HandleSignal(ControlConn &c, const ctl_schema::SignalRequest *req) {
  LOG(INFO) << "handling signal request";
  std::shared_ptr<Process> proc = Process::Find(req->pid());
  if (!proc) {
    std::ostringstream error_msg;
    error_msg << "failed to signal(pid=" << req->pid()
              << ", signo=" << req->signo() << "): process not found";
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  proc->Signal(req->signo());

  if (!c.SendSuccess()) {
    LOG(WARN) << "ctl: failed to send success";
    return true;
  }
  return false;
}
bool HandleGetStats(ControlConn &c, const ctl_schema::GetStatsRequest *req) {
  LOG(INFO) << "handling get stats";
  // TODO(control): implement get stats

  if (!c.SendStats()) {
    LOG(WARN) << "ctl: failed to send stats";
    return true;
  }
  LOG(INFO) << "finished get stats";
  return false;
}

bool HandleRequest(ControlConn &c, const ctl_schema::Request *req) {
  switch (req->inner_type()) {
    case ctl_schema::InnerRequest_run:
      return HandleRun(c, req->inner_as_run());
    case ctl_schema::InnerRequest_snapshot:
      return HandleSnapshot(c, req->inner_as_snapshot());
    case ctl_schema::InnerRequest_restore:
      return HandleRestore(c, req->inner_as_restore());
    case ctl_schema::InnerRequest_startTrace:
      return HandleStartTrace(c, req->inner_as_startTrace());
    case ctl_schema::InnerRequest_stopTrace:
      return HandleStopTrace(c, req->inner_as_stopTrace());
    case ctl_schema::InnerRequest_signal:
      return HandleSignal(c, req->inner_as_signal());
    case ctl_schema::InnerRequest_getStats:
      return HandleGetStats(c, req->inner_as_getStats());
    default:
      // TODO(control): send error back
      return true;
  }
}

void ControlWorker(ControlConn c) {
  while (true) {
    auto ret = c.Recv();
    if (!ret) {
      if (ret.error().code() != EUNEXPECTEDEOF) {
        LOG(WARN) << "failed to receive from control connection: "
                  << ret.error();
      }
      return;
    }

    auto request = c.Get();
    if (!request) break;  // connection ended by remote

    bool close = HandleRequest(c, request);
    if (close) break;  // we break the connection
  }
}

void ControlServer(rt::TCPQueue &q) {
  while (true) {
    Status<rt::TCPConn> c = q.Accept();
    if (!c) panic("couldn't accept a connection");
    rt::Spawn([c = std::move(*c)] mutable {
      ControlWorker(ControlConn(std::move(c)));
    });
  }
}

Status<void> InitControlServer() {
  Status<rt::TCPQueue> q = rt::TCPQueue::Listen({0, GetCfg().port()}, 4096);
  if (!q) return MakeError(q);
  LOG(INFO) << "started control server on port " << GetCfg().port();

  rt::Spawn([q = std::move(*q)] mutable { ControlServer(q); });

  return {};
}

}  // namespace junction
