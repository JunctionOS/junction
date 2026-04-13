#include <charconv>

#include "junction/base/finally.h"
#include "junction/base/string.h"
#include "junction/base/time.h"
#include "junction/bindings/log.h"
#include "junction/bindings/net.h"
#include "junction/bindings/thread.h"
#include "junction/control/ctl_conn.h"
#include "junction/control/serverless.h"
#include "junction/kernel/proc.h"
#include "junction/net/tcp_socket.h"
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

  for (size_t idx = 0; idx < argc; idx += 1)
    argv.push_back(fb_argv->Get(idx)->string_view());

  // Initialize environment and arguments
  auto [envp_s, envp_view] = BuildEnvp();

  for (size_t i = 0; i < req->envp()->size(); i += 1)
    envp_view.push_back(req->envp()->Get(i)->string_view());

  Thread *th = nullptr;
  auto proc =
      CreateFirstProcess(req->bin()->string_view(), argv, envp_view,
                         req->is_init(), std::string{req->cwd()->string_view()},
                         std::string{req->fsroot()->string_view()}, &th);
  if (!proc) {
    std::ostringstream error_msg;
    error_msg << "failed to run(";

    size_t idx = 0;
    for (; idx < argc - 1; idx++) { error_msg << argv[idx] << ", "; }
    error_msg << argv[idx] << "): " << proc.error();
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  if (!c.RunResponse((*proc)->get_pid())) {
    LOG(WARN) << "ctl: failed to send response";
    return true;
  }

  auto file = std::make_shared<TCPSocket>(c.SeizeConn());
  (*proc)->get_file_table().InsertAt(1, file);
  (*proc)->get_file_table().InsertAt(2, file);
  th->ThreadReady();
  return true;
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

  std::string_view args = req->argument()->string_view();
  if (!args.empty()) {
    std::string result =
        InvokeChan(req->name()->string_view(), std::string{args});
    if (!c.InvokeResponse(result)) {
      LOG(WARN) << "failed to send invocation response";
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
  } else if (!proc->is_fully_stopped()) {
    std::ostringstream error_msg;
    error_msg << "failed to stop_trace(pid=" << req->pid()
              << "): process is not stopped";
    if (!c.SendError(error_msg.str())) {
      LOG(WARN) << "ctl: failed to send error: " << error_msg.str();
      return true;
    }
    return false;
  }

  proc->get_mem_map().EnableTracing(*proc.get());

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

  Status<PageAccessTracer> report = proc->get_mem_map().EndTracing();
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

  if (!c.SendReport(*report)) {
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

bool HandlePS(ControlConn &c, const ctl_schema::PSRequest *req) {
  LOG(INFO) << "handling ps request";
  std::vector<pid_t> pids;
  Process::ForEachProcess(
      [&pids](const Process &proc) { pids.push_back(proc.get_pid()); });

  if (!c.PSResponse(pids)) {
    LOG(WARN) << "ctl: failed to send ps response";
    return true;
  }
  return false;
}
bool HandleMigrateStopAndCopy(ControlConn &c,
                              const ctl_schema::MigrateRequest *req) {
  LOG(INFO) << "handling stop-and-copy migration for pid " << req->pid();
  Time t0 = Time::Now();

  std::shared_ptr<Process> p = Process::Find(req->pid());
  if (!p) {
    std::ostringstream msg;
    msg << "migrate: pid " << req->pid() << " not found";
    if (!c.SendError(msg.str())) LOG(WARN) << "ctl: failed to send error";
    return false;
  }

  netaddr dest = {req->dest_ip(), req->dest_port()};
  Status<rt::TCPConn> conn = rt::TCPConn::Dial({0, 0}, dest);
  if (!conn) {
    std::ostringstream msg;
    msg << "migrate: failed to connect to destination: " << conn.error();
    if (!c.SendError(msg.str())) LOG(WARN) << "ctl: failed to send error";
    return false;
  }
  Time t1 = Time::Now();
  LOG(INFO) << "migration sender: TCP connect took " << (t1 - t0).Microseconds()
            << " us";

  p->JobControlStop();
  p->WaitForFullStop();
  Time t2 = Time::Now();
  LOG(INFO) << "migration sender: stop took " << (t2 - t1).Microseconds()
            << " us";
  auto resume = finally([&] { p->DoExit(0); });

  if (Status<void> ret = SnapshotProcToELFStream(p.get(), *conn); !ret) {
    std::ostringstream msg;
    msg << "migrate: snapshot failed: " << ret.error();
    if (!c.SendError(msg.str())) LOG(WARN) << "ctl: failed to send error";
    return false;
  }
  Time t3 = Time::Now();
  LOG(INFO) << "migration sender: total (connect+stop+snapshot) took "
            << (t3 - t0).Microseconds() << " us";

  if (!c.SendSuccess()) LOG(WARN) << "ctl: failed to send success";
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
    case ctl_schema::InnerRequest_ps:
      return HandlePS(c, req->inner_as_ps());
    case ctl_schema::InnerRequest_migrate:
      return HandleMigrateStopAndCopy(c, req->inner_as_migrate());
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

void MigrationServer(rt::TCPQueue &q) {
  while (true) {
    Status<rt::TCPConn> c = q.Accept();
    if (!c) panic("couldn't accept a migration connection");
    rt::Spawn([c = std::move(*c)] mutable {
      Status<std::shared_ptr<Process>> p = RestoreProcessFromELFStream(c);
      if (!p) {
        LOG(ERR) << "migration restore failed: " << p.error();
      } else {
        LOG(INFO) << "migration restore succeeded, pid=" << (*p)->get_pid();
        if (timings().migration_restore_start &&
            timings().migration_restore_done) {
          LOG(INFO) << "migration receiver: restore to RunThreads took "
                    << (*timings().migration_restore_done -
                        *timings().migration_restore_start)
                           .Microseconds()
                    << " us";
        }
      }
    });
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

  uint16_t mig_port = GetCfg().port() + 2;
  Status<rt::TCPQueue> mq = rt::TCPQueue::Listen({0, mig_port}, 4096);
  if (!mq) return MakeError(mq);
  LOG(INFO) << "started migration server on port " << mig_port;
  rt::Spawn([mq = std::move(*mq)] mutable { MigrationServer(mq); });

  return {};
}

}  // namespace junction
