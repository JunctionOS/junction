
#include "junction/control/serverless.h"

#include <format>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/kernel/proc.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

class FunctionInode;

rt::SharedMutex lock_;
std::unordered_map<int, std::shared_ptr<FunctionInode>> channels_;

std::string from_byte_span(std::span<const std::byte> byte_span) {
  return std::string(reinterpret_cast<const char *>(byte_span.data()),
                     byte_span.size());
}

class FunctionChannel {
 public:
  FunctionChannel() = default;
  // Userspace API
  Status<size_t> Read(std::span<std::byte> buf, bool nonblocking) {
    if (unlikely(!timings().first_function_start))
      timings().first_function_start = Time::Now();
    rt::SpinGuard g(lock_);
    while (true) {
      if (request_.size()) {
        size_t nb = request_.size();
        if (nb > buf.size() - 1) return MakeError(ENOSPC);
        std::memcpy(buf.data(), request_.data(), nb);
        buf[nb++] = std::byte{'\n'};
        request_.clear();
        pollers_.Clear(kPollIn);
        return nb;
      }
      if (nonblocking) return MakeError(EAGAIN);
      last_waiter_tid_ = mythread().get_tid();
      bool signaled = !rt::WaitInterruptible(
          lock_, app_waiter_, [this] { return request_.size() > 0; });
      if (signaled) return MakeError(ERESTARTSYS);
    }
  }

  Status<size_t> Write(std::span<const std::byte> buf) {
    Time end = Time::Now();
    if (unlikely(!timings().first_function_end))
      timings().first_function_end = end;
    rt::SpinGuard g(lock_);
    BUG_ON(!in_progress_);
    response_ = from_byte_span(buf);
    junction_waiter_.Wake(true);
    if (!start_.IsZero()) {
      latencies_us_.push_back((end - start_).Microseconds());
      start_ = Time(0);
    }
    return buf.size();
  }

  // Junction kernel API
  std::string DoRequest(std::string cmd) {
    rt::SpinGuard g(lock_);
    request_ = std::move(cmd);
    MarkStart();
    app_waiter_.Wake();
    rt::Wait(lock_, junction_waiter_, [this] { return response_.size() > 0; });
    MarkEnd();
    return std::move(response_);
  }

  void PostRequest(std::string cmd) {
    rt::SpinGuard g(lock_);
    MarkStart();
    request_ = std::move(cmd);
    app_waiter_.Wake();
  }

  Status<std::string> PollResponse() {
    rt::SpinGuard g(lock_);
    if (!response_.size()) return MakeError(EAGAIN);
    MarkEnd();
    return std::move(response_);
  }

  std::string WaitResponse() {
    rt::SpinGuard g(lock_);
    rt::Wait(lock_, junction_waiter_, [this] { return response_.size() > 0; });
    MarkEnd();
    return std::move(response_);
  }

  void SnapshotPrepare() {
    rt::SpinGuard g(lock_);
    request_ = "SNAPSHOT_PREPARE";
    MarkStart(false);
    app_waiter_.Wake();
    rt::Wait(lock_, junction_waiter_, [this] { return response_.size() > 0; });
    MarkEnd();
    BUG_ON(response_ != "OK");
    response_.clear();
  }

  [[nodiscard]] bool in_progress() const { return access_once(in_progress_); }
  [[nodiscard]] pid_t get_last_blocked_tid() const { return last_waiter_tid_; }

  std::vector<uint64_t> get_latencies() {
    rt::SpinGuard g(lock_);
    return latencies_us_;
  }

  template <class Archive>
  void serialize(Archive &ar) {
    ar(latencies_us_);
  }

 private:
  inline void MarkStart(bool time = true) {
    BUG_ON(in_progress_);
    if (time) start_ = Time::Now();
    in_progress_ = true;
    pollers_.Set(kPollIn);
  }

  inline void MarkEnd() {
    BUG_ON(!in_progress_);
    in_progress_ = false;
  }

  friend class FunctionChannelFile;

  void Attach(PollSource *p) {
    rt::SpinGuard g(lock_);
    pollers_.Attach(p);
    if (request_.size()) p->Set(kPollIn);
  }

  void Detach(PollSource *p) {
    rt::SpinGuard g(lock_);
    pollers_.Detach(p);
  }

  rt::Spin lock_;
  rt::ThreadWaker app_waiter_;
  rt::ThreadWaker junction_waiter_;
  pid_t last_waiter_tid_{0};
  bool in_progress_{false};
  Time start_{0};
  std::string request_;
  std::string response_;
  std::vector<uint64_t> latencies_us_;
  PollSourceSet pollers_;
};

class FunctionInode : public Inode {
 public:
  FunctionInode(int id, ino_t inum = AllocateInodeNumber())
      : Inode(kTypeFIFO | 0666, inum), id_(id) {}

  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override;

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  template <class Archive>
  void save(Archive &ar) const {
    BUG_ON(chan_.in_progress());
    ar(id_, get_inum());
    ar(cereal::base_class<Inode>(this));
    ar(chan_);
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<FunctionInode> &construct) {
    int id;
    ino_t inum;
    ar(id, inum);
    construct(id, inum);
    ar(cereal::base_class<Inode>(construct.ptr()));
    ar(construct->chan_);
    rt::ScopedLock g(lock_);
    channels_[id] =
        std::static_pointer_cast<FunctionInode>(construct->get_this());
  }

  [[nodiscard]] FunctionChannel &get_chan() { return chan_; }

 private:
  int id_;
  FunctionChannel chan_;
};

class FunctionChannelFile : public SeekableFile {
 public:
  FunctionChannelFile(int flags, FileMode mode,
                      std::shared_ptr<DirectoryEntry> dent) noexcept
      : SeekableFile(FileType::kNormal, flags & kFlagNonblock, mode,
                     std::move(dent)) {
    FunctionInode &ino = fast_cast<FunctionInode &>(get_inode_ref());
    ino.get_chan().Attach(&get_poll_source());
  }

  ~FunctionChannelFile() override {
    FunctionInode &ino = fast_cast<FunctionInode &>(get_inode_ref());
    ino.get_chan().Detach(&get_poll_source());
  }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    FunctionInode &ino = fast_cast<FunctionInode &>(get_inode_ref());
    return ino.get_chan().Read(buf, is_nonblocking());
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    FunctionInode &ino = fast_cast<FunctionInode &>(get_inode_ref());
    return ino.get_chan().Write(buf);
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(get_mode(), get_dent());
    ar(cereal::base_class<SeekableFile>(this));
  }

  template <class Archive>
  static void load_and_construct(
      Archive &ar, cereal::construct<FunctionChannelFile> &construct) {
    FileMode mode;
    std::shared_ptr<DirectoryEntry> dent;
    ar(mode, dent);
    construct(0, mode, std::move(dent));
    ar(cereal::base_class<SeekableFile>(construct.ptr()));
  }
};

Status<std::shared_ptr<File>> FunctionInode::Open(
    uint32_t flags, FileMode mode, std::shared_ptr<DirectoryEntry> dent) {
  return std::make_shared<FunctionChannelFile>(flags, mode, std::move(dent));
}

std::shared_ptr<FunctionInode> get_channel(int chan) {
  rt::ScopedSharedLock g(lock_);
  auto it = channels_.find(chan);
  if (it == channels_.end()) return {};
  return it->second;
}

Status<void> SetupServerlessChannel(int chan) {
  FSRoot &fs = FSRoot::GetGlobalRoot();
  rt::ScopedLock g(lock_);

  if (channels_.count(chan) > 0) return MakeError(EEXIST);

  Status<std::shared_ptr<Inode>> srvdir = LookupInode(fs, "/serverless");
  IDir *dir;
  if (srvdir) {
    assert((*srvdir)->is_dir());
    dir = static_cast<IDir *>(srvdir->get());
  } else {
    dir = memfs::MkFolder(*fs.get_root().get(), "serverless").get();
  }

  std::shared_ptr<FunctionInode> fino = std::make_shared<FunctionInode>(chan);
  Status<void> ret = dir->Link(std::format("chan{}", chan), fino);
  if (!ret) return ret;
  channels_.emplace(chan, std::move(fino));
  return {};
}

void PrintTimes(const std::vector<uint64_t> &times, std::string_view name) {
  std::stringstream ss;
  ss << "DATA  {\"times\": [";
  for (size_t i = 0; i < times.size(); i++) {
    if (i > 0) ss << ", ";
    ss << times[i];
  }
  ss << "], \"program\": \"" << name << "\"";

  ss << ", \"caladan_init\": " << timings().CaladanStartTime().Microseconds();
  ss << ", \"junction_init\": " << timings().JunctionInitTime().Microseconds();

  if (timings().restore_start) {
    ss << ", \"fs_restore\": " << timings().FSRestoreTime().Microseconds();
    ss << ", \"metadata_restore\": "
       << timings().MetadataRestoreTime().Microseconds();
    ss << ", \"data_restore\": " << timings().DataRestoreTime().Microseconds();
  } else {
    ss << ", \"application_init\": "
       << timings().ApplicationInitTime().Microseconds();
  }

  ss << ", \"first_iter\": " << timings().FirstIterTime().Microseconds();

  ss << "}";
  LOG(ERR) << ss.str();
}

void RunRestored(std::shared_ptr<Process> proc, int chan_id,
                 std::string_view arg) {
  std::shared_ptr<FunctionInode> fino = get_channel(chan_id);
  if (unlikely(!fino)) {
    LOG(ERR) << "Missing serverless channel";
    syscall_exit(-1);
  }

  bool ka = GetCfg().GetBool("keep_alive");
  FunctionChannel &chan = fino->get_chan();
  chan.DoRequest(std::string{arg});

  while (ka) {
    Time tstart = Time::Now();
    chan.DoRequest(std::string{arg});
    Time tend = Time::Now();
    rt::Sleep(Duration((tend - tstart).Microseconds() * 9));
  }

  if (GetCfg().mem_trace()) {
    proc->Signal(SIGSTOP);
    BUG_ON(!proc->WaitForFullStop());
    BUG_ON(!proc->get_mem_map().DumpTracerReport());
  }
  PrintTimes(chan.get_latencies(), GetCfg().GetArg("function_name"));
  syscall_exit(0);
}

void WarmupAndSnapshot(std::shared_ptr<Process> proc, int chan_id,
                       std::string_view arg) {
  std::shared_ptr<FunctionInode> fino = get_channel(chan_id);
  if (unlikely(!fino)) {
    LOG(ERR) << "Missing serverless channel";
    syscall_exit(-1);
  }

  FunctionChannel &chan = fino->get_chan();

  for (size_t i = 0; i < 10; i++) chan.DoRequest(std::string{arg});

  chan.SnapshotPrepare();
  proc->Signal(SIGSTOP);
  BUG_ON(!proc->WaitForFullStop());

  Status<void> ret = TakeSnapshot(proc.get());
  if (!ret) {
    LOG(ERR) << "Failed to snapshot: " << ret.error();
    syscall_exit(-1);
  } else {
    LOG(INFO) << "snapshot successful!";
  }

  PrintTimes(chan.get_latencies(), GetCfg().GetArg("function_name"));
  syscall_exit(0);
}

std::string InvokeChan(int chan, std::string arg) {
  std::shared_ptr<FunctionInode> fino = get_channel(chan);
  assert(fino);
  return fino->get_chan().DoRequest(arg);
}

pid_t GetLastBlockedTid(int chan) {
  std::shared_ptr<FunctionInode> fino = get_channel(chan);
  if (unlikely(!fino)) return 0;
  return fino->get_chan().get_last_blocked_tid();
}

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::FunctionInode);
CEREAL_REGISTER_TYPE(junction::FunctionChannelFile);
