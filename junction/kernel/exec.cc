// exec.cc - support for launching elf binaries

extern "C" {
#include <asm/ops.h>
#include <elf.h>
#include <runtime/thread.h>
#include <sys/auxv.h>

#include "lib/caladan/runtime/defs.h"
}

#include <cstring>

#include "junction/base/arch.h"
#include "junction/base/io.h"
#include "junction/base/string.h"
#include "junction/bindings/log.h"
#include "junction/fs/junction_file.h"
#include "junction/junction.h"
#include "junction/kernel/elf.h"
#include "junction/kernel/exec.h"
#include "junction/kernel/usys.h"
#include "junction/syscall/strace.h"
#include "junction/syscall/syscall.h"

namespace junction {
namespace {

// the number of auxiliary vectors used
inline constexpr size_t kNumAuxVectors = 18;
inline constexpr size_t kMaxInterpFollow = 4;

size_t VectorBytes(const std::vector<std::string_view> &vec) {
  size_t len = 0;
  for (auto &v : vec) len += v.size() + 1;
  return len;
}

template <typename T>
constexpr Elf64_auxv_t MakeAuxVec(uint64_t type, T val) {
  return {.a_type{type}, .a_un{.a_val{static_cast<uint64_t>(val)}}};
}

template <typename T>
constexpr Elf64_auxv_t MakeAuxVec(uint64_t type, T *val) {
  return {.a_type{type}, .a_un{.a_val{reinterpret_cast<uint64_t>(val)}}};
}

void SetupAuxVec(std::array<Elf64_auxv_t, kNumAuxVectors> *vec,
                 const char *filename, const elf_data &edata,
                 char *random_ptr) {
  // get hardware capabilities from CPUID
  cpuid_info info;
  cpuid(0x00000001, 0, &info);

  // Disable VDSO since we want to emulate getcpu() and gettime()
  uintptr_t vdso = 0;

  std::get<0>(*vec) = MakeAuxVec(AT_HWCAP, info.edx);
  std::get<1>(*vec) = MakeAuxVec(AT_PAGESZ, kPageSize);
  // TODO(amb): these are kernel clock ticks via sysconf(_SC_CLK_TCK)
  std::get<2>(*vec) = MakeAuxVec(AT_CLKTCK, 1000000);
  std::get<3>(*vec) = MakeAuxVec(AT_PHDR, edata.phdr_addr);
  std::get<4>(*vec) = MakeAuxVec(AT_PHENT, edata.phdr_entsz);
  std::get<5>(*vec) = MakeAuxVec(AT_PHNUM, edata.phdr_num);
  std::get<6>(*vec) = MakeAuxVec(AT_FLAGS, 0);
  std::get<7>(*vec) = MakeAuxVec(AT_ENTRY, edata.entry_addr);
  std::get<8>(*vec) = MakeAuxVec(
      AT_BASE, edata.interp ? edata.interp->map_base : edata.map_base);
  // TODO(jfried): get these from the proc struct
  std::get<9>(*vec) = MakeAuxVec(AT_UID, 1);
  std::get<10>(*vec) = MakeAuxVec(AT_EUID, 1);
  std::get<11>(*vec) = MakeAuxVec(AT_GID, 1);
  std::get<12>(*vec) = MakeAuxVec(AT_EGID, 1);
  std::get<13>(*vec) = MakeAuxVec(AT_SECURE, 0);
  std::get<14>(*vec) = MakeAuxVec(AT_RANDOM, random_ptr);
  std::get<15>(*vec) = MakeAuxVec(AT_EXECFN, filename);
  std::get<16>(*vec) = MakeAuxVec(AT_SYSINFO_EHDR, vdso);
  std::get<17>(*vec) = MakeAuxVec(AT_NULL, 0);  // must be last
}

void SetupStack(uint64_t *sp, const std::vector<std::string_view> &argv,
                const std::vector<std::string_view> &envp, elf_data &edata) {
  size_t len = 0;
  const char *filename;
  uint64_t *arg_ptr;

  // determine the amount of stack we need to reserve
  len += VectorBytes(argv);
  len += VectorBytes(envp);

  char *info_block_ptr = reinterpret_cast<char *>(*sp - len);
  filename = info_block_ptr;

  // Generate random bytes for aux vector.
  char *random_ptr = info_block_ptr - 16;
  Status<size_t> ret = ReadRandom(readable_span(random_ptr, 16));
  if (!ret) LOG(ERR) << "exec: failed to generate random bytes";
  len += 16;

  // The System V AMD64 ABI requires a 16-byte stack
  // alignment. We go with 32-byte to be extra careful.
  len += sizeof(Elf64_auxv_t) * kNumAuxVectors;
  len += (argv.size() + envp.size() + 3) * sizeof(uint64_t);
  len = AlignUp(len, 32);
  *sp = *sp - len;
  arg_ptr = reinterpret_cast<uint64_t *>(*sp);

  // add the argument count
  *arg_ptr++ = argv.size();

  // add arguments to the stack
  for (auto &arg : argv) {
    *arg_ptr++ = reinterpret_cast<uintptr_t>(info_block_ptr);
    std::memcpy(info_block_ptr, arg.data(), arg.size());
    info_block_ptr[arg.size()] = 0;
    info_block_ptr += arg.size() + 1;
  }

  // null terminate the arg array
  *arg_ptr++ = 0;

  // add environment variables to the stack
  for (auto &arg : envp) {
    *arg_ptr++ = reinterpret_cast<uintptr_t>(info_block_ptr);
    std::memcpy(info_block_ptr, arg.data(), arg.size());
    info_block_ptr[arg.size()] = 0;
    info_block_ptr += arg.size() + 1;
  }

  // null terminate the env array
  *arg_ptr++ = 0;

  // add the auxiliary vector to the stack
  SetupAuxVec(
      reinterpret_cast<std::array<Elf64_auxv_t, kNumAuxVectors> *>(arg_ptr),
      filename, edata, random_ptr);
}

}  // namespace

Status<elf_data> TryLoadBin(Process &p, MemoryMap &mm,
                            std::string_view pathname,
                            std::vector<std::string_view> &argv,
                            bool must_be_reloc,
                            size_t max_depth = kMaxInterpFollow) {
  Status<JunctionFile> file =
      JunctionFile::Open(p.get_fs(), pathname, 0, FileMode::kRead);
  if (!file) return MakeError(file);

  auto edata = LoadELF(mm, *file, p.get_fs(), pathname, must_be_reloc);
  if (edata) {
    // Record pathname in proc
    mm.set_bin_path(pathname, argv);
    return edata;
  }
  if (max_depth == 0) return MakeError(ELOOP);

  file->Seek(0);
  StreamBufferReader r(*file, 256);
  std::istream instream(&r);
  if (instream.get() != '#' || instream.get() != '!') return MakeError(EINVAL);

  std::string s;
  std::getline(instream, s);
  std::vector<std::string_view> tokens = split(s, ' ', 1);

  argv.insert(argv.begin(), tokens.begin(), tokens.end());

  return TryLoadBin(p, mm, tokens[0], argv, must_be_reloc, max_depth - 1);
}

Status<ExecInfo> Exec(Process &p, MemoryMap &mm, std::string_view pathname,
                      std::vector<std::string_view> &argv,
                      const std::vector<std::string_view> &envp,
                      bool must_be_reloc) {
  auto edata = TryLoadBin(p, mm, pathname, argv, must_be_reloc);
  if (!edata) return MakeError(edata);

  // Create the first thread
  uint64_t entry =
      edata->interp ? edata->interp->entry_addr : edata->entry_addr;

  // setup a stack
  Status<void *> guard = mm.MMapAnonymous(
      nullptr, RUNTIME_GUARD_SIZE + RUNTIME_STACK_SIZE, PROT_NONE, 0);
  if (!guard) return MakeError(guard);
  void *rsp = reinterpret_cast<void *>(
      (reinterpret_cast<uintptr_t>(*guard) + RUNTIME_GUARD_SIZE));
  Status<void *> ret = mm.MMapAnonymous(
      rsp, RUNTIME_STACK_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_STACK);
  if (!ret) return MakeError(ret);
  uint64_t sp = reinterpret_cast<uint64_t>(rsp) + RUNTIME_STACK_SIZE;

  SetupStack(&sp, argv, envp, *edata);
  return {{sp, entry}};
}

long usys_execve(const char *filename, const char *argv[], const char *envp[]) {
  // allocate new memory map
  Status<std::shared_ptr<MemoryMap>> mm = CreateMemoryMap(kMemoryMappingSize);
  if (!mm) return MakeCError(mm);

  // turn argv and envp in string_view vectors, memory must remain valid until
  // after Exec returns
  std::vector<std::string_view> argv_view;
  const char **ptr = argv;
  while (*ptr) argv_view.emplace_back(*ptr++);

  std::vector<std::string_view> envp_view;
  ptr = envp;
  while (*ptr) envp_view.emplace_back(*ptr++);

  Process &p = myproc();
  MemoryMap &old_mm = p.get_mem_map();

  // If exec was called from a process with a non-relocatable executable (that
  // is not in vfork) then we can safely replace it with another non-relocatable
  // executable.
  size_t nr_non_reloc = MemoryMap::get_nr_non_reloc();
  if (nr_non_reloc && old_mm.is_non_reloc() && !p.in_vfork_preexec())
    nr_non_reloc--;

  Status<ExecInfo> ret =
      Exec(p, **mm, filename, argv_view, envp_view, nr_non_reloc > 0);
  if (!ret) {
    if (unlikely((**mm).is_non_reloc() && old_mm.is_non_reloc())) {
      LOG(ERR) << "exec: failed while replacing existing non-reloc map with a "
                  "new one";
      syscall_exit(-1);
    }
    return MakeCError(ret);
  }

  // The syscall has suceeded.
  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall(0, "execve", &usys_execve, (strace::PathName *)filename, argv,
               envp);

  // Finish exec from a different stack, since this stack may be unmapped when
  // replacing a proc's MM
  RunOnSyscallStack([regs = *ret, mm = std::move(*mm)]() mutable {
    Thread &myth = mythread();

    // Complete the exec
    myth.get_process().FinishExec(std::move(mm));

    // We can allocate a thread_tf on the syscall stack but not the
    // FunctionCallTf wrapper. Use the Thread instance's fcall_tf.
    thread_tf start_tf;

    // clear argument registers
    start_tf.rdi = 0;
    start_tf.rsi = 0;
    start_tf.rdx = 0;
    start_tf.rcx = 0;
    start_tf.r8 = 0;
    start_tf.r9 = 0;

    start_tf.rsp = std::get<0>(regs);
    start_tf.rip = std::get<1>(regs);

    // Set entry_regs to start_tf and use fcall_tf to unwind.
    myth.ReplaceEntryRegs(start_tf).JmpUnwindSysret(myth);
  });
}

long usys_execveat(int fd, const char *filename, const char *argv[],
                   const char *envp[], int flags) {
  // TODO: support when Junction supports openat
  return -ENOSYS;
}

}  // namespace junction
