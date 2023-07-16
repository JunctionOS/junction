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
#include "junction/bindings/log.h"
#include "junction/junction.h"
#include "junction/kernel/elf.h"
#include "junction/kernel/exec.h"
#include "junction/kernel/usys.h"

namespace junction {
namespace {

// the number of auxiliary vectors used
constexpr size_t kNumAuxVectors = 18;

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
  cpuid(0x00000001, &info);

  // expose the real Linux vDSO, which includes the following system calls:
  // 1. clock_gettime()
  // 2. getcpu()
  // 3. gettimeofday()
  // 4. time()
  uintptr_t vdso = getauxval(AT_SYSINFO_EHDR);

  // disable vdso when stracing
  if (GetCfg().strace_enabled()) vdso = 0;

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

// Start trampoline with zero arg registers; some binaries need this
extern "C" void junction_exec_start(void *entry_arg);
asm(R"(
.globl junction_exec_start
    .type junction_exec_start, @function
    junction_exec_start:

    movq %rdi, %r11
    xor %rdi, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %rcx, %rcx
    xor %r8, %r8
    xor %r9, %r9

    jmpq    *%r11
)");
}  // namespace

Status<thread_t *> Exec(Process &p, MemoryMap &mm, std::string_view pathname,
                        const std::vector<std::string_view> &argv,
                        const std::vector<std::string_view> &envp) {
  // load the ELF program image file
  auto edata = LoadELF(mm, pathname);
  if (!edata) return MakeError(edata);

  // Record pathname in proc
  p.set_bin_path(pathname);

  // Create the first thread
  uint64_t entry =
      edata->interp ? edata->interp->entry_addr : edata->entry_addr;

  Status<std::unique_ptr<Thread>> tstate = p.CreateThreadMain();
  if (!tstate) return MakeError(tstate);
  thread_t *th = (*tstate)->GetCaladanThread();
  th->tf.rip = reinterpret_cast<uintptr_t>(junction_exec_start);
  th->tf.rdi = reinterpret_cast<uintptr_t>(entry);

  // setup a stack
  void *rsp = mm.ReserveForMapping(RUNTIME_GUARD_SIZE + RUNTIME_STACK_SIZE);
  Status<void *> ret = KernelMMap(rsp + RUNTIME_GUARD_SIZE, RUNTIME_STACK_SIZE,
                                  PROT_READ | PROT_WRITE, 0);
  if (!ret) return MakeError(ret);
  th->tf.rsp = reinterpret_cast<uint64_t>(*ret) + RUNTIME_STACK_SIZE;

  SetupStack(&th->tf.rsp, argv, envp, *edata);

  tstate->release();
  return th;
}

int usys_execve(const char *filename, const char *argv[], const char *envp[]) {
  // allocate new memory map
  Status<std::shared_ptr<MemoryMap>> mm = CreateMemoryMap(kMemoryMappingSize);
  if (!mm) return MakeCError(mm);

  // turn argv and envp in string_view vectors, memory must remain valid until
  // after Exec returns
  std::vector<std::string_view> argv_view;
  while (*argv) argv_view.emplace_back(*argv++);

  std::vector<std::string_view> envp_view;
  while (*envp) envp_view.emplace_back(*envp++);

  // TODO(jfried): must stop all other threads

  Status<thread_t *> ret = Exec(myproc(), **mm, filename, argv_view, envp_view);
  if (!ret) return MakeCError(ret);

  // Finish exec from a different thread, since this stack may be unmapped when
  // replacing a proc's MM
  rt::Spawn([oldth = thread_self(), newth = *ret, mm = std::move(*mm)] mutable {
    // Ensure old thread has parked before proceeding
    while (load_acquire(&oldth->thread_running)) rt::Yield();

    // Destroy the previous thread and release its memory
    Thread *tptr = reinterpret_cast<Thread *>(oldth->junction_tstate_buf);
    tptr->~Thread();
    thread_free(oldth);

    // Complete the exec
    tptr = reinterpret_cast<Thread *>(newth->junction_tstate_buf);
    tptr->get_process().FinishExec(std::move(mm));

    // Wake the new main thread
    thread_ready(newth);
  });

  rt::WaitForever();
  std::unreachable();
}

int usys_execveat(int fd, const char *filename, const char *argv[],
                  const char *envp[], int flags) {
  // TODO: support when Junction supports openat
  return -ENOSYS;
}

}  // namespace junction
