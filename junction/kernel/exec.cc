extern "C" {
#include <asm/ops.h>
#include <runtime/thread.h>
#include <sys/auxv.h>
#include <elf.h>
}

#include <cstring>

#include "junction/base/arch.h"
#include "junction/kernel/elf.h"
#include "junction/kernel/proc.h"
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

void SetupAuxVec(Elf64_auxv_t *vec, const char *filename, elf_data &edata,
                 char *random_ptr) {
  int idx = 0;
  cpuid_info info;

  cpuid(0x00000001, &info);

#define AUX_VEC(type, val)                 \
  do {                                     \
    assert(idx < kNumAuxVectors);          \
    vec[idx].a_type = (type);              \
    vec[idx].a_un.a_val = (uint64_t)(val); \
    idx++;                                 \
  } while (0)

  AUX_VEC(AT_HWCAP, info.edx);
  AUX_VEC(AT_PAGESZ, kPageSize);
  /* FIXME: using a fake CLKTCK value for now */
  AUX_VEC(AT_CLKTCK, 1000000);
  AUX_VEC(AT_PHDR, edata.phdr_addr);
  AUX_VEC(AT_PHENT, sizeof(Elf64_Phdr));
  AUX_VEC(AT_PHNUM, edata.phdr_num);
  AUX_VEC(AT_FLAGS, 0);
  AUX_VEC(AT_ENTRY, edata.entry_addr);
  AUX_VEC(AT_BASE, edata.interp ? edata.interp->map_base : 0);
  /* FIXME: get these from the proc struct */
  AUX_VEC(AT_UID, 1);
  AUX_VEC(AT_EUID, 1);
  AUX_VEC(AT_GID, 1);
  AUX_VEC(AT_EGID, 1);
  AUX_VEC(AT_SECURE, 0);
  /*
   * FIXME: for some reason Ubuntu binaries won't
   * work without this vector, so we need to
   * generate real random entropy.
   */
  AUX_VEC(AT_RANDOM, random_ptr);
  AUX_VEC(AT_EXECFN, filename);
  AUX_VEC(AT_SYSINFO_EHDR, 0); /* don't provide vdso */
  AUX_VEC(AT_NULL, 0);         /* must be last */
}

void SetupStack(uint64_t *sp, const std::vector<std::string_view> &argv,
                const std::vector<std::string_view> &envp, elf_data &edata) {
  size_t len = 0;
  char *info_block_ptr, *random_ptr;
  const char *filename;
  uint64_t *arg_ptr;

  // determine the amount of stack we need to reserve
  len += VectorBytes(argv);
  len += VectorBytes(envp);

  info_block_ptr = reinterpret_cast<char *>(*sp - len);
  filename = info_block_ptr;

  // TODO: generate random data here
  random_ptr = info_block_ptr - 16;
  len += 16;  // random bytes

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
  SetupAuxVec(reinterpret_cast<Elf64_auxv_t *>(arg_ptr), filename, edata,
              random_ptr);
}

extern "C" {
// Start trampoline with zero arg registers; some binaries need this
void junction_exec_start(void *entry_arg);
asm(R"(
.globl junction_exec_start
    .type junction_exec_start, @function
    junction_exec_start:

    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %rcx, %rcx
    xor %r8, %r8
    xor %r9, %r9

    jmpq    *%rdi
)");
}
}  // namespace

Status<thread_t *> Exec(std::string_view pathname,
                        const std::vector<std::string_view> &argv,
                        const std::vector<std::string_view> &envp) {
  auto edata = LoadELF(pathname);
  if (!edata) return MakeError(edata);

  uint64_t entry =
      edata->interp ? edata->interp->entry_addr : edata->entry_addr;
  thread_t *th =
      thread_create(junction_exec_start, reinterpret_cast<void *>(entry));
  if (!th) return MakeError(-ENOMEM);

  // get a pointer to this thread's RSP, remove the existing exit function
  // pointer
  uint64_t *rsp = get_tf_rsp(th);
  *rsp -= 8;

  SetupStack(rsp, argv, envp, *edata);

  return th;
}

}  // namespace junction
