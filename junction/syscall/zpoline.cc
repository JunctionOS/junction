
#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/junction.h"
#include "junction/kernel/ksys.h"
#include "junction/syscall/syscall.h"

namespace junction {

constexpr inline size_t kNopSledSize = 460;

// Code from https://github.com/yasukata/zpoline/blob/master/main.c
void FillJumpPage(uint8_t *mem, long int (*fn)()) {
  memset(mem, 0x90, kNopSledSize);

  // optimization introduced by reviewer C
  mem[214 /* __NR_epoll_ctl_old */] = 0xeb; /* short jmp */
  mem[215 /* __NR_epoll_wait_old */] =
      127; /* range of a short jmp : -128 ~ +127 */

  // There are no system calls in this area, do another jump.
  mem[350] = 0xeb;
  mem[351] = 100;

  /*
   * put code for jumping to asm_syscall_hook.
   *
   * here we embed the following code.
   *
   * sub    $0x80,%rsp
   * movabs [asm_syscall_hook],%r11
   * jmpq   *%r11
   *
   */

  // TODO(jfried): remove this instruction
  /* preserve redzone */
  // 48 81 ec 80 00 00 00    sub    $0x80,%rsp
  mem[kNopSledSize + 0x00] = 0x48;
  mem[kNopSledSize + 0x01] = 0x81;
  mem[kNopSledSize + 0x02] = 0xec;
  mem[kNopSledSize + 0x03] = 0x00;
  mem[kNopSledSize + 0x04] = 0x00;
  mem[kNopSledSize + 0x05] = 0x00;
  mem[kNopSledSize + 0x06] = 0x00;

  // 49 bb [64-bit addr (8-byte)]    movabs [64-bit addr (8-byte)],%r11
  mem[kNopSledSize + 0x07] = 0x49;
  mem[kNopSledSize + 0x08] = 0xbb;
  mem[kNopSledSize + 0x09] = ((uint64_t)fn >> (8 * 0)) & 0xff;
  mem[kNopSledSize + 0x0a] = ((uint64_t)fn >> (8 * 1)) & 0xff;
  mem[kNopSledSize + 0x0b] = ((uint64_t)fn >> (8 * 2)) & 0xff;
  mem[kNopSledSize + 0x0c] = ((uint64_t)fn >> (8 * 3)) & 0xff;
  mem[kNopSledSize + 0x0d] = ((uint64_t)fn >> (8 * 4)) & 0xff;
  mem[kNopSledSize + 0x0e] = ((uint64_t)fn >> (8 * 5)) & 0xff;
  mem[kNopSledSize + 0x0f] = ((uint64_t)fn >> (8 * 6)) & 0xff;
  mem[kNopSledSize + 0x10] = ((uint64_t)fn >> (8 * 7)) & 0xff;

  // 41 ff e3                jmp    *%r11
  mem[kNopSledSize + 0x11] = 0x41;
  mem[kNopSledSize + 0x12] = 0xff;
  mem[kNopSledSize + 0x13] = 0xe3;
}

Status<void> InitZpoline() {
  if (!GetCfg().zpoline()) return {};

  Status<void *> mret =
      KernelMMap(nullptr, kPageSize, PROT_EXEC | PROT_WRITE | PROT_READ, 0);
  if (!mret) return MakeError(mret);

  uint8_t *mem = reinterpret_cast<uint8_t *>(*mret);
  FillJumpPage(mem, xsavec_available ? junction_zpoline_enter
                                     : junction_zpoline_enter_noxsavec);

  /*
   * mprotect(PROT_EXEC without PROT_READ), executed
   * on CPUs supporting Memory Protection Keys for Userspace (PKU),
   * configures this memory region as eXecute-Only-Memory (XOM).
   * this enables to cause a segmentation fault for a NULL pointer access.
   */
  Status<void> ret = KernelMProtect(mem, kPageSize, PROT_EXEC);
  if (!ret) {
    LOG(ERR) << "zpoline: mprotect fail";
    return MakeError(ret);
  }

  mret = KernelMRemap(*mret, kPageSize, kPageSize,
                      MREMAP_FIXED | MREMAP_MAYMOVE, nullptr);
  if (!mret) return MakeError(mret);

  return {};
}

}  // namespace junction
