#pragma once

extern "C" {
#include <linux/rseq.h>
}

#include "junction/bindings/thread.h"
#include "junction/snapshot/cereal.h"

namespace junction {

inline constexpr size_t kRseqSize = 32;
inline constexpr size_t kRseqFeatureSize = 28;

class Trapframe;
class Thread;

class RseqState {
 public:
  [[nodiscard]] Status<void> matches(struct rseq *rseq, uint32_t len,
                                     uint32_t sig) const {
    if (rseq != user_rs_ || len != len_) return MakeError(EINVAL);
    if (sig != sig_) return MakeError(EPERM);
    return {};
  }

  explicit operator bool() const { return user_rs_; }
  [[nodiscard]] struct rseq *get_rseq() const { return user_rs_; }

  void reset() {
    if (!user_rs_) return;
    user_rs_->cpu_id_start = user_rs_->mm_cid = 0;
    user_rs_->cpu_id = RSEQ_CPU_ID_UNINITIALIZED;
    user_rs_ = nullptr;
    len_ = sig_ = 0;
  }

  void set(struct rseq *rseq, uint32_t len, uint32_t sig) {
    user_rs_ = rseq;
    len_ = len;
    sig_ = sig;
    if (rseq) update();
  }

  // Fix IP for trapframe if it is executing in a critical section.
  // This must be called whenever a signal handler is executed or there is a
  // trip through the caladan scheduler.
  inline void fixup(Thread &th, Trapframe *tf = nullptr) {
    if (!user_rs_) return;
    if (user_rs_->rseq_cs) _fixup(th, tf);
    update();
  }

  template <typename Archive>
  void serialize(Archive &ar) {
    ar(cereal::binary_data(this, sizeof(RseqState)));
  }

 private:
  void _fixup(Thread &th, Trapframe *tf);

  void update() {
    assert(user_rs_);
    user_rs_->cpu_id_start = user_rs_->cpu_id = user_rs_->mm_cid =
        get_current_affinity();
  }

  struct rseq *user_rs_{nullptr};
  uint32_t len_{0};
  uint32_t sig_{0};
};

}  // namespace junction