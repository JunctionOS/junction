// pod.h - serialization of plain old data types

#pragma once

extern "C" {
#include <signal.h>        // stack_t
#include <sys/resource.h>  // rlimit
#include <sys/stat.h>      // stat
#include <sys/time.h>      // itimerval
}

#include "junction/base/arch.h"
#include "junction/bindings/net.h"  // netaddr
#include "junction/kernel/sigframe.h"
#include "junction/snapshot/cereal.h"

// serialization of POD datastructures
namespace cereal {

template <class Archive>
void serialize(Archive &archive, rlimit &r) {
  archive(cereal::binary_data(reinterpret_cast<uint8_t *>(&r), sizeof(r)));
}

template <class Archive>
void serialize(Archive &archive, stack_t &s) {
  archive(cereal::binary_data(reinterpret_cast<uint8_t *>(&s), sizeof(s)));
}

template <class Archive>
void serialize(Archive &archive, itimerval &it) {
  archive(cereal::binary_data(reinterpret_cast<uint8_t *>(&it), sizeof(it)));
}

template <class Archive>
void serialize(Archive &archive, thread_tf &tf) {
  archive(cereal::binary_data(reinterpret_cast<uint8_t *>(&tf), sizeof(tf)));
}

template <class Archive>
void serialize(Archive &archive, siginfo_t &s) {
  archive(cereal::binary_data(reinterpret_cast<uint8_t *>(&s), sizeof(s)));
}

template <class Archive>
void serialize(Archive &archive, netaddr &n) {
  archive(n.ip, n.port);
}

template <class Archive>
void serialize(Archive &archive, struct stat &s) {
  archive(cereal::binary_data(reinterpret_cast<uint8_t *>(&s), sizeof(s)));
}

}  // namespace cereal
