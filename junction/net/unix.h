#pragma once

#include "junction/net/socket.h"
#include "junction/snapshot/cereal.h"

namespace junction {

Status<std::shared_ptr<Socket>> CreateUnixSocket(int type, int protocol,
                                                 int flags);

// Serialize socket tables.
template <class Archive>
void SerializeUnixSocketState(Archive &ar);

}  // namespace junction