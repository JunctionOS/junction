#pragma once

#include "junction/net/socket.h"

namespace junction {

Status<std::shared_ptr<Socket>> CreateNetlinkSocket(int type, int flags,
                                                    int protocol);

}