#include "junction/net/caladan_poll.h"

#include "junction/fs/poll.h"

namespace junction {

void PollSourceClear(unsigned long poller_data, unsigned int event_mask) {
  PollSource *src = reinterpret_cast<PollSource *>(poller_data);
  src->Clear(event_mask);
}

void PollSourceSet(unsigned long poller_data, unsigned int event_mask) {
  PollSource *src = reinterpret_cast<PollSource *>(poller_data);
  src->Set(event_mask);
}

}  // namespace junction
