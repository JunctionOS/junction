#pragma once

namespace junction {

extern "C" {
void PollSourceClear(unsigned long poller_data, unsigned int event_mask);
void PollSourceSet(unsigned long poller_data, unsigned int event_mask);
}
}  // namespace junction
