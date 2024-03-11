#include "junction/bindings/log.h"

namespace junction::rt {

Logger::~Logger() { logk(level_, "%s", buf_.str().c_str()); }

}  // namespace junction::rt
