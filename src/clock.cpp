#include "tp/clock.hpp"

#include <cerrno>
#include <ctime>  // nanosleep/timespec; clock.hpp used to drag this in by accident

namespace tp {

void sleep_ms(double ms) {
  if (ms <= 0) return;
  struct timespec req;
  req.tv_sec = time_t(ms / 1000.0);
  req.tv_nsec = long((ms - double(req.tv_sec) * 1000.0) * 1e6);
  // nanosleep returns EINTR with the remaining time in `rem`. Returning early
  // from a "wait past the window boundary" sleep turns a deterministic test
  // into a flaky one, so finish the interval.
  struct timespec rem;
  while (nanosleep(&req, &rem) != 0 && errno == EINTR) req = rem;
}

}  // namespace tp
