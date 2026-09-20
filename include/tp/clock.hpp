#pragma once

// Monotonic milliseconds, off the Mach timebase.
//
// Everything this project measures lives between ~0.065 ms (a fast retransmit
// repairing a hole) and ~10 s (the far end of the RTO backoff ladder).
//
// This used to call clock_gettime(CLOCK_MONOTONIC) while the comment quoted
// mach_absolute_time's numbers, which was wrong twice over. Measured on this
// M1, 2M calls each:
//
//   clock_gettime(CLOCK_MONOTONIC)   35.8 ns/call, resolution 1000 ns
//   mach_absolute_time                7.1 ns/call, resolution 41.667 ns
//                                                  (timebase 125/3 ns per tick)
//
// The resolution is what matters, not the call cost. clock_gettime quantises to
// a microsecond, so the fastest results here -- the 0.065-0.144 ms early
// retransmits -- carried ~1% of quantisation, not the "1 part in 25,000" the
// old comment claimed. That is a 400x understatement of the error bar on the
// exact rows the early-retransmit argument rests on.
//
// mach_absolute_time is the raw counter clock_gettime is built on, so going
// straight to it removes the microsecond rounding and costs less. Nothing here
// is quoted in nanoseconds and nothing needs to be; the point is that the
// millisecond figures are now quantised at 41.667 ns instead of 1 us.

#include <mach/mach_time.h>

namespace tp {

inline double now_ms() {
  // The timebase is fixed for the life of the process, so it is fetched once.
  // On Apple Silicon it is 125/3, i.e. a 24 MHz counter.
  static const double kNsPerTick = [] {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return double(tb.numer) / double(tb.denom);
  }();
  // Deliberately NOT rebased to the first call. Rebasing looks tidier and buys
  // nothing: at this counter's magnitude a double's ULP is ~0.01 ns, which is
  // three orders of magnitude under the 41.667 ns tick, so precision is not the
  // constraint.
  //
  // What rebasing would cost is a canary. Every time in RunSummary and Trace is
  // relative to a trace origin, and mixing a raw now_ms() into one of those
  // fields is a mistake this project has made twice -- once printing a
  // retransmit at t=1418493399 ms, once turning a dup-ACK count of 3 into 48.
  // Both were obvious precisely because the raw value was astronomically wrong.
  // Rebased to process start, the same mistake yields a plausible small number
  // and hides.
  return double(mach_absolute_time()) * kNsPerTick / 1e6;
}

// Sleep that does not return early on a signal. usleep() returning EINTR
// halfway through a 1,200 ms window is exactly the bug that makes a
// "crossed the window boundary" test flap.
void sleep_ms(double ms);

}  // namespace tp
