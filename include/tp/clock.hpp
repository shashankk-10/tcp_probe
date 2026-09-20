#pragma once

// Monotonic milliseconds off the Mach timebase.
//
// Measured on this M1, 2M calls each:
//   clock_gettime(CLOCK_MONOTONIC)   35.8 ns/call, resolves to 1000 ns
//   mach_absolute_time                7.1 ns/call, resolves to 41.667 ns
//
// Resolution matters here, call cost does not. The fastest thing measured is a
// ~0.065 ms fast retransmit, and clock_gettime's microsecond step puts about 1%
// of quantisation on it. The raw counter puts 41.667 ns.

#include <mach/mach_time.h>

namespace tp {

inline double now_ms() {
  static const double kNsPerTick = [] {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return double(tb.numer) / double(tb.denom);  // 125/3 on Apple Silicon
  }();
  // Not rebased to the first call. Rebasing would make a raw value mixed into a
  // trace-relative field look plausible instead of absurd, and that mistake has
  // happened here twice. Precision does not need it: the ULP is ~0.01 ns.
  return double(mach_absolute_time()) * kNsPerTick / 1e6;
}

// Does not return early on a signal. usleep() giving up part way through a
// 1,200 ms window will flap a "crossed the window boundary" test.
void sleep_ms(double ms);

}  // namespace tp
