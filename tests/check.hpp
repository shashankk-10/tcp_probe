#pragma once

// A three-line test harness. A dependency-free repo that anyone can build with
// cmake && ctest is worth more here than the features a framework would add,
// and the assertions in this project are all "this number equals that number".

#include <cstdio>
#include <cstdlib>
#include <type_traits>

namespace check {

inline int g_failed = 0;
inline int g_total = 0;

inline void report(const char* file, int line, const char* expr, bool ok) {
  ++g_total;
  if (ok) return;
  ++g_failed;
  fprintf(stderr, "  FAIL %s:%d  %s\n", file, line, expr);
}

inline int finish(const char* suite) {
  printf("%s: %d/%d passed\n", suite, g_total - g_failed, g_total);
  return g_failed == 0 ? 0 : 1;
}

}  // namespace check

#define CHECK(expr) ::check::report(__FILE__, __LINE__, #expr, (expr))
// CHECK_EQ formats its operands as integers, so strings need their own macro
// rather than a clever template -- the diagnostic is the useful part and a
// generic version would print neither side.
#define CHECK_STR(a, b)                                                         \
  do {                                                                          \
    std::string _a = (a);                                                       \
    std::string _b = (b);                                                       \
    bool _ok = (_a == _b);                                                      \
    ::check::report(__FILE__, __LINE__, #a " == " #b, _ok);                     \
    if (!_ok)                                                                   \
      fprintf(stderr, "       got \"%s\", want \"%s\"\n", _a.c_str(),           \
              _b.c_str());                                                      \
  } while (0)
// The reassembly suite compares times, so the diagnostic has to know the
// difference between an integer and a double. Printing a failed
// time_reached(1100) == 10.5 as "got 10, want 10" is worse than printing
// nothing -- it makes a real failure look like a harness bug.
#define CHECK_EQ(a, b)                                                          \
  do {                                                                          \
    auto _a = (a);                                                              \
    auto _b = (b);                                                              \
    bool _ok = (_a == _b);                                                      \
    ::check::report(__FILE__, __LINE__, #a " == " #b, _ok);                     \
    if (!_ok) {                                                                 \
      if constexpr (std::is_floating_point_v<decltype(_a)> ||                   \
                    std::is_floating_point_v<decltype(_b)>)                     \
        fprintf(stderr, "       got %.6g, want %.6g\n", (double)_a, (double)_b); \
      else                                                                      \
        fprintf(stderr, "       got %lld, want %lld\n", (long long)_a,          \
                (long long)_b);                                                 \
    }                                                                           \
  } while (0)
