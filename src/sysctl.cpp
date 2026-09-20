#include "tp/sysctl.hpp"

#include <signal.h>
#include <sys/sysctl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>

namespace tp {
namespace {

// atexit handlers take no argument, so the pending restores live here. Keyed by
// name, with a depth count: two guards on the same oid must collapse to ONE
// restore of the EARLIEST value, and the inner guard must not remove the outer
// guard's safety net when it goes out of scope.
struct Pending {
  int original = 0;
  int depth = 0;
};

std::map<std::string, Pending>& pending() {
  static std::map<std::string, Pending> m;
  return m;
}

void restore_all() {
  for (const auto& [name, p] : pending()) {
    int v = p.original;
    sysctlbyname(name.c_str(), nullptr, nullptr, &v, sizeof v);
  }
  pending().clear();
}

// Not async-signal-safe, and knowingly so. Walking a std::map and calling
// sysctlbyname() from a handler is undefined in the strict reading. The
// alternative is leaving a kernel knob modified on the machine of anyone who
// presses Ctrl-C, which is a worse outcome than a theoretical deadlock in a
// handler that immediately re-raises and dies. It is a real compromise, so it
// gets a comment instead of being quietly made.
void on_signal(int sig) {
  restore_all();
  signal(sig, SIG_DFL);
  raise(sig);
}

bool g_handlers_armed = false;

void arm_handlers() {
  if (g_handlers_armed) return;
  g_handlers_armed = true;
  atexit(restore_all);
  for (int sig : {SIGINT, SIGTERM, SIGHUP}) signal(sig, on_signal);
}

}  // namespace

int sysctl_get(const char* name, int fallback) {
  int v = 0;
  size_t sz = sizeof v;
  if (sysctlbyname(name, &v, &sz, nullptr, 0) < 0) return fallback;
  return v;
}

bool sysctl_set(const char* name, int value) {
  return sysctlbyname(name, nullptr, nullptr, &value, sizeof value) == 0;
}

ScopedSysctl::ScopedSysctl(const char* name, int value) : name_(name) {
  original_ = sysctl_get(name, -1);
  if (original_ < 0) return;
  if (!sysctl_set(name, value)) return;
  ok_ = true;

  Pending& p = pending()[name_];
  if (p.depth == 0) p.original = original_;  // outermost guard owns the value
  ++p.depth;
  arm_handlers();
}

ScopedSysctl::~ScopedSysctl() {
  if (!ok_) return;
  sysctl_set(name_.c_str(), original_);
  auto it = pending().find(name_);
  if (it == pending().end()) return;
  // Only the outermost guard retires the entry. Erasing unconditionally left a
  // nested guard tearing down the fallback restore for a guard still on the
  // stack, so an exit() between the two would have stranded the inner value.
  if (--it->second.depth <= 0) pending().erase(it);
}

TcpKnobs read_knobs() {
  TcpKnobs k{};
  k.rtt_min = sysctl_get("net.inet.tcp.rtt_min");
  k.rexmt_slop = sysctl_get("net.inet.tcp.rexmt_slop");
  k.enable_tlp = sysctl_get("net.inet.tcp.enable_tlp");
  k.delayed_ack = sysctl_get("net.inet.tcp.delayed_ack");
  k.mssdflt = sysctl_get("net.inet.tcp.mssdflt");
  k.sack = sysctl_get("net.inet.tcp.sack");
  k.rexmtthresh = sysctl_get("net.inet.tcp.rexmt_thresh");
  k.recvspace = sysctl_get("net.inet.tcp.recvspace");
  k.sendspace = sysctl_get("net.inet.tcp.sendspace");
  k.challengeack_limit = sysctl_get("net.inet.tcp.challengeack_limit");

  char buf[256] = {0};
  size_t sz = sizeof buf;
  if (sysctlbyname("kern.version", buf, &sz, nullptr, 0) == 0) {
    // kern.version is multi-line; the xnu tag is what matters for citing
    // source line numbers, so keep the line it appears on.
    char* p = strstr(buf, "root:xnu");
    k.kernel_version = p ? std::string(p) : std::string(buf);
    size_t nl = k.kernel_version.find('\n');
    if (nl != std::string::npos) k.kernel_version.resize(nl);
  }
  return k;
}

void print_knobs(const TcpKnobs& k) {
  printf("kernel            : %s\n", k.kernel_version.c_str());
  printf("rtt_min           : %d ms      rexmt_slop : %d ms\n", k.rtt_min, k.rexmt_slop);
  printf("enable_tlp        : %-9d delayed_ack: %d\n", k.enable_tlp, k.delayed_ack);
  printf("sack              : %-9d mssdflt    : %d\n", k.sack, k.mssdflt);
  printf("rexmt_thresh      : %-9d chalack_lim: %d\n", k.rexmtthresh, k.challengeack_limit);
  printf("sendspace         : %-9d recvspace  : %d\n", k.sendspace, k.recvspace);
}

}  // namespace tp
