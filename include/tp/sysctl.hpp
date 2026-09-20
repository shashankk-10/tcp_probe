#pragma once

// Reading and temporarily changing net.inet.tcp.* knobs.
//
// Several experiments here are only convincing because of a control run: if
// the cap observed on retransmissions really is tcprexmtthresh and not some
// other mechanism, then changing tcprexmtthresh must move it, exactly. That
// requires writing a live kernel sysctl, which means it also requires putting
// it back -- including on the paths where the experiment aborts.

#include <string>
#include <vector>

namespace tp {

// Returns the current integer value, or `fallback` if the oid does not exist
// on this kernel (several of these were renamed across releases, and an
// experiment that silently reads -1 and carries on reports nonsense).
int sysctl_get(const char* name, int fallback = -1);
bool sysctl_set(const char* name, int value);

// RAII guard: restores the original value on destruction, including during
// stack unwinding. Registers an atexit handler as well, because an experiment
// that calls exit() on a hard error would otherwise leave the machine's TCP
// stack detuned after the process is gone.
//
// atexit is not enough on its own. It does not run on a signal, and the most
// likely way anyone kills one of these experiments is Ctrl-C while it sits in a
// 1.2-second sleep waiting for a rate-limit window to roll over. That would
// leave net.inet.tcp.challengeack_limit at 3 on the user's machine until the
// next reboot, which is a real change to a stranger's kernel from a program
// they ran once. So SIGINT/SIGTERM/SIGHUP are handled too, and the handler
// restores before re-raising with the default disposition.
class ScopedSysctl {
 public:
  ScopedSysctl(const char* name, int value);
  ~ScopedSysctl();
  ScopedSysctl(const ScopedSysctl&) = delete;
  ScopedSysctl& operator=(const ScopedSysctl&) = delete;

  bool ok() const { return ok_; }
  int original() const { return original_; }

 private:
  std::string name_;
  int original_ = -1;
  bool ok_ = false;
};

// Snapshot of every knob an experiment's numbers depend on, printed at the top
// of each run. A result table without this is unreproducible: the same binary
// on the same machine gives different retransmission timings if rtt_min or
// rexmt_slop was touched, and nothing in the output would say so.
struct TcpKnobs {
  int rtt_min, rexmt_slop, enable_tlp, delayed_ack, mssdflt, sack, rexmtthresh;
  int recvspace, sendspace, challengeack_limit;
  std::string kernel_version;
};
TcpKnobs read_knobs();
void print_knobs(const TcpKnobs& k);

}  // namespace tp
