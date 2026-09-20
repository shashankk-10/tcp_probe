// Baseline: what the path costs when nothing is lost.
//
// This experiment produces no headline. It exists so the ones that do have a
// floor to be quoted against. A "0.4 ms recovery" means nothing until a reader
// knows that an uninterrupted round trip on this path is 0.2 ms; a "312 ms
// recovery" means nothing until they know it is not 312 ms of utun overhead.
//
// It also checks the two negotiated values every later experiment depends on:
// the MSS the kernel adopted (which fixes where segment boundaries fall, and
// therefore what a byte-offset drop rule selects) and whether SACK was agreed
// (which, per tcp_output.c:2966, decides whether a tail loss probe can arm at
// all).

#include <algorithm>
#include <cstdio>
#include <vector>

#include "harness.hpp"

using namespace tp;

int main(int argc, char** argv) {
  const bool verbose = argc > 1 && std::string(argv[1]) == "-v";

  Lab lab;
  std::string err;
  if (!lab.start("BASELINE -- an unimpaired transfer, to anchor every other number",
                 &err)) {
    fprintf(stderr, "FATAL: %s\n", err.c_str());
    return 2;
  }

  struct Arm {
    const char* name;
    bool sack;
    double ack_delay_ms;
  };
  const Arm arms[] = {
      {"no SACK, no injected delay", false, 0.0},
      {"SACK,    no injected delay", true, 0.0},
      {"SACK,    5 ms ACK delay", true, 5.0},
      {"SACK,   20 ms ACK delay", true, 20.0},
  };

  constexpr uint32_t kBytes = 64 * 1024;
  uint16_t sport = 41000;

  printf("%-28s %9s %9s %9s %7s %7s %8s\n", "arm", "syn->sa", "transfer", "goodput",
         "segs", "mss", "sackOK");
  printf("%-28s %9s %9s %9s %7s %7s %8s\n", "---", "(ms)", "(ms)", "(MB/s)", "", "", "");

  for (const Arm& a : arms) {
    PeerConfig cfg;
    cfg.sport = sport++;
    cfg.dport = kPort;
    // Derived from cfg.sport, not from `sport`, which the line above has already
    // moved on. Any distinct value works, but reading the counter post-increment
    // looks like an off-by-one every time someone reviews it.
    cfg.isn = 100000 + uint32_t(cfg.sport) * 13;
    cfg.mss = 1024;
    cfg.offer_sack = a.sack;
    cfg.ack_delay_ms = a.ack_delay_ms;

    LossPolicy none;  // deliberately empty: this is the unimpaired arm
    Outcome o = run_scenario(lab, cfg, kBytes, 20000, none);
    if (!o.ok) {
      printf("%-28s  FAILED: %s\n", a.name, o.err.c_str());
      continue;
    }

    // Every inbound segment carrying data, retransmissions included. That is
    // only the right count because this arm has no loss policy, so there should
    // be no retransmissions at all -- and if there are, the check below says so
    // and the "unimpaired" label is wrong.
    int data_segs = 0;
    uint32_t max_len = 0;
    for (const Event& e : o.trace.events())
      if (!e.tx && e.len > 0) {
        ++data_segs;
        max_len = std::max(max_len, e.len);
      }

    const double transfer = o.sum.t_last_original - o.sum.t_first_data;
    const double mbps =
        transfer > 0 ? (double(o.sum.bytes_delivered) / 1e6) / (transfer / 1000.0) : 0;

    printf("%-28s %9.3f %9.3f %9.1f %7d %7u %8s%s\n", a.name, o.handshake_rtt_ms,
           transfer, mbps, data_segs, max_len, o.sack_negotiated ? "yes" : "no",
           o.sum.completed ? "" : "  INCOMPLETE");

    if (!o.sum.retransmits.empty()) {
      // With an injected ACK delay this is expected and is not a fault: srtt
      // rises to about the delay, the tail loss probe arms at
      // 2*srtt + tcp_delack, and at the end of the transfer it fires before our
      // delayed ACK for the last segment gets back. The kernel resends a
      // segment that was never lost. Worth seeing -- it is the TLP being
      // measured by accident on the one arm that has no loss at all -- but it
      // says nothing about the harness.
      //
      // With NO injected delay there is no such excuse, and a retransmission
      // means the path really is dirty.
      const char* verdict = a.ack_delay_ms > 0
                                ? "expected: injected ACK delay arms the TLP"
                                : "UNEXPLAINED -- no loss and no delay, the path is dirty";
      printf("    NOTE: %zu retransmission(s) on a run with no loss policy (%s).\n",
             o.sum.retransmits.size(), verdict);
    }
    // No short-write check here: run_scenario() now fails the whole arm on one,
    // so it is reported by the !o.ok branch above and this would be dead.
    if (verbose) o.trace.dump(stdout);
  }

  printf("\nReading this table:\n");
  printf("  syn->sa is the floor. It is one round trip through utun plus the\n");
  printf("  stack's own handling, measured on this process's clock, and no\n");
  printf("  recovery interval in the other experiments can be smaller.\n");
  printf("  mss should equal what we advertised (1024). If the kernel used\n");
  printf("  mssdflt=%d instead, our MSS option was not parsed and every drop\n",
         lab.knobs.mssdflt);
  printf("  rule expressed in byte offsets selects a different segment.\n");
  printf("  The injected delay is ONE WAY, on our ACKs only: the kernel's RTT\n");
  printf("  sample is ~= the delay, not twice it.\n");

  print_integrity(lab);
  return 0;
}
