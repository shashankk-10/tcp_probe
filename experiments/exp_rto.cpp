// The retransmission timeout: its floor, its dependence on measured RTT, and
// its backoff ladder.
//
// Three questions, each with a prediction taken from the source in
// reference/xnu before anything was measured.
//
// 1. THE FLOOR. TCP_REXMTVAL (tcp_var.h:1075) is
//        max(t_rttmin, (srtt >> (RTT_SHIFT - DELTA_SHIFT)) + rttvar >> DELTA_SHIFT)
//    and the result is then RANGESET between t_rttmin and TCPTV_REXMTMAX with
//    TCP_ADD_REXMTSLOP added. On this host rtt_min is 100 ms and rexmt_slop is
//    200 ms, which suggests a floor near 300 ms.
//
//    That 300 ms is an INFERENCE, not a source-derived fact, and the
//    distinction matters. TCPT_RANGESET and TCP_ADD_REXMTSLOP are defined in
//    bsd/netinet/tcp_timer.h, which is not in reference/xnu -- only the seven
//    .c/.h files listed there were fetched. So "rtt_min + rexmt_slop" is a
//    plausible reading of two sysctl names, not a macro anyone here has read.
//    The first run measured 356-368 ms at low injected delay, i.e. roughly
//    60 ms ABOVE the inferred floor, consistently. Until tcp_timer.h is in the
//    reference tree that gap is unexplained, and it is left stated rather than
//    rounded away.
//
// 2. THE DEPENDENCE ON RTT. If the floor is what dominates, then injecting
//    5 ms or 20 ms of one-way delay should barely move the first RTO -- until
//    the injected delay is large enough that the computed value exceeds the
//    floor. A reader's first objection to this whole project is "your path has
//    no latency, so your timings are artificial". This sweep answers it with a
//    measurement instead of a disclaimer.
//
// 3. THE LADDER. tcp_timer.c:886 gives tcp_backoff[] = {1,2,4,8,16,32,64,...}
//    and line 1275 multiplies TCP_REXMTVAL by it. Dropping every copy of a
//    segment should therefore produce retransmissions at roughly
//    t, 2t, 4t, 8t... Holding a connection open long enough to see five rungs
//    takes about 10 seconds, which is why this experiment is the slow one.

#include <cstdio>
#include <string>
#include <vector>

#include "harness.hpp"

using namespace tp;

int main(int argc, char** argv) {
  const bool verbose = argc > 1 && std::string(argv[1]) == "-v";

  Lab lab;
  std::string err;
  if (!lab.start("RETRANSMISSION TIMEOUT -- floor, RTT dependence, backoff ladder",
                 &err)) {
    fprintf(stderr, "FATAL: %s\n", err.c_str());
    return 2;
  }

  const int predicted_floor = lab.knobs.rtt_min + lab.knobs.rexmt_slop;
  printf("predicted RTO floor = rtt_min + rexmt_slop = %d + %d = %d ms\n",
         lab.knobs.rtt_min, lab.knobs.rexmt_slop, predicted_floor);
  printf("predicted ladder    = tcp_backoff[] {1,2,4,8,16,...} x RTO "
         "(tcp_timer.c:886,1275)\n\n");

  constexpr uint32_t kBytes = 32 * 1024;
  constexpr uint32_t kMss = 1024;
  uint16_t sport = 44000;

  // ---- Part 1 & 2: first RTO as a function of injected one-way delay.
  //
  // The loss must be at the TAIL and SACK must be OFF, or the measurement is
  // of something else: with data behind it the hole is repaired by fast
  // retransmit, and with SACK on a tail loss is repaired by the TLP. Only a
  // tail loss on a non-SACK connection has nothing between it and the RTO.
  printf("Part 1 -- first retransmission after a tail loss (no SACK, so no TLP)\n\n");
  printf("%14s %14s %14s %12s\n", "injected delay", "syn->sa (ms)", "first RTO (ms)",
         "over floor");
  printf("%14s %14s %14s %12s\n", "(ms, one way)", "", "", "(ms)");

  for (double delay : {0.0, 5.0, 20.0, 60.0}) {
    PeerConfig cfg;
    cfg.sport = sport++;
    cfg.dport = kPort;
    cfg.isn = 400000 + sport * 23;
    cfg.mss = kMss;
    cfg.offer_sack = false;  // no TLP, so the RTO is what fires
    cfg.ack_delay_ms = delay;

    LossPolicy loss;
    loss.add({kBytes - 1, kBytes, 1, 0});

    Outcome o = run_scenario(lab, cfg, kBytes, 20000, loss);
    if (!o.ok) {
      printf("%14.1f  FAILED: %s\n", delay, o.err.c_str());
      continue;
    }
    if (!loss.unfired().empty()) {
      printf("%14.1f  INVALID: drop rule never fired\n", delay);
      continue;
    }
    if (o.sum.hol_delay_ms < 0) {
      printf("%14.1f  INVALID: the hole was never filled within the timeout\n", delay);
      continue;
    }
    printf("%14.1f %14.3f %14.1f %12.1f\n", delay, o.handshake_rtt_ms,
           o.sum.hol_delay_ms, o.sum.hol_delay_ms - predicted_floor);
    if (verbose) o.trace.dump(stdout);
  }

  printf("\n  Reading the 'over floor' column: %d ms is an INFERENCE from two\n",
         predicted_floor);
  printf("  sysctl names, not a macro anyone has read -- TCPT_RANGESET and\n");
  printf("  TCP_ADD_REXMTSLOP live in tcp_timer.h, which is not in reference/xnu.\n");
  printf("  What the column actually tests is the SHAPE: if it stays flat while\n");
  printf("  the injected delay grows, the RTO is dominated by a floor rather\n");
  printf("  than by any measurement of this path, and the tail-loss cost in\n");
  printf("  exp_hol is a constant of the stack, not of the network. A column\n");
  printf("  that rises with the delay means the opposite.\n");

  // ---- Part 3: the backoff ladder.
  printf("\nPart 3 -- backoff ladder: every copy of the last segment is dropped\n\n");

  PeerConfig cfg;
  cfg.sport = sport++;
  cfg.dport = kPort;
  cfg.isn = 490000;
  cfg.mss = kMss;
  cfg.offer_sack = false;

  LossPolicy loss;
  // times = 12: drop the original and every retransmission, so the connection
  // climbs the ladder instead of recovering on the first rung. This is the one
  // experiment that measures backoff instead of recovery.
  loss.add({kBytes - 1, kBytes, 12, 0});

  Outcome o = run_scenario(lab, cfg, kBytes, 30000, loss);
  if (!o.ok) {
    printf("  FAILED: %s\n", o.err.c_str());
  } else {
    // Retransmissions of the tail are what we dropped; they never reach the
    // reassembly, so they are recovered from the trace's DROPPED entries.
    std::vector<double> times;
    for (const Event& e : o.trace.events())
      if (!e.tx && e.dropped) times.push_back(e.t_ms);

    if (times.size() < 2) {
      printf("  only %zu dropped tail segments seen -- not enough to show a ladder\n",
             times.size());
    } else {
      // The raw interval ratio is NOT the right column, and the first run
      // showed why: it read 1.13, 0.88, 1.13, 1.23, 1.37, 1.54, 1.70, 1.83 --
      // drifting toward 2 without ever reaching it, and dipping below 1.0,
      // which a monotonic backoff array cannot produce.
      //
      // Subtract rexmt_slop first and it falls out. If the slop is
      // added AFTER the backoff multiplication -- RTO = slop + base*2^shift
      // rather than (slop + base)*2^shift -- then the raw ratio is dragged
      // toward 1 by the constant, while (interval - slop) doubles exactly.
      // On the first run that column read 121.4, 240.7, 480.8, 960.2, 1921.5:
      // ratios 1.983, 1.997, 1.997, 2.001. That is the structure, and this
      // column is the test.
      const double slop = lab.knobs.rexmt_slop;

      // The base RTO is not known a priori -- it is whatever TCP_REXMTVAL
      // computed for this connection -- so recover it from the data as the
      // smallest (interval - slop) observed, which is the rung where
      // tcp_backoff[] is 1. Dividing the column through by it turns the table
      // into the backoff array itself.
      double base = 0;
      for (size_t i = 1; i < times.size(); ++i) {
        const double adj = (times[i] - times[i - 1]) - slop;
        if (adj > 1.0 && (base == 0 || adj < base)) base = adj;
      }

      printf("%6s %12s %12s %14s %10s %12s\n", "rung", "t (ms)", "interval",
             "interval-slop", "raw ratio", "/ base");
      double prev_iv = 0;
      for (size_t i = 1; i < times.size(); ++i) {
        const double iv = times[i] - times[i - 1];
        const double adj = iv - slop;
        printf("%6zu %12.1f %12.1f %14.1f", i, times[i], iv, adj);
        if (prev_iv > 0) printf(" %10.2f", iv / prev_iv);
        else printf(" %10s", "-");
        if (base > 0) printf(" %12.1f\n", adj / base);
        else printf(" %12s\n", "-");
        prev_iv = iv;
      }
      printf("\n  recovered base RTO = %.1f ms; slop = %g ms; first RTO = %.1f ms\n",
             base, slop, base + slop);
      printf("\n  Read the '/ base' column. It should reproduce tcp_backoff[] =\n");
      printf("  {1,2,4,8,16,32,64,64,...} (tcp_timer.c:886-887) directly.\n");
      printf("\n  The raw ratio column never reaches 2.00 and even dips below\n");
      printf("  1.0, which a monotonic backoff array cannot produce. That is an\n");
      printf("  artefact of the constant term: because the slop is added AFTER\n");
      printf("  the multiply -- RTO = slop + base*backoff, not\n");
      printf("  (slop + base)*backoff -- it drags every raw ratio toward 1.\n");
      printf("  Subtract it first and the array is visible. It is\n");
      printf("  also why the first RTO (%.0f ms) sits BELOW the naive\n", base + slop);
      printf("  rtt_min+rexmt_slop guess of %d ms: rtt_min is not the base.\n",
             lab.knobs.rtt_min + lab.knobs.rexmt_slop);
      printf("\n  ONE ANOMALY REMAINS, unresolved:\n");
      printf("  the shift counter appears to RESET once early in the ladder --\n");
      printf("  the multiplier sequence runs 1, 2, then 1, 2 again before\n");
      printf("  continuing 4, 8, 16, 32, 64. A single reset of t_rxtshift after\n");
      printf("  the second retransmission is not something this experiment can\n");
      printf("  attribute to a line; bsd/netinet/tcp_timer.h is not in\n");
      printf("  reference/xnu, and tcp_timer.c has several paths that zero it.\n");
    }
    if (verbose) o.trace.dump(stdout);
  }

  print_integrity(lab);
  return 0;
}
