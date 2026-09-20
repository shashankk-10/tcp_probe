// The duplicate-ACK threshold is not 3.
//
// This experiment was built to confirm the textbook rule -- three duplicate
// ACKs trigger fast retransmit -- and it failed to, twice, for two different
// reasons. The second failure is the result.
//
// ATTEMPT 1 dropped a segment half way through a 96 KB transfer and counted the
// duplicate ACKs preceding the retransmission. The count was 48: ~48 segments
// were already in flight behind the hole and every one drew a duplicate ACK.
// The kernel retransmitted on the 3rd; the other 45 were in flight before its
// retransmission got back. Counting responses cannot recover a threshold when
// the stimulus overshoots it 16x.
//
// ATTEMPT 2 capped the stimulus: place the drop so exactly N segments follow,
// which caps the duplicate ACKs at N, and sweep N upward looking for the step
// where recovery goes from timer-speed to RTT-speed. There was no step. Every
// N from 1 to 4 recovered in under 0.2 ms -- including N=1, where only ONE
// duplicate ACK can ever be sent.
//
// The reason is tcp_early_rexmt_check(), tcp_input.c:1491, implementing
// RFC 5827. When the outstanding window is small the threshold is LOWERED:
//
//     if (osegs < 4) {
//         tp->t_rexmtthresh = ((osegs - 1) > 1) ? (osegs - 1) : 1;
//         tp->t_rexmtthresh = MIN(tp->t_rexmtthresh, tcprexmtthresh);
//
// With N segments behind the hole the outstanding count is N+1, so the
// effective threshold is min(3, max(N, 1)) -- which is never greater than N,
// the number of duplicate ACKs available. The sweep can therefore never find a
// step, and `tcprexmtthresh = 3` is an upper BOUND on a per-connection value,
// not the rule. That is the finding.
//
// THE CONTROL. An adaptive threshold and a fast timer are still hard to tell
// apart from timing alone, so this needs a prediction that only early
// retransmit can make. tcp_input.c:319-323 supplies one:
//
//     #define TCP_EARLY_REXMT_WIN   (60 * TCP_RETRANSHZ)   /* 60 seconds */
//     #define TCP_EARLY_REXMT_LIMIT 10
//
// gated at line 1497 by
//
//     if ((SACK_ENABLED(tp) || tp->t_early_rexmt_count < TCP_EARLY_REXMT_LIMIT) && ...
//
// So on a connection WITHOUT SACK, early retransmit is allowed at most 10 times
// per 60 seconds; with SACK the counter is bypassed entirely. Prediction: take
// 12 single-segment losses in a row on one non-SACK connection and the first
// ~10 recover in well under a millisecond while the later ones fall off a cliff
// to the full RTO -- and the same 12 losses on a SACK connection never degrade.
// A timer cannot produce a cliff at a count.

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "harness.hpp"
#include "tp/sysctl.hpp"

using namespace tp;

namespace {

constexpr uint32_t kMss = 1024;

// Part 1: sweep the number of segments behind the hole.
void sweep_followers(Lab& lab, uint16_t* sport, bool verbose) {
  constexpr uint32_t kBytes = 96 * 1024;
  printf("\nPart 1 -- cap the stimulus: exactly N segments follow the hole\n");
  printf("(SACK off, so neither SACK recovery nor the tail loss probe can repair it)\n\n");
  printf("  %-12s %12s %10s %14s %s\n", "segments", "HoL (ms)", "dupACKs",
         "predicted", "recovery");
  printf("  %-12s %12s %10s %14s %s\n", "after hole", "", "sent", "threshold", "");

  for (int n = 1; n <= 5; ++n) {
    PeerConfig cfg;
    cfg.sport = (*sport)++;
    cfg.dport = kPort;
    cfg.isn = 300000 + uint32_t(cfg.sport) * 19;
    cfg.mss = kMss;
    cfg.offer_sack = false;

    const uint32_t off = kBytes - uint32_t(n + 1) * kMss;
    LossPolicy loss;
    loss.add({off, off + 1, 1, 0});

    Outcome o = run_scenario(lab, cfg, kBytes, 15000, loss);
    if (!o.ok || !loss.unfired().empty() || !o.sum.completed ||
        o.sum.ack_send_failures > 0) {
      const char* why = "incomplete";
      if (!o.ok) why = o.err.c_str();
      else if (!loss.unfired().empty()) why = "rule never fired";
      else if (o.sum.ack_send_failures > 0) why = "ACK send failed";
      printf("  %2d           INVALID (%s)\n", n, why);
      continue;
    }

    // osegs = the hole plus everything behind it.
    const int osegs = n + 1;
    const int predicted = osegs < 4 ? std::min(3, std::max(osegs - 1, 1))
                                    : lab.knobs.rexmtthresh;
    printf("  %2d           %12.3f %10d %14d %s\n", n, o.sum.hol_delay_ms,
           o.sum.dup_acks_sent, predicted,
           o.sum.hol_delay_ms < 50 ? "fast" : "timer");
    if (verbose) o.trace.dump(stdout);
  }
  printf("\n  Note the N=1 row. One duplicate ACK, and it still recovers at RTT\n");
  printf("  speed. Under a fixed threshold of 3 that is impossible.\n");
}

// Part 2: the control. Repeated single-segment losses on ONE connection.
void rate_limit(Lab& lab, uint16_t* sport, bool sack, bool verbose) {
  // Each round delivers a chunk and loses one segment near its end, leaving 1
  // segment behind the hole so every repair must come from early retransmit.
  constexpr int kRounds = 14;
  constexpr uint32_t kChunk = 8 * kMss;

  PeerConfig cfg;
  cfg.sport = (*sport)++;
  cfg.dport = kPort;
  cfg.isn = 600000 + uint32_t(cfg.sport) * 29;
  cfg.mss = kMss;
  cfg.offer_sack = sack;
  cfg.send_sack_blocks = sack;

  Trace tr;
  Peer p(lab.utun, tr, cfg);
  std::string err;
  if (!p.establish(lab.listen_fd, &err)) {
    printf("  %s: could not establish: %s\n", sack ? "SACK" : "no SACK", err.c_str());
    return;
  }
  if (p.peer_sack_ok() != sack) {
    printf("  %s: negotiation disagreed with the arm -- skipping\n",
           sack ? "SACK" : "no SACK");
    p.reset();
    return;
  }

  printf("\n  %s connection, %d consecutive single-segment losses:\n",
         sack ? "SACK       " : "no SACK    ", kRounds);
  printf("    %-7s %12s %10s\n", "round", "HoL (ms)", "recovery");

  std::vector<uint8_t> buf(kChunk);
  for (uint32_t i = 0; i < kChunk; ++i) buf[i] = uint8_t(i * 31 + 7);

  int fast = 0, slow = 0;
  for (int r = 0; r < kRounds; ++r) {
    const uint32_t base = uint32_t(r) * kChunk;
    if (write(p.accepted_fd(), buf.data(), buf.size()) != ssize_t(buf.size())) {
      printf("    round %d: short write\n", r);
      break;
    }
    // Lose the second-to-last segment of this chunk, leaving exactly one
    // behind it.
    const uint32_t off = base + kChunk - 2 * kMss;
    LossPolicy loss;
    loss.add({off, off + 1, 1, 0});

    RunSummary s = p.receive(base + kChunk, 5000, loss);
    if (!loss.unfired().empty() || !s.completed || s.ack_send_failures > 0) {
      const char* why = "incomplete";
      if (!loss.unfired().empty()) why = "no drop";
      // An ACK this peer could not write starves the kernel of exactly the
      // signal that drives fast retransmit, so the round would time out and
      // read as a budget exhaustion that never happened.
      if (s.ack_send_failures > 0) why = "ACK send failed";
      printf("    %-7d %12s %10s\n", r, "-", why);
      continue;
    }
    const bool is_fast = s.hol_delay_ms >= 0 && s.hol_delay_ms < 50;
    is_fast ? ++fast : ++slow;
    printf("    %-7d %12.3f %10s\n", r, s.hol_delay_ms, is_fast ? "fast" : "TIMER");
  }
  printf("    => %d fast, %d timer\n", fast, slow);
  if (verbose) tr.dump(stdout);
  p.reset();
}

}  // namespace

int main(int argc, char** argv) {
  const bool verbose = argc > 1 && std::string(argv[1]) == "-v";

  Lab lab;
  std::string err;
  if (!lab.start("DUPLICATE-ACK THRESHOLD -- it is not 3, it adapts", &err)) {
    fprintf(stderr, "FATAL: %s\n", err.c_str());
    return 2;
  }

  printf("net.inet.tcp.rexmt_thresh = %d (tcp_input.c:265). sysctl_rexmtthresh\n",
         lab.knobs.rexmtthresh);
  printf("(tcp_input.c:7831) accepts only 2 or 3; anything else returns EINVAL.\n");
  printf("tcp_early_rexmt_check (tcp_input.c:1491, RFC 5827) lowers the\n");
  printf("PER-CONNECTION threshold to max(osegs-1, 1) when osegs < 4, and is\n");
  printf("capped at 10 uses per 60 s UNLESS SACK is enabled (lines 319-323, 1497).\n");

  uint16_t sport = 43000;
  sweep_followers(lab, &sport, verbose);

  printf("\nPart 2 -- the control: exhaust the early-retransmit budget\n");
  printf("Prediction: without SACK the first ~%d losses repair fast and the rest\n",
         10);
  printf("fall to the RTO. With SACK the counter is bypassed and none degrade.\n");
  rate_limit(lab, &sport, /*sack=*/false, verbose);
  rate_limit(lab, &sport, /*sack=*/true, verbose);

  printf("\nA cliff at a COUNT cannot be produced by a timer. If the no-SACK arm\n");
  printf("steps to RTO-speed partway down and the SACK arm does not, the fast\n");
  printf("recoveries in Part 1 were early retransmit.\n");

  print_integrity(lab);
  return 0;
}
