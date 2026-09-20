// Head-of-line blocking: what one lost segment costs the receiving
// application, as a function of WHERE it was lost and whether the receiver
// offered SACK.
//
// This is the experiment the project exists for. The claim it tests is not
// "TCP retransmits" -- everyone knows that. It is that the cost of a single
// loss is bimodal, and which mode you land in is decided by facts that have
// nothing to do with the loss itself:
//
//   1. A loss with data behind it is repaired by fast retransmit. Later
//      segments keep arriving, each draws a duplicate ACK, and at
//      tcprexmtthresh (= 3, tcp_input.c:265) the kernel resends without
//      waiting for any timer. Cost: about one round trip.
//
//   2. A loss with NOTHING behind it generates no duplicate ACKs, because
//      there is no later data to trigger them. The kernel cannot know the
//      segment is gone until a timer says so.
//
//   3. In case 2 the kernel has a mitigation -- the Tail Loss Probe -- but
//      tcp_output.c:2966 arms it only when SACK_ENABLED(tp). SACK is enabled
//      only if the PEER offered SACK-permitted in its SYN. So a receiver that
//      omits two bytes of TCP option in its first packet loses TLP entirely
//      and pays the full retransmission timeout instead.
//
// (3) is the part that is not obvious, and it is why this experiment runs the
// same loss pattern twice with only the SYN's option field changed.
//
// PREDICTIONS, from the source in reference/xnu (state them before measuring;
// a prediction written after the fact is not a prediction):
//   - mid-stream loss  : ~1 RTT, so on this path a fraction of a millisecond.
//   - tail loss + SACK : pto = 2*srtt + (inflight <= maxseg ? tcp_delack : 2),
//                        clamped down to t_rxtcur.
//   - tail loss, no SACK: t_rxtcur, which RANGESETs to at least
//                        rtt_min (=100 ms) + rexmt_slop (=200 ms) on this host.

#include <cstdio>
#include <string>
#include <vector>

#include "harness.hpp"

using namespace tp;

namespace {

struct Arm {
  const char* name;
  bool sack;
  bool tail;  // drop the last segment instead of one in the middle
};

// Names the mechanism that repaired the loss. Three outcomes matter here, not
// two, and the earlier version of this collapsed the last two into "timer" --
// which put the headline result (a tail loss repaired in ~3 ms by the TLP) in
// the same bucket as the thing it is being contrasted against (the same loss
// costing a full RTO). The table then needed a reader to derive the finding
// from a byte offset printed on a sub-line.
//
// Separating fast retransmit is easy: it is driven by duplicate ACKs, so the
// count of them is direct evidence.
//
// Separating TLP from RTO is the interesting one. The obvious test is WHICH
// bytes came back -- a TLP resends the last segment, an RTO resends from
// snd_una -- but that test degenerates in precisely the case this experiment
// cares about: when the TAIL segment is the one lost, the last segment and
// snd_una are the same bytes, and both arms retransmit from the identical
// offset. (They do: off=97280 in both tail rows.)
//
// What does separate them is the floor. t_rxtcur RANGESETs to at least
// rtt_min + rexmt_slop, so a retransmission arriving materially before that
// floor cannot be the retransmission timer, and TLP is the only other timer in
// tcp_output that can have sent it. That is an argument from the kernel's own
// clamp rather than from a threshold picked to fit the data, which is why the
// floor is passed in from the live sysctls instead of hardcoded.
const char* classify(const RunSummary& s, int dupack_thresh, int rto_floor_ms) {
  if (s.retransmits.empty()) return "none";
  // The kernel resent something but the frontier never passed the hole inside
  // the timeout. Calling that "rto" would put a failed arm in the same column
  // as a successful one.
  if (s.hol_delay_ms < 0) return "unrepaired";
  if (s.dup_acks_sent >= dupack_thresh) return "fast-retransmit";
  // Half the floor is a deliberately loose line: the measured first RTO on this
  // host is ~230 ms against a nominal 300 ms floor, so a tight comparison
  // against the nominal value would misclassify every RTO. TLP lands two orders
  // of magnitude below either.
  if (s.hol_delay_ms < rto_floor_ms / 2.0) return "tlp";
  return "rto";
}

}  // namespace

int main(int argc, char** argv) {
  const bool verbose = argc > 1 && std::string(argv[1]) == "-v";

  Lab lab;
  std::string err;
  if (!lab.start("HEAD-OF-LINE BLOCKING -- the cost of one lost segment", &err)) {
    fprintf(stderr, "FATAL: %s\n", err.c_str());
    return 2;
  }

  constexpr uint32_t kBytes = 96 * 1024;
  constexpr uint32_t kMss = 1024;
  // Mid-stream means "with enough data behind it to raise rexmt_thresh
  // duplicate ACKs", and that is a constraint on the offset, not a vibe. Early
  // in the connection cwnd is still one initial window (~10 segments), so a
  // drop at 8 KB may have only one or two segments behind it and would fall
  // through to a timer -- producing a "mid-stream" row that is secretly
  // measuring the same thing as the tail rows. Half way into a 96 KB transfer
  // the window has grown and ~64 KB of data follows the hole.
  constexpr uint32_t kMidOffset = kBytes / 2;
  const uint32_t kTailOffset = kBytes - 1;

  printf("predicted, from reference/xnu at %s:\n", lab.knobs.kernel_version.c_str());
  printf("  fast retransmit at %d duplicate ACKs        (tcp_input.c:265, "
         "net.inet.tcp.rexmt_thresh)\n",
         lab.knobs.rexmtthresh);
  printf("  TLP armed only when SACK was negotiated     (tcp_output.c:2966)\n");
  printf("  RTO floor = rtt_min + rexmt_slop = %d + %d = %d ms\n\n", lab.knobs.rtt_min,
         lab.knobs.rexmt_slop, lab.knobs.rtt_min + lab.knobs.rexmt_slop);

  const Arm arms[] = {
      {"mid-stream loss, no SACK", false, false},
      {"mid-stream loss, SACK", true, false},
      {"tail loss,       no SACK", false, true},
      {"tail loss,       SACK", true, true},
  };

  printf("%-26s %10s %10s %9s %8s %10s  %s\n", "arm", "HoL delay", "syn->sa", "dupACKs",
         "rexmits", "delivered", "recovered by");
  printf("%-26s %10s %10s %9s %8s %10s  %s\n", "---", "(ms)", "(ms)", "", "", "bytes", "");

  uint16_t sport = 42000;
  std::vector<std::pair<std::string, double>> results;

  for (const Arm& a : arms) {
    PeerConfig cfg;
    cfg.sport = sport++;
    cfg.dport = kPort;
    cfg.isn = 200000 + uint32_t(cfg.sport) * 17;
    cfg.mss = kMss;
    cfg.offer_sack = a.sack;
    cfg.send_sack_blocks = a.sack;

    LossPolicy loss;
    const uint32_t off = a.tail ? kTailOffset : kMidOffset;
    loss.add({off, off + 1, 1, 0});  // drop once: the retransmission gets through

    Outcome o = run_scenario(lab, cfg, kBytes, 15000, loss);
    if (!o.ok) {
      printf("%-26s  FAILED: %s\n", a.name, o.err.c_str());
      continue;
    }

    // A rule that never fired means this arm tested nothing. Saying so is the
    // whole point of LossPolicy::unfired(); a silent clean run here would be
    // indistinguishable from a real zero-cost result.
    if (!loss.unfired().empty()) {
      printf("%-26s  INVALID: the drop rule never matched a segment -- this arm "
             "measured nothing\n",
             a.name);
      continue;
    }
    if (a.sack && !o.sack_negotiated) {
      printf("%-26s  INVALID: we offered SACK-permitted and the kernel did not "
             "agree; arm is mislabelled\n",
             a.name);
      continue;
    }
    if (!a.sack && o.sack_negotiated) {
      printf("%-26s  INVALID: we did not offer SACK and the kernel enabled it "
             "anyway\n",
             a.name);
      continue;
    }

    printf("%-26s %10.3f %10.3f %9d %8zu %10u  %s%s\n", a.name, o.sum.hol_delay_ms,
           o.handshake_rtt_ms, o.sum.dup_acks_sent, o.sum.retransmits.size(),
           o.sum.bytes_delivered,
           classify(o.sum, lab.knobs.rexmtthresh,
                    lab.knobs.rtt_min + lab.knobs.rexmt_slop),
           o.sum.completed ? "" : "  INCOMPLETE");

    results.emplace_back(a.name, o.sum.hol_delay_ms);

    // A mid-stream arm that never raised the threshold did not test fast
    // retransmit; it fell through to the same timer the tail arms measure, and
    // reporting it beside them as a contrast would be wrong.
    if (!a.tail && o.sum.dup_acks_sent < lab.knobs.rexmtthresh)
      printf("     SUSPECT: only %d duplicate ACKs, below rexmt_thresh=%d -- this "
             "row is not measuring fast retransmit.\n",
             o.sum.dup_acks_sent, lab.knobs.rexmtthresh);

    // Offsets are printed so the classification above can be checked by hand.
    // For a mid-stream hole they are decisive on their own (a TLP resends the
    // last segment, an RTO resends from snd_una); for a tail hole those are the
    // same bytes, and the argument falls back to the RTO floor -- see
    // classify().
    if (verbose || !o.sum.retransmits.empty()) {
      printf("     retransmits at:");
      for (size_t i = 0; i < o.sum.retransmits.size() && i < 6; ++i)
        printf(" t=%.1fms off=%lld", o.sum.retransmits[i].t_ms,
               (long long)o.sum.retransmits[i].rel_seq);
      if (o.sum.retransmits.size() > 6) printf(" ...");
      printf("\n");
    }
    if (verbose) o.trace.dump(stdout);
  }

  printf("\nWhat to look for:\n");
  printf("  The two mid-stream rows should be fast and close to each other:\n");
  printf("  SACK changes what the sender knows, but with data still flowing it\n");
  printf("  would have found the hole from duplicate ACKs regardless.\n");
  printf("  The two tail rows are the result. If they differ by roughly the RTO\n");
  printf("  floor, then omitting two bytes of TCP option in the SYN cost the\n");
  printf("  application an entire retransmission timeout -- which is the claim\n");
  printf("  tcp_output.c:2966 predicts and the reason this arm exists.\n");

  print_integrity(lab);
  return 0;
}
