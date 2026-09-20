// The RFC 5961 challenge-ACK rate limiter, and where XNU puts it.
//
// This is a secondary result, and it is stated carefully because the obvious
// framing of it is wrong.
//
// WHAT IS TRUE: tcp_is_ack_ratelimited() (tcp_input.c:487) reads and writes
// tp->t_challengeack_last and tp->t_challengeack_count -- both fields of
// struct tcpcb (tcp_var.h:811-812). Only the limit itself,
// net.inet.tcp.challengeack_limit, is global. So the BUDGET is per connection.
// It is a fixed 1000 ms window anchored at the first triggering segment, not a
// sliding window and not a refilling token bucket, and the count is not
// incremented on the limited path -- so a burst of N > limit probes inside one
// window draws exactly `limit` challenge ACKs, not "roughly" that many.
//
// WHAT IS NOT A NEW FINDING: Linux puts this counter in a per-host variable,
// which is what made CVE-2016-5696 an off-path attack -- an attacker could
// observe the global budget being consumed by someone else's connection. XNU
// being per-connection is an implementation divergence between two stacks, and
// RFC 5961 s7 leaves the scope unspecified. It is NOT a correction to the
// literature, and claiming otherwise invites an interviewer who knows the CVE
// to flatly contradict it. The interesting statement is the comparison.
//
// WHY IT BELONGS IN A PROJECT ABOUT LOSS: a per-connection counter is extra
// state that is invisible in the TCP state machine as usually drawn. The same
// input, in the same RFC 9293 state, on the same connection, produces a
// different output depending only on elapsed time. B3 is the minimal witness
// for that.

#include <cstdio>
#include <string>

#include "harness.hpp"
#include "tp/clock.hpp"
#include "tp/sysctl.hpp"

using namespace tp;

namespace {

constexpr int kProbes = 25;

struct Trigger {
  const char* name;
  const char* site;
  uint8_t flags;
  int32_t seq_off;
  int32_t ack_off;
};

}  // namespace

int main() {
  Lab lab;
  std::string err;
  if (!lab.start("CHALLENGE-ACK LIMITER -- per connection on XNU, per host on Linux",
                 &err)) {
    fprintf(stderr, "FATAL: %s\n", err.c_str());
    return 2;
  }

  const int limit = lab.knobs.challengeack_limit;
  if (limit <= 0) {
    fprintf(stderr, "FATAL: challengeack_limit unreadable\n");
    return 2;
  }
  printf("predicting exactly %d bare ACKs per %d probes, per connection, per "
         "1000 ms window\n\n",
         limit, kProbes);

  // All three reach a tcp_is_ack_ratelimited() call site. The SYN trigger
  // requires tlen <= 0, which is why none of these carries a payload.
  const Trigger triggers[] = {
      {"SYN in ESTABLISHED", "tcp_input.c:4133 (RFC 5961 s4.2)", TH_SYN, 0, 0},
      {"ACK above snd_max", "tcp_input.c:4874 rcvacktoomuch", TH_ACK, 0, 1000000},
      {"in-window RST, seq != RCV.NXT", "tcp_input.c:4271 badrst", TH_RST, 10, 0},
  };

  uint16_t sport = 45000;
  uint32_t isn = 500000;
  auto make = [&](PeerConfig* c) {
    c->sport = sport++;
    c->dport = kPort;
    c->isn = (isn += 100000);
    c->mss = 1024;
    c->offer_sack = true;
  };

  Trigger best = triggers[0];
  int exact_hits = 0;

  printf("%-30s %6s %6s %10s  %s\n", "trigger", "ACKs", "RSTs", "vs limit", "site");
  for (const Trigger& t : triggers) {
    PeerConfig cfg;
    make(&cfg);
    Trace tr;
    Peer p(lab.utun, tr, cfg);
    if (!p.establish(lab.listen_fd, &err)) {
      printf("%-30s  could not establish: %s\n", t.name, err.c_str());
      continue;
    }
    auto r = p.burst(t.flags, t.seq_off, t.ack_off, kProbes, 400);
    // A short burst and a rate limit look identical in the reply count, and
    // this experiment's entire result IS a reply count. So an under-fired
    // burst gets thrown away.
    if (!r.complete(kProbes)) {
      printf("%-30s  DISCARDED: only %d of %d probes were sent (%d write "
             "failures) -- a short burst mimics the limit being measured\n",
             t.name, r.sent, kProbes, r.send_failures);
      p.reset();
      sleep_ms(60);
      continue;
    }
    const bool exact = r.acks == limit;
    printf("%-30s %6d %6d %10s  %s\n", t.name, r.acks, r.rsts,
           exact ? "== limit" : "!= limit", t.site);
    if (exact && exact_hits == 0) best = t;
    if (exact) ++exact_hits;
    p.reset();
    sleep_ms(60);
  }

  if (exact_hits == 0) {
    printf("\nNo trigger hit the limit exactly. Everything below depends on one "
           "that does, so stopping here.\n");
    print_integrity(lab);
    return 1;
  }
  printf("\n%d of 3 triggers hit exactly %d. Using \"%s\" below.\n\n", exact_hits, limit,
         best.name);

  // ---- per-connection, not host-global.
  {
    PeerConfig cx, cy;
    make(&cx);
    make(&cy);
    Trace tx, ty;
    Peer x(lab.utun, tx, cx), y(lab.utun, ty, cy);
    std::string e1, e2;
    if (x.establish(lab.listen_fd, &e1) && y.establish(lab.listen_fd, &e2)) {
      auto rx = x.burst(best.flags, best.seq_off, best.ack_off, kProbes, 300);
      auto ry = y.burst(best.flags, best.seq_off, best.ack_off, kProbes, 300);
      printf("per-connection budget:\n");
      if (!rx.complete(kProbes) || !ry.complete(kProbes)) {
        printf("  DISCARDED: bursts sent %d and %d of %d probes\n", rx.sent, ry.sent,
               kProbes);
      } else {
        printf("  X drained          -> %d ACKs\n", rx.acks);
        printf("  fresh Y right after-> %d ACKs   %s\n", ry.acks,
               ry.acks == limit ? "(a host-global counter would have starved Y)"
                                : "(UNEXPECTED: Y was starved)");
      }
      x.reset();
      y.reset();
      sleep_ms(60);
    } else {
      printf("per-connection budget: could not stand up two connections: %s / %s\n",
             e1.c_str(), e2.c_str());
    }
  }

  // ---- the same input, the same state, a different answer -- from time alone.
  {
    PeerConfig cz;
    make(&cz);
    Trace tz;
    Peer z(lab.utun, tz, cz);
    if (z.establish(lab.listen_fd, &err)) {
      const double t0 = now_ms();
      auto r1 = z.burst(best.flags, best.seq_off, best.ack_off, kProbes, 300);
      auto r2 = z.burst(best.flags, best.seq_off, best.ack_off, kProbes, 300);
      const double t2 = now_ms() - t0;
      sleep_ms(1200);  // cross the 1000 ms window boundary
      auto r3 = z.burst(best.flags, best.seq_off, best.ack_off, kProbes, 300);
      const double t3 = now_ms() - t0;
      printf("\nsame input, same ESTABLISHED state, only elapsed time differs:\n");
      printf("  t=0 ms            -> %d ACKs\n", r1.acks);
      printf("  t=%.0f ms (same window) -> %d ACKs\n", t2, r2.acks);
      printf("  t=%.0f ms (next window) -> %d ACKs\n", t3, r3.acks);
      if (!r1.complete(kProbes) || !r2.complete(kProbes) || !r3.complete(kProbes))
        printf("  DISCARDED: probes sent %d/%d/%d of %d\n", r1.sent, r2.sent, r3.sent,
               kProbes);
      else
        printf("  %s\n", (r1.acks == limit && r2.acks == 0 && r3.acks == limit)
                           ? "as predicted by the fixed-window reading of tcp_input.c:487"
                           : "NOT the predicted pattern -- the source reading is wrong "
                             "somewhere");
      z.reset();
      sleep_ms(60);
    }
  }

  // ---- the control. Without this, the observed cap is just a number that
  // happens to equal the sysctl.
  {
    const int probe_limit = limit >= 4 ? 3 : 1;
    ScopedSysctl guard("net.inet.tcp.challengeack_limit", probe_limit);
    if (guard.ok()) {
      PeerConfig ck;
      make(&ck);
      Trace tk;
      Peer k(lab.utun, tk, ck);
      if (k.establish(lab.listen_fd, &err)) {
        auto r = k.burst(best.flags, best.seq_off, best.ack_off, kProbes, 300);
        if (!r.complete(kProbes))
          printf("\ncontrol: DISCARDED, only %d of %d probes sent\n", r.sent, kProbes);
        else
          printf("\ncontrol: set challengeack_limit=%d -> %d ACKs  %s\n", probe_limit,
                 r.acks, r.acks == probe_limit ? "(tracks exactly)" : "(does NOT track)");
        k.reset();
      }
    } else {
      printf("\ncontrol: could not set challengeack_limit\n");
    }
  }
  printf("challengeack_limit restored to %d\n",
         sysctl_get("net.inet.tcp.challengeack_limit"));

  print_integrity(lab);
  return 0;
}
