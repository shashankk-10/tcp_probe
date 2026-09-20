#include "tp/peer.hpp"

#include <errno.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>

#include "tp/clock.hpp"
#include "tp/seq.hpp"

namespace tp {

Peer::~Peer() {
  // reset() is the normal teardown, but an experiment that bails on an error
  // path can return without reaching it. Five experiments times a few dozen
  // connections is enough leaked descriptors to matter.
  if (afd_ >= 0) close(afd_);
}

bool Peer::send_now(const Seg& s, double now, const char* note) {
  std::string err;
  if (!u_.send(s, &err)) {
    tr_.note(now, std::string("send failed: ") + err);
    return false;
  }
  tr_.record_tx(now, s.seq, s.ack, s.flags, uint32_t(s.payload.size()),
                note ? note : "");
  return true;
}

bool Peer::establish(int listen_fd, std::string* err) {
  snd_ = cfg_.isn;

  Seg syn;
  syn.sport = cfg_.sport;
  syn.dport = cfg_.dport;
  syn.seq = snd_;
  syn.flags = TH_SYN;
  syn.win = cfg_.win;
  syn.opt.mss = cfg_.mss;
  syn.opt.sack_permitted = cfg_.offer_sack;

  const double t0 = now_ms();
  // The origin is set before the SYN so handshake segments are numbered
  // against the same clock as everything after; data_isn is patched in once
  // the SYN-ACK reveals it.
  tr_.set_origin(t0, 0, cfg_.isn);
  std::string serr;
  if (!u_.send(syn, &serr)) {
    *err = "SYN: " + serr;
    return false;
  }
  tr_.record_tx(t0, syn.seq, 0, syn.flags, 0,
                cfg_.offer_sack ? "SYN mss+sackOK" : "SYN mss, no sackOK");

  // Wait for the SYN-ACK. drain() appends, so the batch is cleared per pass --
  // reusing it re-examined every earlier segment on each iteration.
  std::vector<Seg> seen;
  Seg sa;
  bool got = false;
  for (double deadline = now_ms() + 2000; now_ms() < deadline && !got;) {
    seen.clear();
    u_.drain(50, &seen);
    for (const Seg& s : seen) {
      if (s.dport != cfg_.sport || s.sport != cfg_.dport) continue;
      if (s.flags & TH_RST) {
        *err = "kernel answered the SYN with RST -- is anything listening on that port?";
        return false;
      }
      if ((s.flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        sa = s;
        got = true;
        break;
      }
    }
  }
  if (!got) {
    *err = "no SYN-ACK off the utun fd within 2000 ms";
    return false;
  }
  if (sa.ack != snd_ + 1) {
    *err = "SYN-ACK acknowledged " + std::to_string(sa.ack) + ", expected " +
           std::to_string(snd_ + 1);
    return false;
  }

  handshake_rtt_ms_ = sa.t_ms - t0;
  data_isn_ = sa.seq + 1;
  max_seq_end_seen_ = data_isn_;
  peer_sack_ok_ = sa.opt.sack_permitted;
  peer_mss_ = sa.opt.mss.value_or(0);
  tr_.set_origin(t0, data_isn_, cfg_.isn);
  tr_.record_rx(sa.t_ms, sa.seq, sa.ack, sa.flags, 0, false,
                std::string("SYN-ACK mss=") + std::to_string(peer_mss_) +
                    (peer_sack_ok_ ? " sackOK" : " NO sackOK"));

  snd_ += 1;
  Seg ack;
  ack.sport = cfg_.sport;
  ack.dport = cfg_.dport;
  ack.seq = snd_;
  ack.ack = data_isn_;
  ack.flags = TH_ACK;
  ack.win = cfg_.win;
  send_now(ack, now_ms(), "3WHS ACK");

  // accept() returning is the real proof the stack reached ESTABLISHED.
  struct pollfd pfd{listen_fd, POLLIN, 0};
  if (poll(&pfd, 1, 2000) != 1) {
    *err = "handshake looked right on the wire but accept() never became ready";
    return false;
  }
  struct sockaddr_in from;
  socklen_t flen = sizeof from;
  afd_ = accept(listen_fd, reinterpret_cast<struct sockaddr*>(&from), &flen);
  if (afd_ < 0) {
    *err = std::string("accept(): ") + strerror(errno);
    return false;
  }
  if (ntohs(from.sin_port) != cfg_.sport) {
    *err = "accept() reported a source port we never sent from";
    return false;
  }

  // Nagle would coalesce the writes an experiment makes and change the
  // segmentation under test. The experiments here care about where segment
  // boundaries fall, so this is load-bearing, not hygiene.
  int one = 1;
  setsockopt(afd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  return true;
}

void Peer::queue_ack(double now, uint32_t ack, std::vector<SeqRange> sacks, bool is_dup) {
  pending_.push_back({now + cfg_.ack_delay_ms, ack, std::move(sacks), is_dup});
}

void Peer::flush_acks(double now, bool force) {
  while (!pending_.empty() && (force || pending_.front().due_ms <= now)) {
    PendingAck p = std::move(pending_.front());
    pending_.pop_front();
    Seg a;
    a.sport = cfg_.sport;
    a.dport = cfg_.dport;
    a.seq = snd_;
    a.ack = p.ack;
    a.flags = TH_ACK;
    a.win = cfg_.win;
    if (cfg_.offer_sack && cfg_.send_sack_blocks && !p.sacks.empty())
      a.opt.sack_blocks = std::move(p.sacks);
    const bool ok = send_now(a, now, p.is_dup ? "dup ACK" : nullptr);
    if (cur_) {
      if (!ok) {
        ++cur_->ack_send_failures;
      } else {
        ++cur_->acks_sent;
        if (p.is_dup) ++cur_->dup_acks_sent;
      }
    }
  }
}

uint32_t Peer::delivered() const { return rsm_ ? rsm_->delivered() : 0; }

RunSummary Peer::receive(uint32_t total_target, double timeout_ms, LossPolicy& loss) {
  RunSummary sum;
  sum.bytes_wanted = total_target;
  cur_ = &sum;
  if (!rsm_) rsm_ = std::make_unique<Reassembly>(data_isn_);
  Reassembly& rsm = *rsm_;

  // The hole is the first range the policy discards; its last byte is what the
  // frontier must pass before the application sees anything beyond it.
  uint32_t hole_end_seq = 0;
  bool hole_open = false;

  const double t_end = now_ms() + timeout_ms;
  std::vector<Seg> batch;
  while (now_ms() < t_end && rsm.delivered() < total_target) {
    // Wake up in time for the next queued ACK; otherwise a 50 ms drain would
    // hold a 5 ms delayed ACK for 50 ms and the injected RTT would be a lie.
    double slice = 20.0;
    if (!pending_.empty()) slice = std::min(slice, pending_.front().due_ms - now_ms());
    if (slice < 0) slice = 0;
    batch.clear();
    u_.drain(slice, &batch);

    for (const Seg& s : batch) {
      if (s.dport != cfg_.sport || s.sport != cfg_.dport) continue;
      if (s.flags & TH_RST) {
        sum.saw_rst = true;
        tr_.record_rx(s.t_ms, s.seq, s.ack, s.flags, 0, false, "RST");
        cur_ = nullptr;
        return sum;
      }
      const uint32_t len = uint32_t(s.payload.size());

      if (len > 0) {
        const int64_t rel = int64_t(int32_t(s.seq - data_isn_));
        const bool is_rexmt = seq_lt(s.seq, max_seq_end_seen_);
        if (seq_gt(s.seq + len, max_seq_end_seen_)) max_seq_end_seen_ = s.seq + len;
        // Trace-relative. s.t_ms is raw monotonic time; every other field in
        // RunSummary is relative to the trace origin, and mixing the two made
        // the first run print retransmit times of 1418493399 ms.
        if (is_rexmt) sum.retransmits.push_back({s.t_ms - tr_.t0(), rel, len});

        // rel is signed on the wire but a drop rule is expressed in unsigned
        // offsets; a negative rel would be a segment below the data ISN, which
        // cannot happen after the handshake. Guard rather than cast blindly.
        const bool droppable = rel >= 0;
        if (droppable && loss.drop(uint32_t(rel), len)) {
          ++sum.segments_dropped;
          tr_.record_rx(s.t_ms, s.seq, s.ack, s.flags, len, true, "");
          if (!hole_open) {
            hole_open = true;
            hole_end_seq = s.seq + len;
            // Trace-relative, not absolute: every other time in RunSummary is
            // relative to the same origin, and mixing the two here would make
            // the head-of-line delay come out as an epoch.
            sum.t_hole_created = tr_.events().back().t_ms;
          }
          // No ACK at all. Withholding it turns this into a loss instead of
          // a reordering.
          continue;
        }

        const bool moved = rsm.accept(s.seq, len, s.t_ms);
        tr_.record_rx(s.t_ms, s.seq, s.ack, s.flags, len, false,
                      is_rexmt ? "retransmit" : "");
        if (sum.t_first_data < 0) sum.t_first_data = tr_.events().back().t_ms;
        if (!is_rexmt) sum.t_last_original = tr_.events().back().t_ms;

        queue_ack(now_ms(), rsm.rcv_nxt(), rsm.sack_blocks(), /*is_dup=*/!moved);

        if (hole_open && seq_geq(rsm.rcv_nxt(), hole_end_seq)) {
          hole_open = false;
          sum.t_hole_filled = tr_.events().back().t_ms;
          sum.hol_delay_ms = sum.t_hole_filled - sum.t_hole_created;
        }
      } else if (s.flags & TH_FIN) {
        sum.saw_fin = true;
        tr_.record_rx(s.t_ms, s.seq, s.ack, s.flags, 0, false, "FIN");
      } else {
        // A pure ACK from the kernel. No data, but the timing is evidence --
        // it is how a TLP's ACK-only probe shows up -- so it goes in the trace.
        tr_.record_rx(s.t_ms, s.seq, s.ack, s.flags, 0, false, "");
      }
    }
    flush_acks(now_ms());
  }
  flush_acks(now_ms(), /*force=*/true);

  sum.bytes_delivered = rsm.delivered();
  sum.completed = rsm.delivered() >= total_target;
  cur_ = nullptr;
  return sum;
}

Peer::BurstResult Peer::burst(uint8_t flags, int32_t seq_off, int32_t ack_off, int n,
                              double collect_ms) {
  // rcv_nxt here is the kernel's next expected byte from us, which after the
  // handshake with no data sent is simply our snd_. The kernel's SND.NXT is
  // data_isn_ plus whatever it has sent; for the challenge-ACK probes nothing
  // has been sent, so data_isn_ is the right base.
  const uint32_t seq = uint32_t(int32_t(snd_) + seq_off);
  const uint32_t ack = uint32_t(int32_t(data_isn_) + ack_off);

  BurstResult r;
  for (int i = 0; i < n; ++i) {
    Seg s;
    s.sport = cfg_.sport;
    s.dport = cfg_.dport;
    s.seq = seq;
    s.ack = ack;
    s.flags = flags;
    s.win = cfg_.win;
    std::string err;
    if (u_.send(s, &err)) {
      ++r.sent;
    } else {
      ++r.send_failures;
      if (r.send_failures == 1) tr_.note(now_ms(), "burst send failed: " + err);
    }
  }

  // drain_for, not drain: the question here is how many replies the burst
  // provoked IN TOTAL. Returning as soon as the first one lands counted 1
  // challenge ACK where the kernel had sent 10.
  std::vector<Seg> replies;
  u_.drain_for(collect_ms, &replies);

  for (const Seg& s : replies) {
    if (s.dport != cfg_.sport || s.sport != cfg_.dport) continue;
    if (s.flags & TH_RST) ++r.rsts;
    else if (s.flags & TH_ACK) ++r.acks;
  }
  tr_.note(now_ms(), "burst " + flagstr(flags) + " x" + std::to_string(r.sent) + "/" +
                         std::to_string(n) + " -> " + std::to_string(r.acks) +
                         " ACKs, " + std::to_string(r.rsts) + " RSTs");
  return r;
}

void Peer::reset() {
  if (afd_ >= 0) {
    close(afd_);
    afd_ = -1;
  }
  Seg r;
  r.sport = cfg_.sport;
  r.dport = cfg_.dport;
  r.seq = snd_;
  r.ack = 0;
  r.flags = TH_RST;
  r.win = 0;
  std::string err;
  u_.send(r, &err);

  // Drop everything that belonged to the connection just torn down. establish()
  // reassigns snd_/data_isn_/max_seq_end_seen_, but the reassembly frontier and
  // any queued ACKs are not on that path: reusing this object would have
  // compared the new connection's segments against the old frontier and
  // reported the whole stream as duplicate. No experiment re-establishes on one
  // Peer today, so this would have been found late.
  rsm_.reset();
  pending_.clear();
  cur_ = nullptr;
}

}  // namespace tp
