#pragma once

// The synthetic TCP peer: the other end of the connection, implemented in
// userspace, with the real XNU stack opposite it.
//
// The peer is deliberately the CLIENT and the kernel is deliberately the
// SENDER. That orientation is what makes the measurements about the kernel:
// every retransmission decision, every timer, and every congestion-control
// response belongs to XNU, and this class only decides what to acknowledge and
// when. If the peer were the sender, the recovery timings would be this
// program's own policy reflected back, which would look like a result and be
// worth nothing.
//
// The peer negotiates no timestamps and no window scale. Both have
// consequences: no window scale caps the advertised window at 65535, and no
// timestamps leaves the kernel's RTT sampling to Karn's algorithm over untimed
// segments. See the README's limitations list.

#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "tp/policy.hpp"
#include "tp/reassembly.hpp"
#include "tp/segment.hpp"
#include "tp/trace.hpp"
#include "tp/utun.hpp"

namespace tp {

struct PeerConfig {
  uint16_t sport = 40001;   // our source port
  uint16_t dport = 9999;    // the kernel's listening port
  uint32_t isn = 1000;      // our initial sequence number
  uint16_t mss = 1024;      // advertised in our SYN; bounds the kernel's segments
  uint16_t win = 65535;     // no window scale, so this is the ceiling
  bool offer_sack = false;  // SACK-permitted in the SYN -- gates TLP, see README
  bool send_sack_blocks = true;  // emit SACK blocks on dup ACKs (needs offer_sack)

  // One-way delay applied to OUR segments only. The kernel's RTT sample is
  // therefore ~= ack_delay_ms, not 2x it: the forward path stays ~0 because we
  // cannot delay a packet the kernel has already handed to utun. Stated here
  // because an RTT that is half what a reader assumes would silently halve
  // every predicted RTO.
  double ack_delay_ms = 0.0;
};

// How a retransmission was identified on the wire.
struct Retransmit {
  double t_ms = 0;       // relative to trace origin
  int64_t rel_seq = 0;   // byte offset into the data stream
  uint32_t len = 0;
};

struct RunSummary {
  uint32_t bytes_delivered = 0;
  uint32_t bytes_wanted = 0;
  bool completed = false;       // frontier reached bytes_wanted
  double t_first_data = -1;     // relative ms
  double t_last_original = -1;  // last segment carrying never-before-seen bytes
  double t_hole_created = -1;   // arrival of the first segment the policy dropped
  double t_hole_filled = -1;    // frontier passed that segment's last byte
  double hol_delay_ms = -1;     // t_hole_filled - t_hole_created
  int dup_acks_sent = 0;
  int acks_sent = 0;
  int segments_dropped = 0;
  // ACKs this peer failed to write. Nonzero means the kernel was starved of
  // acknowledgements by the harness rather than by the loss policy, so the
  // recovery timing in this run measures the harness.
  int ack_send_failures = 0;
  std::vector<Retransmit> retransmits;
  bool saw_rst = false;
  bool saw_fin = false;
};

class Peer {
 public:
  Peer(Utun& u, Trace& tr, const PeerConfig& cfg) : u_(u), tr_(tr), cfg_(cfg) {}
  ~Peer();
  Peer(const Peer&) = delete;
  Peer& operator=(const Peer&) = delete;

  // Drives the three-way handshake and accepts the resulting socket off
  // `listen_fd`. accept() returning is the proof that matters: it means the
  // crafted segments did not merely reach the stack, they drove it through
  // SYN-RECEIVED into ESTABLISHED.
  bool establish(int listen_fd, std::string* err);

  int accepted_fd() const { return afd_; }
  uint32_t data_isn() const { return data_isn_; }
  // What the kernel put in its SYN-ACK, which is not necessarily what we asked
  // for. Every arm that depends on SACK checks this before believing its label.
  bool peer_sack_ok() const { return peer_sack_ok_; }
  uint16_t peer_mss() const { return peer_mss_; }
  // SYN to SYN-ACK, measured on this process's clock. It is the floor for
  // every timing below: utun traversal in both directions plus the stack's
  // handling. Any recovery interval quoted without it is unanchored, because a
  // reader cannot tell a 0.4 ms result from a measurement artefact.
  double handshake_rtt_ms() const { return handshake_rtt_ms_; }

  // Receives until the CUMULATIVE in-order byte count reaches `total_target`,
  // or `timeout_ms` elapses, applying `loss`. The target is cumulative, not
  // per-call, because the reassembly state persists for the life of the
  // connection -- which is what lets one connection take several losses in
  // sequence, as the early-retransmit rate-limit experiment needs.
  RunSummary receive(uint32_t total_target, double timeout_ms, LossPolicy& loss);

  uint32_t delivered() const;

  struct BurstResult {
    int acks = 0;  // bare ACKs, i.e. challenge ACKs
    int rsts = 0;  // tallied separately: a RST tears the connection down, so
                   // every later probe would hit a closed socket and draw its
                   // own RST. Counting those as responses would hide a rate
                   // limit completely.
    int sent = 0;  // probes that actually reached the fd
    int send_failures = 0;
    // A burst that under-fires looks exactly like a kernel rate limit: fire 25,
    // 15 fail to write, count 10 replies, conclude "the limit is 10". The limit
    // experiment is the one place in this repo where the result IS a count of
    // replies, so the count of *stimuli* has to be reported next to it or the
    // conclusion is unfalsifiable.
    bool complete(int wanted) const { return send_failures == 0 && sent == wanted; }
  };

  // Fires `n` copies of one crafted segment back to back and counts the
  // replies. Offsets are relative to the two sequence spaces, which are the
  // easiest thing here to get backwards: for a segment WE send, `seq` lives in
  // OUR space (the kernel's RCV.NXT) and `ack` lives in the KERNEL's space
  // (its SND.NXT). So seq_off is an offset within the kernel's receive window
  // and ack_off an offset relative to its snd_max.
  BurstResult burst(uint8_t flags, int32_t seq_off, int32_t ack_off, int n,
                    double collect_ms);

  // Tears the connection down with a RST so the next experiment starts from a
  // clean port. Politeness is not the point -- leaving the kernel socket in
  // FIN-WAIT means the next run on the same 4-tuple behaves differently.
  void reset();

 private:
  struct PendingAck {
    double due_ms = 0;
    uint32_t ack = 0;
    std::vector<SeqRange> sacks;
    bool is_dup = false;
  };

  void queue_ack(double now, uint32_t ack, std::vector<SeqRange> sacks, bool is_dup);
  // `force` drains the queue regardless of due time, for the final flush at the
  // end of a run. It exists so that flush can be forced without lying about
  // WHEN it happened: the earlier version passed a fabricated future `now` to
  // bypass the due check, and that timestamp went straight into the trace.
  void flush_acks(double now, bool force = false);
  // False if the write failed. Callers that tally what they sent must check it:
  // counting a segment this function could not put on the fd inflates
  // dup_acks_sent, which exp_dupack prints as a headline column.
  bool send_now(const Seg& s, double now, const char* note);

  Utun& u_;
  Trace& tr_;
  PeerConfig cfg_;

  int afd_ = -1;
  uint32_t snd_ = 0;       // our SND.NXT
  uint32_t data_isn_ = 0;  // kernel's first data byte
  bool peer_sack_ok_ = false;
  uint16_t peer_mss_ = 0;
  double handshake_rtt_ms_ = -1;
  uint32_t max_seq_end_seen_ = 0;  // highest (seq+len) the kernel has ever sent
  std::deque<PendingAck> pending_;
  RunSummary* cur_ = nullptr;
  // Lives for the whole connection. A fresh Reassembly per receive() call
  // would reset the frontier to the ISN and report every later byte as a
  // duplicate.
  std::unique_ptr<Reassembly> rsm_;
};

}  // namespace tp
