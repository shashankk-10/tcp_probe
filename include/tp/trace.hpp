#pragma once

// A timestamped log of every segment in either direction.
//
// Sequence numbers are stored RELATIVE to the start of the data stream.
// Absolute ISNs are random 32-bit values; a trace printed in them is unreadable
// and, worse, is unreadable in a way that hides the one thing a reader is
// looking for -- whether a retransmission carried the same bytes as the
// original. Relative numbering makes that a glance instead of arithmetic.

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace tp {

struct Event {
  double t_ms = 0;      // relative to the trace's t0
  bool tx = false;      // true: this process sent it. false: the kernel did.
  uint8_t flags = 0;
  int64_t rel_seq = 0;  // signed: pre-handshake segments land before the origin
  int64_t rel_ack = 0;
  uint32_t len = 0;
  bool dropped = false;  // received, then discarded by the loss policy
  std::string note;
};

class Trace {
 public:
  // Called once the data ISN is known, so earlier events can be renumbered
  // against the same origin.
  void set_origin(double t0_ms, uint32_t data_isn, uint32_t our_isn);

  void record(const Event& e) { events_.push_back(e); }
  void record_rx(double t_ms, uint32_t seq, uint32_t ack, uint8_t flags, uint32_t len,
                 bool dropped, std::string note = {});
  void record_tx(double t_ms, uint32_t seq, uint32_t ack, uint8_t flags, uint32_t len,
                 std::string note = {});
  void note(double t_ms, std::string text);

  const std::vector<Event>& events() const { return events_; }
  // The origin every Event::t_ms is measured against. Anything that stamps a
  // time outside record_rx/record_tx must subtract this, or it lands in raw
  // monotonic-clock units alongside relative ones and comparisons between the
  // two silently succeed -- which is exactly how the first run's dup-ACK count
  // came out as 48 instead of 3.
  double t0() const { return t0_; }
  void dump(FILE* out) const;
  bool write_csv(const std::string& path) const;

 private:
  std::vector<Event> events_;
  double t0_ = 0;
  uint32_t data_isn_ = 0;  // kernel's first data byte
  uint32_t our_isn_ = 0;   // our first data byte (we send none, so this is fixed)
};

}  // namespace tp
