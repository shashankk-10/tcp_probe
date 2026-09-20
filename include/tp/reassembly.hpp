#pragma once

// The receiver's view of the stream, and the thing that actually produces this
// project's headline number.
//
// A TCP receiver may hold out-of-order data but may not hand it to the
// application until every earlier byte has arrived. So the cost of a lost
// segment, as the application experiences it, is not "one segment was resent"
// -- it is the wall-clock gap between the moment the stream stalled and the
// moment the frontier moved again. This class records exactly that, and
// nothing about it needs a kernel, a socket, or root, which is why it is a
// pure data structure with its own tests.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "tp/segment.hpp"
#include "tp/seq.hpp"

namespace tp {

class Reassembly {
 public:
  // `isn` is the sequence number of the first data byte (the kernel's ISN + 1
  // once the SYN is accounted for).
  explicit Reassembly(uint32_t isn) : rcv_nxt_(isn), isn_(isn) {}

  // Records an accepted segment. Returns true if the in-order frontier moved,
  // which is the caller's cue that a cumulative ACK carries new information.
  bool accept(uint32_t seq, uint32_t len, double t_ms);

  uint32_t rcv_nxt() const { return rcv_nxt_; }
  uint32_t isn() const { return isn_; }
  // Bytes delivered in order so far.
  uint32_t delivered() const { return rcv_nxt_ - isn_; }

  // Held out-of-order ranges, most recent first -- the order RFC 2018 s4 asks
  // a SACK sender to use. Capped at `max` because the option field holds at
  // most 4 blocks (3 alongside a timestamp option, which this peer does not
  // send).
  std::vector<SeqRange> sack_blocks(size_t max = 4) const;

  bool has_gap() const { return !held_.empty(); }

  // Wall-clock time at which the frontier first reached or passed `seq`.
  // Returns -1 if it never did. This is the raw material for the head-of-line
  // delay: time_reached(seq_of_byte_after_the_hole) minus the moment the hole
  // was created.
  double time_reached(uint32_t seq) const;

  size_t dup_segments() const { return dups_; }
  size_t ooo_segments() const { return ooo_; }

 private:
  struct Advance {
    uint32_t frontier;
    double t_ms;
  };
  uint32_t rcv_nxt_;
  uint32_t isn_;
  std::vector<SeqRange> held_;   // disjoint, sorted ascending, all > rcv_nxt_
  std::vector<Advance> advances_;
  size_t dups_ = 0;
  size_t ooo_ = 0;
};

}  // namespace tp
