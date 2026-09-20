#pragma once

// What the synthetic peer pretends not to have received.
//
// "Loss" here is a decision, not an accident: the segment does arrive on the
// utun fd, and the peer chooses to discard it and to withhold the ACK that
// would have covered it. From the kernel's side that is indistinguishable from
// a drop on the wire, and it has two advantages over real impairment -- it is
// exactly reproducible, and it is per-segment rather than statistical, so an
// experiment can say "drop the segment carrying byte 40,000 and nothing else".
//
// Rules are expressed in RELATIVE byte offsets from the first data byte, not in
// segment ordinals. The kernel decides how to carve the stream into segments
// and it does not always carve it the same way twice (a retransmission may be
// repacketised), so an ordinal names a different span of bytes on a rerun while
// an offset names the same one.

#include <cstdint>
#include <string>
#include <vector>

namespace tp {

struct DropRule {
  uint32_t lo = 0;   // relative byte offset, inclusive
  uint32_t hi = 0;   // relative byte offset, exclusive
  // How many times a segment overlapping [lo,hi) may be dropped. 1 means the
  // original is lost and the first retransmission gets through, which is what
  // "measure the recovery" needs. Raising it measures the backoff ladder
  // instead -- a different experiment, so it is a parameter rather than a
  // constant.
  int times = 1;
  int fired = 0;
};

class LossPolicy {
 public:
  void add(DropRule r) { rules_.push_back(r); }

  // `rel_seq` is the offset of the segment's first byte from the start of the
  // data stream; `len` its length. Returns true if the peer should discard it.
  // Zero-length segments (pure ACKs, the bare FIN) are never dropped: they
  // carry no data to lose, and discarding them would be testing a different
  // failure mode than the one every experiment here is named after.
  bool drop(uint32_t rel_seq, uint32_t len);

  int total_dropped() const { return dropped_; }
  // Rules that never fired. An experiment whose rule never matched did not
  // test what its name says, and silently reporting a clean run in that case
  // is the worst outcome available -- so callers are expected to assert on it.
  std::vector<size_t> unfired() const;

  const std::vector<DropRule>& rules() const { return rules_; }

 private:
  std::vector<DropRule> rules_;
  int dropped_ = 0;
};

}  // namespace tp
