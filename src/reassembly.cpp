#include "tp/reassembly.hpp"

#include <algorithm>
#include <cassert>

namespace tp {

bool Reassembly::accept(uint32_t seq, uint32_t len, double t_ms) {
  if (len == 0) return false;
  uint32_t start = seq, end = seq + len;

  // Trim anything already delivered. A retransmission usually overlaps the
  // frontier rather than sitting cleanly beyond it, and treating a partial
  // overlap as a pure duplicate loses the new tail.
  if (seq_leq(end, rcv_nxt_)) {
    ++dups_;
    return false;
  }
  if (seq_lt(start, rcv_nxt_)) start = rcv_nxt_;

  // Merge into the held set. held_ is disjoint and sorted ascending, and this
  // walk relies on both: once a range is found to start beyond cur, every later
  // range starts beyond it too, so cur can no longer grow and is safe to emit
  // in place. That is why the output needs no sort -- an earlier version sorted
  // `merged` afterwards, which was pure cost for an ordering the loop already
  // guarantees. The assert below is what keeps that reasoning honest if the
  // loss patterns ever change.
  std::vector<SeqRange> merged;
  merged.reserve(held_.size() + 1);
  SeqRange cur{start, end};
  bool placed = false;
  for (const SeqRange& r : held_) {
    if (seq_lt(r.end, cur.start)) {
      merged.push_back(r);
    } else if (seq_gt(r.start, cur.end)) {
      if (!placed) {
        merged.push_back(cur);
        placed = true;
      }
      merged.push_back(r);
    } else {
      // Overlapping or adjacent: absorb.
      if (seq_lt(r.start, cur.start)) cur.start = r.start;
      if (seq_gt(r.end, cur.end)) cur.end = r.end;
    }
  }
  if (!placed) merged.push_back(cur);
  held_.swap(merged);
  assert(std::is_sorted(held_.begin(), held_.end(),
                        [](const SeqRange& a, const SeqRange& b) {
                          return seq_lt(a.start, b.start);
                        }));

  // Drain any prefix that is now contiguous with the frontier.
  const uint32_t before = rcv_nxt_;
  size_t drained = 0;
  for (const SeqRange& r : held_) {
    if (seq_gt(r.start, rcv_nxt_)) break;
    if (seq_gt(r.end, rcv_nxt_)) rcv_nxt_ = r.end;
    ++drained;
  }
  held_.erase(held_.begin(), held_.begin() + long(drained));

  const bool moved = rcv_nxt_ != before;
  if (moved) advances_.push_back({rcv_nxt_, t_ms});
  else ++ooo_;
  return moved;
}

std::vector<SeqRange> Reassembly::sack_blocks(size_t max) const {
  std::vector<SeqRange> out;
  // RFC 2018 wants the block covering the most recently received data first.
  // held_ is sorted ascending, and the newest arrival is not necessarily the
  // highest, but for the loss patterns this project generates it always is --
  // a reordering experiment would break that, so it is worth knowing about
  // before anyone writes one.
  for (auto it = held_.rbegin(); it != held_.rend() && out.size() < max; ++it)
    out.push_back(*it);
  return out;
}

double Reassembly::time_reached(uint32_t seq) const {
  for (const Advance& a : advances_)
    if (seq_geq(a.frontier, seq)) return a.t_ms;
  return -1.0;
}

}  // namespace tp
