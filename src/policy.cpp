#include "tp/policy.hpp"

namespace tp {

bool LossPolicy::drop(uint32_t rel_seq, uint32_t len) {
  if (len == 0) return false;
  const uint32_t seg_lo = rel_seq, seg_hi = rel_seq + len;
  for (DropRule& r : rules_) {
    if (r.fired >= r.times) continue;
    // Overlap, not containment. The kernel picks the segment boundaries, so a
    // rule written as "the byte at offset 40000" must still match the segment
    // that happens to carry it, whatever its extent.
    if (seg_lo < r.hi && r.lo < seg_hi) {
      ++r.fired;
      ++dropped_;
      return true;
    }
  }
  return false;
}

std::vector<size_t> LossPolicy::unfired() const {
  std::vector<size_t> out;
  for (size_t i = 0; i < rules_.size(); ++i)
    if (rules_[i].fired == 0) out.push_back(i);
  return out;
}

}  // namespace tp
