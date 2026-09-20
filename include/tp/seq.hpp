#pragma once

// TCP sequence-space comparison (RFC 1323 appendix). Sequence numbers are a
// 32-bit cyclic space, so ordering is defined by the sign of the difference,
// not by <. Using plain < works for every experiment in this repo -- none runs
// long enough to wrap -- which is exactly why it would be a latent bug rather
// than an immediate one, so it is done properly here.

#include <cstdint>

namespace tp {

inline bool seq_lt(uint32_t a, uint32_t b) { return int32_t(a - b) < 0; }
inline bool seq_leq(uint32_t a, uint32_t b) { return int32_t(a - b) <= 0; }
inline bool seq_gt(uint32_t a, uint32_t b) { return int32_t(a - b) > 0; }
inline bool seq_geq(uint32_t a, uint32_t b) { return int32_t(a - b) >= 0; }

}  // namespace tp
