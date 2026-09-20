#pragma once

// TCP sequence-space comparison (RFC 1323 appendix). Sequence numbers are a
// 32-bit cyclic space, so ordering is defined by the sign of the difference,
// not by <. Plain < works for every experiment here, since none runs long
// enough to wrap. That makes it a latent bug, not an immediate one, so it is
// done properly.

#include <cstdint>

namespace tp {

inline bool seq_lt(uint32_t a, uint32_t b) { return int32_t(a - b) < 0; }
inline bool seq_leq(uint32_t a, uint32_t b) { return int32_t(a - b) <= 0; }
inline bool seq_gt(uint32_t a, uint32_t b) { return int32_t(a - b) > 0; }
inline bool seq_geq(uint32_t a, uint32_t b) { return int32_t(a - b) >= 0; }

}  // namespace tp
