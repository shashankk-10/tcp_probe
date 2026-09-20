#pragma once

// Internet checksum (RFC 1071). Split into an unfolded accumulator and a fold
// step so a TCP pseudo-header sum can be chained into a segment sum without
// materialising the two next to each other in a buffer.

#include <cstddef>
#include <cstdint>

namespace tp {

// Sums 16-bit big-endian words. Returns a host-order accumulator with carries
// still unfolded, so callers can add several of these together.
inline uint32_t sum_be16(const void* data, size_t len) {
  const auto* p = static_cast<const uint8_t*>(data);
  uint32_t sum = 0;
  size_t i = 0;
  for (; i + 1 < len; i += 2) sum += (uint32_t(p[i]) << 8) | p[i + 1];
  if (i < len) sum += uint32_t(p[i]) << 8;  // odd tail pads with a zero byte
  return sum;
}

// Folds carries and complements. The result is a host-order number whose
// big-endian encoding belongs in the checksum field, so callers store it with
// htons(). Host order is returned, not network order, because it
// makes the one place that byte-swaps visible instead of hiding a swap inside
// a function whose name says nothing about byte order.
inline uint16_t fold(uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return uint16_t(~sum & 0xffff);
}

}  // namespace tp
