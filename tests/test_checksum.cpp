// The Internet checksum, against values that can be checked by hand.

#include "tp/checksum.hpp"

#include <cstring>

#include "check.hpp"

int main() {
  using namespace tp;

  // RFC 1071 s3 worked example: 00 01 f2 03 f4 f5 f6 f7 sums to 0xddf2, so the
  // complement is 0x220d. Taking the example from the RFC rather than from
  // this implementation's own output is the point -- a self-consistent
  // checksum that is wrong the same way twice passes any test built from it.
  const uint8_t rfc[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  CHECK_EQ(fold(sum_be16(rfc, sizeof rfc)), 0x220d);

  // An odd tail pads with a zero byte on the right, so appending a 0x00 to an
  // odd-length buffer must not change the result.
  const uint8_t odd[] = {0x12, 0x34, 0x56};
  const uint8_t even[] = {0x12, 0x34, 0x56, 0x00};
  CHECK_EQ(fold(sum_be16(odd, sizeof odd)), fold(sum_be16(even, sizeof even)));

  // The defining property: a buffer with its own checksum stored in it sums to
  // zero. This is what the kernel does on receipt, so it is the only property
  // that actually has to hold.
  uint8_t buf[20];
  for (size_t i = 0; i < sizeof buf; ++i) buf[i] = uint8_t(i * 7 + 3);
  buf[10] = buf[11] = 0;
  const uint16_t ck = fold(sum_be16(buf, sizeof buf));
  buf[10] = uint8_t(ck >> 8);
  buf[11] = uint8_t(ck);
  CHECK_EQ(fold(sum_be16(buf, sizeof buf)), 0);

  // Carries must fold, not truncate. 0xffff + 0xffff = 0x1fffe -> 0xffff.
  CHECK_EQ(fold(0x1fffeu), 0x0000);
  CHECK_EQ(fold(0x00000u), 0xffff);

  return check::finish("checksum");
}
