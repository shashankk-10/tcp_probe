#pragma once

// IPv4 + TCP segment build and parse, including the option kinds this project
// actually depends on: MSS, SACK-permitted, and SACK blocks.
//
// Options are not decoration here. tcp_output.c:2966 gates the Tail Loss Probe
// on SACK_ENABLED(tp), which is set only if the peer offered SACK-permitted in
// its SYN. So whether this file emits a 2-byte option in one packet decides
// whether the kernel arms a timer thousands of milliseconds later. That is the
// central experiment, and it is why the option encoder is first-class rather
// than a hardcoded byte string.

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace tp {

// TCP option kinds, named so call sites do not carry bare integers.
enum : uint8_t {
  kOptEol = 0,
  kOptNop = 1,
  kOptMss = 2,
  kOptWscale = 3,
  kOptSackPermitted = 4,
  kOptSack = 5,
  kOptTimestamp = 8,
};

// A half-open byte range [start, end) in sequence space, as carried by a SACK
// block. Half-open matches how the wire format defines it and, more usefully,
// makes adjacency (a.end == b.start) a plain equality test.
struct SeqRange {
  uint32_t start = 0;
  uint32_t end = 0;
  uint32_t len() const { return end - start; }
};

// What we choose to put in a segment's option field.
struct Options {
  std::optional<uint16_t> mss;
  bool sack_permitted = false;
  std::vector<SeqRange> sack_blocks;
  std::optional<uint8_t> wscale;

  bool empty() const {
    return !mss && !sack_permitted && sack_blocks.empty() && !wscale;
  }
  // Serialised length, padded to a 4-byte boundary as the data offset requires.
  size_t wire_len() const;
  // Writes into `out`, returning bytes written. `out` needs 40 bytes of room,
  // which is the maximum the 4-bit data offset can express.
  size_t encode(uint8_t* out) const;
};

// One segment, in host byte order throughout. Anything that has been through
// parse() or is about to go through build() uses host order; the only byte
// swaps live inside those two functions.
struct Seg {
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint8_t flags = 0;
  uint16_t win = 0;
  uint16_t sport = 0;
  uint16_t dport = 0;
  std::vector<uint8_t> payload;
  Options opt;

  // Observation time, filled in by the receive path. Not part of the wire
  // format; carried here so a trace entry and the segment it describes cannot
  // drift apart.
  double t_ms = 0;

  size_t len() const { return payload.size(); }
  // SYN and FIN each occupy one sequence number. Everything that advances a
  // sequence number should go through this rather than adding payload.size()
  // and remembering the +1 separately, which is how off-by-ones get in.
  uint32_t seq_span() const {
    return uint32_t(payload.size()) + ((flags & TH_SYN) ? 1u : 0u) +
           ((flags & TH_FIN) ? 1u : 0u);
  }
};

// "SA", "A", "FA", "-" for no flags. Order is FSRPAU, matching tcpdump so a
// trace can be eyeballed against a capture without re-learning a notation.
std::string flagstr(uint8_t flags);

// Builds a complete IPv4+TCP packet into `out` (needs 4 + 1500 bytes; the
// leading 4 are the network-order address family that utun requires on every
// read and write). Returns total bytes, including that 4-byte prefix.
//
// ip_id is passed in rather than generated internally so that a replayed
// experiment produces a byte-identical packet stream -- a hidden counter makes
// two runs differ in a field nobody is looking at, which is a bad surprise to
// hit while diffing captures.
size_t build(uint8_t* out, size_t out_cap, in_addr src, in_addr dst,
             const Seg& s, uint16_t ip_id);

// Parses one utun frame. Returns false for anything that is not a well-formed
// IPv4 TCP segment: the wrong address family (a fresh utun gets an IPv6
// link-local and immediately emits MLD/RS on it), a non-TCP protocol, or a
// length field that disagrees with the bytes actually present.
bool parse(const uint8_t* frame, size_t n, Seg* out);

}  // namespace tp
