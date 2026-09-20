#include "tp/segment.hpp"

#include <netinet/ip.h>

#include <cstring>

#include "tp/checksum.hpp"

namespace tp {
namespace {

void put16(uint8_t* p, uint16_t v) {
  p[0] = uint8_t(v >> 8);
  p[1] = uint8_t(v);
}
void put32(uint8_t* p, uint32_t v) {
  p[0] = uint8_t(v >> 24);
  p[1] = uint8_t(v >> 16);
  p[2] = uint8_t(v >> 8);
  p[3] = uint8_t(v);
}
uint16_t get16(const uint8_t* p) { return uint16_t(p[0]) << 8 | p[1]; }
uint32_t get32(const uint8_t* p) {
  return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}

}  // namespace

size_t Options::wire_len() const {
  size_t n = 0;
  if (mss) n += 4;
  if (wscale) n += 3;
  if (sack_permitted) n += 2;
  // NOP, NOP, kind, len, then 8 bytes per block -- the two NOPs are part of the
  // encoding, so they are counted here. wire_len() and encode() disagreeing by
  // those two bytes would put a garbage byte in the data offset and the kernel
  // would silently drop every segment carrying a SACK block.
  if (!sack_blocks.empty()) n += 4 + 8 * sack_blocks.size();
  return (n + 3) & ~size_t(3);  // data offset counts 32-bit words
}

size_t Options::encode(uint8_t* out) const {
  size_t i = 0;
  if (mss) {
    out[i++] = kOptMss;
    out[i++] = 4;
    put16(out + i, *mss);
    i += 2;
  }
  if (sack_permitted) {
    out[i++] = kOptSackPermitted;
    out[i++] = 2;
  }
  if (wscale) {
    out[i++] = kOptWscale;
    out[i++] = 3;
    out[i++] = *wscale;
  }
  if (!sack_blocks.empty()) {
    // RFC 2018 puts no NOP requirement on us, but every stack in the field
    // emits NOP,NOP,SACK so the 8-byte blocks land 4-byte aligned. Matching
    // that costs two bytes and avoids being the one odd sender in a capture.
    // The option's own length field counts only kind+len+blocks, NOT the NOPs.
    out[i++] = kOptNop;
    out[i++] = kOptNop;
    out[i++] = kOptSack;
    out[i++] = uint8_t(2 + 8 * sack_blocks.size());
    for (const SeqRange& b : sack_blocks) {
      put32(out + i, b.start);
      i += 4;
      put32(out + i, b.end);
      i += 4;
    }
  }
  while (i % 4) out[i++] = kOptEol;
  return i;
}

std::string flagstr(uint8_t f) {
  std::string s;
  if (f & TH_FIN) s += 'F';
  if (f & TH_SYN) s += 'S';
  if (f & TH_RST) s += 'R';
  if (f & TH_PUSH) s += 'P';
  if (f & TH_ACK) s += 'A';
  if (f & TH_URG) s += 'U';
  return s.empty() ? "-" : s;
}

size_t build(uint8_t* out, size_t out_cap, in_addr src, in_addr dst, const Seg& s,
             uint16_t ip_id) {
  uint8_t optbuf[40];
  const size_t optlen = s.opt.wire_len();
  if (optlen > sizeof optbuf) return 0;
  memset(optbuf, 0, sizeof optbuf);
  s.opt.encode(optbuf);

  const size_t iplen = sizeof(struct ip);
  const size_t tcplen = sizeof(struct tcphdr) + optlen;
  const size_t total = iplen + tcplen + s.payload.size();
  if (4 + total > out_cap) return 0;

  uint32_t af = htonl(AF_INET);
  memcpy(out, &af, 4);

  auto* ih = reinterpret_cast<struct ip*>(out + 4);
  memset(ih, 0, iplen);
  ih->ip_v = 4;
  ih->ip_hl = iplen / 4;
  // Wire order, not host order: utun hands the frame to ip_input() directly,
  // so nothing byte-swaps ip_len on the way in the way a raw socket would.
  ih->ip_len = htons(uint16_t(total));
  ih->ip_id = htons(ip_id);
  ih->ip_ttl = 64;
  ih->ip_p = IPPROTO_TCP;
  ih->ip_src = src;
  ih->ip_dst = dst;
  ih->ip_sum = htons(fold(sum_be16(ih, iplen)));

  auto* th = reinterpret_cast<struct tcphdr*>(out + 4 + iplen);
  memset(th, 0, sizeof(struct tcphdr));
  th->th_sport = htons(s.sport);
  th->th_dport = htons(s.dport);
  th->th_seq = htonl(s.seq);
  th->th_ack = htonl(s.ack);
  th->th_off = uint8_t(tcplen / 4);
  th->th_flags = s.flags;
  th->th_win = htons(s.win);
  if (optlen) memcpy(out + 4 + iplen + sizeof(struct tcphdr), optbuf, optlen);
  if (!s.payload.empty())
    memcpy(out + 4 + iplen + tcplen, s.payload.data(), s.payload.size());

  struct PseudoHeader {
    in_addr src, dst;
    uint8_t zero, proto;
    uint16_t len;
  } ph{src, dst, 0, IPPROTO_TCP, htons(uint16_t(tcplen + s.payload.size()))};
  static_assert(sizeof(PseudoHeader) == 12, "TCP pseudo-header must be 12 bytes");
  th->th_sum = htons(fold(sum_be16(&ph, sizeof ph) +
                          sum_be16(th, tcplen + s.payload.size())));
  return 4 + total;
}

bool parse(const uint8_t* frame, size_t n, Seg* out) {
  if (n < 4) return false;
  uint32_t af;
  memcpy(&af, frame, 4);
  if (ntohl(af) != AF_INET) return false;
  if (n < 4 + sizeof(struct ip)) return false;

  const auto* ih = reinterpret_cast<const struct ip*>(frame + 4);
  if (ih->ip_v != 4) return false;
  const size_t ihl = size_t(ih->ip_hl) * 4;
  if (ihl < sizeof(struct ip)) return false;
  if (ih->ip_p != IPPROTO_TCP) return false;

  const size_t iptot = ntohs(ih->ip_len);
  // Trust the shorter of the two lengths. A frame claiming more than arrived is
  // the shape of a read that got truncated, and parsing past it reads garbage.
  if (iptot > n - 4) return false;
  if (ihl + sizeof(struct tcphdr) > iptot) return false;

  const auto* th = reinterpret_cast<const struct tcphdr*>(frame + 4 + ihl);
  const size_t doff = size_t(th->th_off) * 4;
  if (doff < sizeof(struct tcphdr) || ihl + doff > iptot) return false;

  out->sport = ntohs(th->th_sport);
  out->dport = ntohs(th->th_dport);
  out->seq = ntohl(th->th_seq);
  out->ack = ntohl(th->th_ack);
  out->flags = th->th_flags;
  out->win = ntohs(th->th_win);
  out->opt = Options{};

  const uint8_t* o = frame + 4 + ihl + sizeof(struct tcphdr);
  const size_t olen = doff - sizeof(struct tcphdr);
  for (size_t i = 0; i < olen;) {
    const uint8_t kind = o[i];
    if (kind == kOptEol) break;
    if (kind == kOptNop) {
      ++i;
      continue;
    }
    if (i + 1 >= olen) break;  // kind with no length byte: malformed, stop
    const uint8_t len = o[i + 1];
    if (len < 2 || i + len > olen) break;
    switch (kind) {
      case kOptMss:
        if (len == 4) out->opt.mss = get16(o + i + 2);
        break;
      case kOptSackPermitted:
        if (len == 2) out->opt.sack_permitted = true;
        break;
      case kOptWscale:
        if (len == 3) out->opt.wscale = o[i + 2];
        break;
      case kOptSack:
        for (size_t b = i + 2; b + 8 <= i + len; b += 8)
          out->opt.sack_blocks.push_back({get32(o + b), get32(o + b + 4)});
        break;
      default:
        break;
    }
    i += len;
  }

  const size_t paylen = iptot - ihl - doff;
  out->payload.assign(frame + 4 + ihl + doff, frame + 4 + ihl + doff + paylen);
  return true;
}

}  // namespace tp
