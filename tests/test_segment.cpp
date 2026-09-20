// Wire encode/decode. The option encoder is the part that decides whether the
// kernel arms a tail-loss-probe timer, so its length accounting is tested
// here directly, and not inferred from a packet that happened to arrive.

#include "tp/segment.hpp"

#include <arpa/inet.h>
#include <netinet/ip.h>

#include <cstring>

#include "check.hpp"
#include "tp/checksum.hpp"

using namespace tp;

namespace {

in_addr addr(const char* s) {
  in_addr a{};
  inet_pton(AF_INET, s, &a);
  return a;
}

// Round-trips a segment through build() and parse() and returns the result.
bool roundtrip(const Seg& in, Seg* out) {
  uint8_t buf[4 + 1500];
  size_t n = build(buf, sizeof buf, addr("10.90.0.2"), addr("10.90.0.1"), in, 1);
  if (n == 0) return false;
  return parse(buf, n, out);
}

}  // namespace

int main() {
  // ---- option lengths. wire_len() and encode() disagreeing puts a wrong
  // value in the 4-bit data offset, and the kernel silently drops the segment.
  {
    Options o;
    CHECK_EQ(o.wire_len(), 0u);

    o.mss = 1024;
    CHECK_EQ(o.wire_len(), 4u);

    o.sack_permitted = true;  // +2 -> 6, padded to 8
    CHECK_EQ(o.wire_len(), 8u);

    Options s;
    s.sack_blocks = {{100, 200}};  // NOP NOP kind len + 8 = 12
    CHECK_EQ(s.wire_len(), 12u);
    s.sack_blocks.push_back({300, 400});  // + 8 = 20
    CHECK_EQ(s.wire_len(), 20u);

    // encode() must write exactly wire_len() bytes, every time.
    for (const Options* p : {&o, &s}) {
      uint8_t buf[40];
      memset(buf, 0xaa, sizeof buf);
      size_t n = p->encode(buf);
      CHECK_EQ(n, p->wire_len());
      CHECK_EQ(n % 4, 0u);
    }
  }

  // ---- a bare ACK round-trips with every field intact.
  {
    Seg in;
    in.sport = 40001;
    in.dport = 9999;
    in.seq = 0x11223344;
    in.ack = 0x55667788;
    in.flags = TH_ACK;
    in.win = 65535;
    Seg out;
    CHECK(roundtrip(in, &out));
    CHECK_EQ(out.sport, in.sport);
    CHECK_EQ(out.dport, in.dport);
    CHECK_EQ(out.seq, in.seq);
    CHECK_EQ(out.ack, in.ack);
    CHECK_EQ(out.flags, in.flags);
    CHECK_EQ(out.win, in.win);
    CHECK_EQ(out.payload.size(), 0u);
  }

  // ---- a SYN carrying MSS and SACK-permitted. This is the segment the whole
  // TLP experiment turns on, so both options must survive the round trip.
  {
    Seg in;
    in.sport = 40001;
    in.dport = 9999;
    in.seq = 1000;
    in.flags = TH_SYN;
    in.win = 65535;
    in.opt.mss = 1024;
    in.opt.sack_permitted = true;
    Seg out;
    CHECK(roundtrip(in, &out));
    CHECK(out.opt.mss.has_value());
    CHECK_EQ(out.opt.mss.value_or(0), 1024);
    CHECK(out.opt.sack_permitted);
  }

  // ---- the same SYN without sack_permitted must NOT come back with it set.
  // A parser that defaults the flag to true would make every run look like the
  // SACK arm of the experiment.
  {
    Seg in;
    in.sport = 40001;
    in.dport = 9999;
    in.flags = TH_SYN;
    in.opt.mss = 1024;
    Seg out;
    CHECK(roundtrip(in, &out));
    CHECK(!out.opt.sack_permitted);
  }

  // ---- SACK blocks survive with their boundaries exact.
  {
    Seg in;
    in.sport = 40001;
    in.dport = 9999;
    in.flags = TH_ACK;
    in.opt.sack_blocks = {{5000, 6000}, {7000, 8000}};
    Seg out;
    CHECK(roundtrip(in, &out));
    CHECK_EQ(out.opt.sack_blocks.size(), 2u);
    if (out.opt.sack_blocks.size() == 2) {
      CHECK_EQ(out.opt.sack_blocks[0].start, 5000u);
      CHECK_EQ(out.opt.sack_blocks[0].end, 6000u);
      CHECK_EQ(out.opt.sack_blocks[1].start, 7000u);
      CHECK_EQ(out.opt.sack_blocks[1].end, 8000u);
    }
  }

  // ---- payload survives alongside options.
  {
    Seg in;
    in.sport = 40001;
    in.dport = 9999;
    in.flags = TH_PUSH | TH_ACK;
    in.payload = {'h', 'e', 'l', 'l', 'o'};
    in.opt.sack_blocks = {{1, 2}};
    Seg out;
    CHECK(roundtrip(in, &out));
    CHECK_EQ(out.payload.size(), 5u);
    CHECK(out.payload == in.payload);
  }

  // ---- the checksum a receiver computes over the built packet is zero.
  {
    Seg in;
    in.sport = 40001;
    in.dport = 9999;
    in.seq = 12345;
    in.ack = 67890;
    in.flags = TH_ACK;
    in.win = 4096;
    in.payload.assign(37, 0x5a);  // odd length, to exercise the padding path
    uint8_t buf[4 + 1500];
    in_addr src = addr("10.90.0.2"), dst = addr("10.90.0.1");
    size_t n = build(buf, sizeof buf, src, dst, in, 7);
    CHECK(n > 0);

    const auto* ih = reinterpret_cast<const struct ip*>(buf + 4);
    CHECK_EQ(fold(sum_be16(ih, sizeof(struct ip))), 0);

    const size_t ihl = size_t(ih->ip_hl) * 4;
    const size_t tcp_total = ntohs(ih->ip_len) - ihl;
    struct {
      in_addr s, d;
      uint8_t z, p;
      uint16_t l;
    } ph{src, dst, 0, IPPROTO_TCP, htons(uint16_t(tcp_total))};
    CHECK_EQ(fold(sum_be16(&ph, sizeof ph) + sum_be16(buf + 4 + ihl, tcp_total)), 0);
  }

  // ---- parse() must reject, not misread, frames that are not ours.
  {
    Seg out;
    uint8_t frame[64];
    memset(frame, 0, sizeof frame);

    CHECK(!parse(frame, 3, &out));  // shorter than the AF prefix

    uint32_t af6 = htonl(AF_INET6);
    memcpy(frame, &af6, 4);
    CHECK(!parse(frame, sizeof frame, &out));  // the MLD/RS traffic a new utun emits

    uint32_t af4 = htonl(AF_INET);
    memcpy(frame, &af4, 4);
    auto* ih = reinterpret_cast<struct ip*>(frame + 4);
    ih->ip_v = 4;
    ih->ip_hl = 5;
    ih->ip_p = IPPROTO_UDP;
    ih->ip_len = htons(28);
    CHECK(!parse(frame, sizeof frame, &out));  // not TCP

    // ip_len claiming more than arrived: the shape of a truncated read. Parsing
    // past it reads whatever was in the buffer from the previous frame.
    ih->ip_p = IPPROTO_TCP;
    ih->ip_len = htons(900);
    CHECK(!parse(frame, 4 + 40, &out));

    // A data offset smaller than a bare TCP header is malformed.
    ih->ip_len = htons(40);
    auto* th = reinterpret_cast<struct tcphdr*>(frame + 4 + 20);
    th->th_off = 3;
    CHECK(!parse(frame, 4 + 40, &out));
  }

  // ---- a truncated option field must terminate the parse loop, not spin or
  // read past the header. A kind byte with no length byte after it is the case
  // that gets this wrong.
  {
    Seg in;
    in.sport = 1;
    in.dport = 2;
    in.flags = TH_SYN;
    in.opt.mss = 512;
    uint8_t buf[4 + 1500];
    size_t n = build(buf, sizeof buf, addr("10.90.0.2"), addr("10.90.0.1"), in, 1);
    CHECK(n > 0);
    // Overwrite the MSS option with a lone kind byte and pad the rest with a
    // kind that claims a length running past the option field.
    auto* ih = reinterpret_cast<struct ip*>(buf + 4);
    uint8_t* o = buf + 4 + size_t(ih->ip_hl) * 4 + sizeof(struct tcphdr);
    o[0] = kOptSack;
    o[1] = 200;  // length far beyond the option field
    Seg out;
    CHECK(parse(buf, n, &out));  // header is still well-formed
    CHECK_EQ(out.opt.sack_blocks.size(), 0u);  // and nothing was invented
  }

  // ---- seq_span: SYN and FIN each occupy a sequence number.
  {
    Seg s;
    s.flags = TH_SYN;
    CHECK_EQ(s.seq_span(), 1u);
    s.flags = TH_FIN | TH_ACK;
    CHECK_EQ(s.seq_span(), 1u);
    s.flags = TH_ACK;
    s.payload.assign(10, 0);
    CHECK_EQ(s.seq_span(), 10u);
    s.flags = TH_FIN | TH_ACK;
    CHECK_EQ(s.seq_span(), 11u);
  }

  CHECK_STR(flagstr(TH_SYN | TH_ACK), "SA");
  CHECK_STR(flagstr(TH_FIN | TH_PUSH | TH_ACK), "FPA");
  CHECK_STR(flagstr(0), "-");

  return check::finish("segment");
}
