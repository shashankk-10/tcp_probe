#include "tp/trace.hpp"

#include "tp/segment.hpp"

namespace tp {

void Trace::set_origin(double t0_ms, uint32_t data_isn, uint32_t our_isn) {
  t0_ = t0_ms;
  data_isn_ = data_isn;
  our_isn_ = our_isn;
}

void Trace::record_rx(double t_ms, uint32_t seq, uint32_t ack, uint8_t flags,
                      uint32_t len, bool dropped, std::string note) {
  Event e;
  e.t_ms = t_ms - t0_;
  e.tx = false;
  e.flags = flags;
  // Inbound seq lives in the kernel's space, inbound ack in ours.
  e.rel_seq = int64_t(int32_t(seq - data_isn_));
  e.rel_ack = int64_t(int32_t(ack - our_isn_));
  e.len = len;
  e.dropped = dropped;
  e.note = std::move(note);
  events_.push_back(std::move(e));
}

void Trace::record_tx(double t_ms, uint32_t seq, uint32_t ack, uint8_t flags,
                      uint32_t len, std::string note) {
  Event e;
  e.t_ms = t_ms - t0_;
  e.tx = true;
  e.flags = flags;
  // Outbound seq is ours, outbound ack refers to the kernel's stream. This is
  // the mirror of record_rx and it is the single easiest thing in the project
  // to get backwards; getting it backwards yields a trace that looks plausible
  // and is off by the difference of two random ISNs.
  e.rel_seq = int64_t(int32_t(seq - our_isn_));
  e.rel_ack = int64_t(int32_t(ack - data_isn_));
  e.len = len;
  e.note = std::move(note);
  events_.push_back(std::move(e));
}

void Trace::note(double t_ms, std::string text) {
  Event e;
  e.t_ms = t_ms - t0_;
  e.note = std::move(text);
  e.flags = 0;
  events_.push_back(std::move(e));
}

void Trace::dump(FILE* out) const {
  fprintf(out, "   %9s  %-3s %-5s %10s %10s %6s  %s\n", "t(ms)", "dir", "flags", "seq",
          "ack", "len", "note");
  for (const Event& e : events_) {
    if (e.flags == 0 && e.len == 0 && !e.note.empty()) {
      fprintf(out, "   %9.3f  %s\n", e.t_ms, e.note.c_str());
      continue;
    }
    fprintf(out, "   %9.3f  %-3s %-5s %10lld %10lld %6u  %s%s\n", e.t_ms,
            e.tx ? "-->" : "<--", flagstr(e.flags).c_str(), (long long)e.rel_seq,
            (long long)e.rel_ack, e.len, e.dropped ? "DROPPED " : "", e.note.c_str());
  }
}

bool Trace::write_csv(const std::string& path) const {
  FILE* f = fopen(path.c_str(), "w");
  if (!f) return false;
  fprintf(f, "t_ms,dir,flags,rel_seq,rel_ack,len,dropped,note\n");
  for (const Event& e : events_) {
    // Notes carry strerror() text and interface names, so a quote in one is not
    // hypothetical. RFC 4180 escapes a quote by doubling it.
    std::string note;
    note.reserve(e.note.size());
    for (char c : e.note) {
      if (c == '"') note += '"';
      note += c;
    }
    fprintf(f, "%.6f,%s,%s,%lld,%lld,%u,%d,\"%s\"\n", e.t_ms, e.tx ? "tx" : "rx",
            flagstr(e.flags).c_str(), (long long)e.rel_seq, (long long)e.rel_ack, e.len,
            e.dropped ? 1 : 0, note.c_str());
  }
  fclose(f);
  return true;
}

}  // namespace tp
