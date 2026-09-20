// Non-determinism ATTRIBUTION: a battery of probes run against 7 SUL classes,
// producing a signature matrix. The point is that the probes separate
//   "the SUL is genuinely non-deterministic"  from
//   "my mapper has a deterministic bug"       from
//   "I missed a packet"                       from
//   "state leaked from the previous query".
// Every probe here is implementable against the real utun harness; the
// simulated SULs exist only to prove the probes actually discriminate.
// build: clang++ -std=c++20 -O2 -o discriminate discriminate.cpp
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

using Word = std::vector<int>;
using OutWord = std::vector<int>;

static const int SYN = 0, ACK = 1, FIN = 2, RST = 3, DATA = 4, CLOSE = 5;
static const int O_SILENT = 0, O_SYNACK = 1, O_ACK = 2, O_RST = 3, O_FINACK = 4;
static const char *INAME[] = {"SYN", "ACK", "FIN", "RST", "DATA", "close()"};

struct Base {
  int n = 10, k = 6;
  std::vector<std::vector<int>> d, o;
  std::vector<std::vector<char>> chal;
};
static Base tcpBase() {
  Base b;
  b.d.assign(10, std::vector<int>(6, 0)); b.o.assign(10, std::vector<int>(6, 0));
  b.chal.assign(10, std::vector<char>(6, 0));
  auto T = [&](int s,int a,int ns,int out,bool c=false){ b.d[s][a]=ns; b.o[s][a]=out; b.chal[s][a]=c; };
  T(0,SYN,1,O_SYNACK); T(0,ACK,0,O_RST); T(0,FIN,0,O_SILENT); T(0,RST,0,O_SILENT); T(0,DATA,0,O_RST); T(0,CLOSE,9,O_SILENT);
  T(1,SYN,1,O_SILENT); T(1,ACK,2,O_SILENT); T(1,FIN,3,O_ACK); T(1,RST,0,O_SILENT); T(1,DATA,1,O_SILENT); T(1,CLOSE,5,O_FINACK);
  T(2,SYN,2,O_ACK,true); T(2,ACK,2,O_SILENT); T(2,FIN,3,O_ACK); T(2,RST,9,O_SILENT); T(2,DATA,2,O_ACK); T(2,CLOSE,5,O_FINACK);
  T(3,SYN,3,O_ACK,true); T(3,ACK,3,O_SILENT); T(3,FIN,3,O_ACK); T(3,RST,9,O_SILENT); T(3,DATA,3,O_ACK); T(3,CLOSE,4,O_FINACK);
  T(4,SYN,4,O_ACK,true); T(4,ACK,9,O_SILENT); T(4,FIN,4,O_ACK); T(4,RST,9,O_SILENT); T(4,DATA,4,O_SILENT); T(4,CLOSE,4,O_SILENT);
  T(5,SYN,5,O_ACK,true); T(5,ACK,6,O_SILENT); T(5,FIN,7,O_ACK); T(5,RST,9,O_SILENT); T(5,DATA,5,O_ACK); T(5,CLOSE,5,O_SILENT);
  T(6,SYN,6,O_ACK,true); T(6,ACK,6,O_SILENT); T(6,FIN,8,O_ACK); T(6,RST,9,O_SILENT); T(6,DATA,6,O_ACK); T(6,CLOSE,6,O_SILENT);
  T(7,SYN,7,O_ACK,true); T(7,ACK,8,O_SILENT); T(7,FIN,7,O_ACK); T(7,RST,9,O_SILENT); T(7,DATA,7,O_SILENT); T(7,CLOSE,7,O_SILENT);
  T(8,SYN,8,O_ACK,true); T(8,ACK,8,O_SILENT); T(8,FIN,8,O_ACK); T(8,RST,8,O_SILENT); T(8,DATA,8,O_SILENT); T(8,CLOSE,8,O_SILENT);
  T(9,SYN,9,O_RST); T(9,ACK,9,O_RST); T(9,FIN,9,O_RST); T(9,RST,9,O_SILENT); T(9,DATA,9,O_RST); T(9,CLOSE,9,O_SILENT);
  return b;
}

// A SUL exposes reset()/step(); step returns what the LEARNER SEES.
// wireStep() returns what actually went on the wire (the /dev/bpf observer).
struct SUL {
  const Base &b; int cur = 0;
  long resets = 0, steps = 0;
  int lastWire = -1;                 // what a second observer would have seen
  double clockMs = 0.0;              // simulated wall clock
  explicit SUL(const Base &bb) : b(bb) {}
  virtual ~SUL() = default;
  virtual void reset() { resets++; cur = 0; }
  virtual int step(int a) = 0;
  virtual void idle(double ms) { clockMs += ms; }
  virtual void setLimit(int) {}      // the sysctl toggle; no-op unless limited
  virtual const char *name() const = 0;
};

// S1: fully deterministic reference.
struct S_Det : SUL {
  explicit S_Det(const Base &b) : SUL(b) {}
  int step(int a) override { steps++; clockMs += 0.2; int out = b.o[cur][a]; lastWire = out; cur = b.d[cur][a]; return out; }
  const char *name() const override { return "S1 deterministic"; }
};

// S2: the REAL xnu limiter. tp->t_challengeack_count lives in the tcpcb, so it
// is zeroed by every reset (new connection). The 1000 ms window is anchored at
// the first triggering segment; a query that never lasts 1000 ms never crosses
// it. => DETERMINISTIC, just with (L+1) extra states per challenge chain.
struct S_PerConnCounter : SUL {
  int L; int cnt = 0; double anchor = -1;
  long granted = 0, suppressed = 0;
  S_PerConnCounter(const Base &b, int l) : SUL(b), L(l) {}
  void reset() override { SUL::reset(); cur = 0; cnt = 0; anchor = -1; }
  void setLimit(int l) override { L = l; }
  int step(int a) override {
    steps++; clockMs += 0.2;
    int out = b.o[cur][a];
    if (b.chal[cur][a]) {
      if (anchor < 0 || clockMs - anchor >= 1000.0) { anchor = clockMs; cnt = 1; granted++; }
      else if (cnt < L) { cnt++; granted++; }
      else { out = O_SILENT; suppressed++; }
    }
    lastWire = out; cur = b.d[cur][a]; return out;
  }
  const char *name() const override { return "S2 per-conn limiter"; }
};

// S3: the limiter modelled WRONGLY as host-global (the salvage file's model):
// the counter survives reset, so query i's answer depends on queries 0..i-1.
struct S_GlobalCounter : SUL {
  int L; int cnt = 0; double anchor = -1;
  S_GlobalCounter(const Base &b, int l) : SUL(b), L(l) {}
  void reset() override { SUL::reset(); cur = 0; }       // NOTE: cnt survives
  void setLimit(int l) override { L = l; }
  int step(int a) override {
    steps++; clockMs += 0.2;
    int out = b.o[cur][a];
    if (b.chal[cur][a]) {
      if (anchor < 0 || clockMs - anchor >= 1000.0) { anchor = clockMs; cnt = 1; }
      else if (cnt < L) cnt++;
      else out = O_SILENT;
    }
    lastWire = out; cur = b.d[cur][a]; return out;
  }
  const char *name() const override { return "S3 host-global cnt"; }
};

// S4: per-connection counter, but the query is SLOW enough that it sometimes
// straddles the 1000 ms window boundary (scheduler jitter). Genuinely ND, and
// the non-determinism is a function of ELAPSED TIME, not of history.
struct S_WindowStraddle : SUL {
  int L; int cnt = 0; double anchor = -1; double jitterMs; std::mt19937_64 rng;
  S_WindowStraddle(const Base &b, int l, double j, uint64_t sd) : SUL(b), L(l), jitterMs(j), rng(sd) {}
  void reset() override { SUL::reset(); cur = 0; cnt = 0; anchor = -1; }
  void setLimit(int l) override { L = l; }
  int step(int a) override {
    steps++;
    // per-step cost is ~60 ms (a realistic utun round trip with a quiescence
    // wait), and with probability 1/8 the scheduler stalls for jitterMs on top.
    clockMs += 60.0 + ((rng() % 8 == 0) ? jitterMs : 0.0);
    int out = b.o[cur][a];
    if (b.chal[cur][a]) {
      if (anchor < 0 || clockMs - anchor >= 1000.0) { anchor = clockMs; cnt = 1; }
      else if (cnt < L) cnt++;
      else out = O_SILENT;
    }
    lastWire = out; cur = b.d[cur][a]; return out;
  }
  const char *name() const override { return "S4 window straddle"; }
};

// S5: i.i.d. lost output -- the harness's quiescence window expired early, or
// libpcap dropped the frame. Wire says packet, learner records silence.
struct S_LostPacket : SUL {
  double p; std::mt19937_64 rng;
  S_LostPacket(const Base &b, double pp, uint64_t sd) : SUL(b), p(pp), rng(sd) {}
  int step(int a) override {
    steps++; clockMs += 0.2;
    int out = b.o[cur][a]; lastWire = out; cur = b.d[cur][a];
    if (out != O_SILENT && std::uniform_real_distribution<double>(0,1)(rng) < p) return O_SILENT;
    return out;
  }
  const char *name() const override { return "S5 lost packet"; }
};

// S6: a DETERMINISTIC mapper bug: challenge ACKs are always mis-parsed as
// silence. Perfectly repeatable; no ND detector can ever fire.
struct S_MapperBug : SUL {
  explicit S_MapperBug(const Base &b) : SUL(b) {}
  int step(int a) override {
    steps++; clockMs += 0.2;
    int out = b.o[cur][a]; bool c = b.chal[cur][a]; lastWire = out; cur = b.d[cur][a];
    return c ? O_SILENT : out;
  }
  const char *name() const override { return "S6 mapper bug (det)"; }
};

// S7: state leaked from the previous query: reset() fails to clear the TCB
// (e.g. the 4-tuple was reused while the old PCB still existed), so the next
// query starts where the last one ended.
struct S_StateLeak : SUL {
  int carried = 0;
  explicit S_StateLeak(const Base &b) : SUL(b) {}
  void reset() override { resets++; cur = carried; }
  int step(int a) override { steps++; clockMs += 0.2; int out = b.o[cur][a]; lastWire = out; cur = b.d[cur][a]; carried = cur; return out; }
  const char *name() const override { return "S7 prev-query leak"; }
};

// ------------------------------------------------------------------ probes ---
struct Run { OutWord seen, wire; };
static Run runWord(SUL &s, const Word &w) {
  s.reset(); Run r;
  for (int a : w) { int o = s.step(a); r.seen.push_back(o); r.wire.push_back(s.lastWire); }
  return r;
}
static std::string wstr(const Word &w) {
  if (w.empty()) return "eps";
  std::string s; for (size_t i = 0; i < w.size(); i++) { if (i) s += "."; s += INAME[w[i]]; } return s;
}

// P1 REPEAT: R back-to-back runs of w, nothing else in between.
// Returns the 1-based repetition at which the answer first changed, or 0.
static int P1_repeat(SUL &s, const Word &w, int R) {
  OutWord first;
  for (int r = 0; r < R; r++) { auto x = runWord(s, w).seen;
    if (r == 0) first = x; else if (x != first) return r + 1; }
  return 0;
}
// P2 STABILITY of P1 across independent restarts of the whole probe.
// A counter gives the SAME r every time; randomness does not.
struct P2 { std::vector<int> rs; bool constant() const {
  if (rs.empty()) return false;
  for (int r : rs) if (r != rs[0]) return false; return rs[0] != 0; } };
static P2 P2_stability(const std::function<std::unique_ptr<SUL>(uint64_t)> &mk, const Word &w, int R, int trials) {
  P2 p; for (int t = 0; t < trials; t++) { auto s = mk(1000 + 7919ULL*t); p.rs.push_back(P1_repeat(*s, w, R)); } return p;
}
// P3 INTERLEAVE: w, z, w, z, ... Does w's answer change only when z intervenes?
// Compare against the answer P1 settles on when w is run alone.
static int P3_interleave(SUL &s, const Word &w, const Word &z, int R) {
  OutWord first = runWord(s, w).seen;
  for (int r = 1; r < R; r++) { runWord(s, z); auto x = runWord(s, w).seen; if (x != first) return r + 1; }
  return 0;
}
// P4 IDLE: w, idle(T), w.  Does the answer depend on T?
static bool P4_idleSensitive(const std::function<std::unique_ptr<SUL>(uint64_t)> &mk, const Word &w, double T) {
  auto a = mk(4242); OutWord x0 = runWord(*a, w).seen; OutWord x1 = runWord(*a, w).seen;
  auto b = mk(4242); OutWord y0 = runWord(*b, w).seen; b->idle(T); OutWord y1 = runWord(*b, w).seen;
  (void)x0; (void)y0;
  return x1 != y1;
}
// P5 OBSERVER: fraction of positions where seen != wire (the /dev/bpf check).
static double P5_observerMismatch(SUL &s, const std::vector<Word> &ws) {
  long tot = 0, bad = 0;
  for (auto &w : ws) { auto r = runWord(s, w);
    for (size_t i = 0; i < r.seen.size(); i++) { tot++; if (r.seen[i] != r.wire[i]) bad++; } }
  return tot ? (double)bad / tot : 0.0;
}
// P6 PREFIX CONSISTENCY: out(u) must be a prefix of out(u.v) for every u,v.
// This is free: the query cache already stores it as a trie.
static double P6_prefixViolations(SUL &s, const std::vector<Word> &ws) {
  long tot = 0, bad = 0;
  for (auto &w : ws) { if (w.size() < 2) continue;
    auto full = runWord(s, w).seen;
    for (size_t L = 1; L < w.size(); L++) { Word u(w.begin(), w.begin() + L);
      auto pre = runWord(s, u).seen; tot++;
      for (size_t i = 0; i < pre.size(); i++) if (pre[i] != full[i]) { bad++; break; } } }
  return tot ? (double)bad / tot : 0.0;
}
// P7 SYSCTL TOGGLE: does the P1 divergence vanish when the limit is raised?
static bool P7_toggleFixes(const std::function<std::unique_ptr<SUL>(uint64_t)> &mk, const Word &w, int R) {
  auto a = mk(9001); int before = P1_repeat(*a, w, R);
  auto b = mk(9001); b->setLimit(1 << 20); int after = P1_repeat(*b, w, R);
  return before != 0 && after == 0;
}

int main() {
  Base b = tcpBase();
  const int L = 10;
  // the witness word: drive to ESTABLISHED then fire challenge triggers
  Word wChal = {SYN, ACK, SYN};
  Word wLong = {SYN, ACK, SYN, SYN, SYN, SYN, SYN, SYN, SYN, SYN, SYN, SYN, SYN, SYN};
  Word zScrub = {SYN, ACK, DATA, CLOSE};
  std::mt19937_64 rng(7);
  std::vector<Word> corpus;
  for (int i = 0; i < 400; i++) { int len = 2 + (int)(rng() % 7); Word w;
    for (int j = 0; j < len; j++) w.push_back((int)(rng() % 6)); corpus.push_back(w); }

  struct Row { const char *nm; std::function<std::unique_ptr<SUL>(uint64_t)> mk; };
  std::vector<Row> rows = {
    {"S1 deterministic",     [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_Det(b)); }},
    {"S2 per-conn limiter",  [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_PerConnCounter(b, L)); }},
    {"S3 host-global cnt",   [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_GlobalCounter(b, L)); }},
    {"S4 window straddle",   [&](uint64_t sd){ return std::unique_ptr<SUL>(new S_WindowStraddle(b, L, 700.0, sd)); }},
    {"S5 lost packet p=.05", [&](uint64_t sd){ return std::unique_ptr<SUL>(new S_LostPacket(b, 0.05, sd)); }},
    {"S6 mapper bug (det)",  [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_MapperBug(b)); }},
    {"S7 prev-query leak",   [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_StateLeak(b)); }},
  };

  std::printf("probe battery\n  witness w = %s   (%zu symbols, %d challenge triggers > L)\n  scrub   z = %s\n  L = %d\n\n",
              wstr(wLong).c_str(), wLong.size(), 12, wstr(zScrub).c_str(), L);
  (void)wChal;
  std::printf("%-22s %-10s %-26s %-10s %-8s %-9s %-9s %-8s\n",
              "SUL", "P1 rep@", "P2 stable across 8 trials", "P3 intlv@", "P4 idle", "P5 obs%", "P6 pfx%", "P7 sysctl");
  for (auto &r : rows) {
    auto s1 = r.mk(11); int p1 = P1_repeat(*s1, wLong, 60);
    auto p2 = P2_stability(r.mk, wLong, 60, 8);
    auto s3 = r.mk(11); int p3 = P3_interleave(*s3, wLong, zScrub, 60);
    bool p4 = P4_idleSensitive(r.mk, wLong, 1500.0);
    auto s5 = r.mk(11); double p5 = P5_observerMismatch(*s5, corpus);
    auto s6 = r.mk(11); double p6 = P6_prefixViolations(*s6, corpus);
    bool p7 = P7_toggleFixes(r.mk, wLong, 60);
    std::string p2s; for (size_t i = 0; i < p2.rs.size(); i++) { p2s += std::to_string(p2.rs[i]); if (i+1<p2.rs.size()) p2s += ","; }
    p2s += p2.constant() ? " CONST" : "";
    std::printf("%-22s %-10d %-26s %-10d %-8s %8.2f%% %8.2f%% %-8s\n",
                r.nm, p1, p2s.c_str(), p3, p4 ? "YES" : "no", 100*p5, 100*p6, p7 ? "FIXES" : "no");
  }

  std::printf("\n-- P1 divergence repetition vs the limit L (S3 host-global only; S2 never diverges) --\n");
  for (int l : {1, 2, 5, 10, 20}) {
    Word wShort = {SYN, ACK, SYN};
    auto s = std::unique_ptr<SUL>(new S_GlobalCounter(b, l));
    int r = P1_repeat(*s, wShort, 80);
    auto s2 = std::unique_ptr<SUL>(new S_PerConnCounter(b, l));
    int r2 = P1_repeat(*s2, wShort, 80);
    std::printf("  L=%-3d  S3 first divergence at rep %-3d (L+1 = %-3d) %s   |  S2 first divergence at rep %d\n",
                l, r, l + 1, r == l + 1 ? "MATCH" : "MISMATCH", r2);
  }

  std::printf("\n-- the saturation probe: how many challenge ACKs does ONE connection get? --\n");
  for (int l : {1, 2, 5, 10}) {
    S_PerConnCounter s(b, l);
    s.reset(); s.step(SYN); s.step(ACK);
    for (int i = 0; i < 200; i++) s.step(SYN);
    std::printf("  L=%-3d  200 in-window triggers on one connection: granted=%-4ld suppressed=%-4ld  granted==L? %s\n",
                l, s.granted, s.suppressed, s.granted == l ? "YES" : "no");
  }

  std::printf("\n-- P8: a DETERMINISTIC slow harness is still deterministic, but it learns a\n"
              "   DIFFERENT machine. Same SUL, two harness speeds, same witness. --\n");
  Word wVeryLong; for (int i = 0; i < 3; i++) { wVeryLong.push_back(SYN); wVeryLong.push_back(ACK); }
  for (int i = 0; i < 24; i++) wVeryLong.push_back(SYN);
  for (double stepMs : {0.2, 20.0, 60.0, 120.0}) {
    S_PerConnCounter s(b, L); OutWord first; int diverge = 0; OutWord o0;
    for (int rep = 0; rep < 30; rep++) {
      s.reset(); OutWord o;
      for (int a : wVeryLong) { o.push_back(s.step(a)); s.idle(stepMs - 0.2); }
      if (rep == 0) { first = o; o0 = o; } else if (o != first) { diverge = rep + 1; break; }
    }
    long nonSilent = 0; for (int x : o0) if (x != O_SILENT) nonSilent++;
    std::printf("  per-step cost %6.1f ms (query span %7.1f ms): repeat-divergence at rep %-3d"
                " | non-silent outputs in the answer = %ld %s\n",
                stepMs, stepMs * wVeryLong.size(), diverge, nonSilent,
                diverge ? "<-- ND" : "(deterministic)");
  }

  std::printf("\n-- P9: JITTER is what makes the timed SUL non-deterministic, not slowness --\n");
  for (double jit : {0.0, 100.0, 700.0}) {
    int div = 0;
    for (int t = 0; t < 8 && !div; t++) { S_WindowStraddle s(b, L, jit, 500 + 13*t); div = P1_repeat(s, wVeryLong, 40); }
    std::printf("  per-step 60 ms, stall %5.1f ms with prob 1/8: first divergence at rep %-3d %s\n",
                jit, div, div ? "<-- ND" : "(deterministic)");
  }
  return 0;
}
