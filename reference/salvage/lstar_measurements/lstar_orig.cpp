// Mealy L* with Rivest-Schapire counterexample analysis.
// Scratch reference implementation to measure query counts and to characterise
// exactly how a non-deterministic SUL breaks the algorithm.
// build: clang++ -std=c++20 -O2 -o lstar lstar.cpp
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using Word = std::vector<int>;
using OutWord = std::vector<int>;

// ------------------------------------------------------------------ Mealy ----
struct Mealy {
  int n = 0, k = 0;
  std::vector<std::vector<int>> d;  // next state
  std::vector<std::vector<int>> o;  // output
  std::vector<std::vector<char>> chal;  // marks "challenge-ACK" transitions
  std::vector<std::string> sname;
  std::vector<std::string> iname;
  std::vector<std::string> oname;

  int step(int s, int a, int &out) const { out = o[s][a]; return d[s][a]; }
  OutWord run(int s, const Word &w) const {
    OutWord r; r.reserve(w.size());
    for (int a : w) { r.push_back(o[s][a]); s = d[s][a]; }
    return r;
  }
  int reach(int s, const Word &w) const { for (int a : w) s = d[s][a]; return s; }
};

static const int SYN = 0, ACK = 1, FIN = 2, RST = 3, DATA = 4, CLOSE = 5;
static const int O_SILENT = 0, O_SYNACK = 1, O_ACK = 2, O_RST = 3, O_FINACK = 4;

// A hand-written server-side TCP-ish Mealy machine. NOT the kernel: a test bed
// with roughly the right shape so query counts are in the right ballpark.
static Mealy tcpServer() {
  Mealy m;
  m.k = 6;
  m.iname = {"SYN", "ACK", "FIN", "RST", "DATA", "close()"};
  m.oname = {"-", "SYNACK", "ACK", "RST", "FINACK"};
  m.sname = {"LISTEN","SYN_RCVD","ESTAB","CLOSE_WAIT","LAST_ACK",
             "FIN_WAIT_1","FIN_WAIT_2","CLOSING","TIME_WAIT","CLOSED"};
  m.n = (int)m.sname.size();
  m.d.assign(m.n, std::vector<int>(m.k, 0));
  m.o.assign(m.n, std::vector<int>(m.k, 0));
  m.chal.assign(m.n, std::vector<char>(m.k, 0));
  auto T = [&](int s, int a, int ns, int out, bool c = false) {
    m.d[s][a] = ns; m.o[s][a] = out; m.chal[s][a] = c;
  };
  // LISTEN
  T(0,SYN,1,O_SYNACK); T(0,ACK,0,O_RST); T(0,FIN,0,O_SILENT);
  T(0,RST,0,O_SILENT); T(0,DATA,0,O_RST); T(0,CLOSE,9,O_SILENT);
  // SYN_RCVD
  T(1,SYN,1,O_SILENT); T(1,ACK,2,O_SILENT); T(1,FIN,3,O_ACK);
  T(1,RST,0,O_SILENT); T(1,DATA,1,O_SILENT); T(1,CLOSE,5,O_FINACK);
  // ESTAB
  T(2,SYN,2,O_ACK,true); T(2,ACK,2,O_SILENT); T(2,FIN,3,O_ACK);
  T(2,RST,9,O_SILENT); T(2,DATA,2,O_ACK); T(2,CLOSE,5,O_FINACK);
  // CLOSE_WAIT
  T(3,SYN,3,O_ACK,true); T(3,ACK,3,O_SILENT); T(3,FIN,3,O_ACK);
  T(3,RST,9,O_SILENT); T(3,DATA,3,O_ACK); T(3,CLOSE,4,O_FINACK);
  // LAST_ACK
  T(4,SYN,4,O_ACK,true); T(4,ACK,9,O_SILENT); T(4,FIN,4,O_ACK);
  T(4,RST,9,O_SILENT); T(4,DATA,4,O_SILENT); T(4,CLOSE,4,O_SILENT);
  // FIN_WAIT_1
  T(5,SYN,5,O_ACK,true); T(5,ACK,6,O_SILENT); T(5,FIN,7,O_ACK);
  T(5,RST,9,O_SILENT); T(5,DATA,5,O_ACK); T(5,CLOSE,5,O_SILENT);
  // FIN_WAIT_2
  T(6,SYN,6,O_ACK,true); T(6,ACK,6,O_SILENT); T(6,FIN,8,O_ACK);
  T(6,RST,9,O_SILENT); T(6,DATA,6,O_ACK); T(6,CLOSE,6,O_SILENT);
  // CLOSING
  T(7,SYN,7,O_ACK,true); T(7,ACK,8,O_SILENT); T(7,FIN,7,O_ACK);
  T(7,RST,9,O_SILENT); T(7,DATA,7,O_SILENT); T(7,CLOSE,7,O_SILENT);
  // TIME_WAIT
  T(8,SYN,8,O_ACK,true); T(8,ACK,8,O_SILENT); T(8,FIN,8,O_ACK);
  T(8,RST,8,O_SILENT); T(8,DATA,8,O_SILENT); T(8,CLOSE,8,O_SILENT);
  // CLOSED
  T(9,SYN,9,O_RST); T(9,ACK,9,O_RST); T(9,FIN,9,O_RST);
  T(9,RST,9,O_SILENT); T(9,DATA,9,O_RST); T(9,CLOSE,9,O_SILENT);
  return m;
}

// Moore partition refinement: report number of distinguishable states.
static int minimalSize(const Mealy &m) {
  std::vector<int> cls(m.n);
  {  // initial: by output signature
    std::map<std::vector<int>, int> sig;
    for (int s = 0; s < m.n; s++) cls[s] = sig.emplace(m.o[s], (int)sig.size()).first->second;
  }
  while (true) {
    std::map<std::vector<int>, int> sig;
    std::vector<int> nc(m.n);
    for (int s = 0; s < m.n; s++) {
      std::vector<int> key{cls[s]};
      for (int a = 0; a < m.k; a++) key.push_back(cls[m.d[s][a]]);
      nc[s] = sig.emplace(key, (int)sig.size()).first->second;
    }
    if (sig.size() == (size_t)(*std::max_element(cls.begin(), cls.end()) + 1)) { cls = nc; break; }
    cls = nc;
  }
  return *std::max_element(cls.begin(), cls.end()) + 1;
}

// ------------------------------------------------------------------- SULs ----
struct SUL {
  long resets = 0, steps = 0;
  virtual ~SUL() = default;
  virtual void reset() = 0;
  virtual int step(int a) = 0;
};

struct RefSUL : SUL {
  const Mealy &m; int cur = 0;
  explicit RefSUL(const Mealy &mm) : m(mm) {}
  void reset() override { resets++; cur = 0; }
  int step(int a) override { steps++; int out = m.o[cur][a]; cur = m.d[cur][a]; return out; }
};

// Reference machine + a HOST-GLOBAL token bucket on challenge-ACK transitions.
// Mirrors net.inet.tcp.challengeack_limit: the counter survives connection
// reset (it is not part of the TCB), and refills on a wall-clock period, which
// we model as `period` SUL steps.
struct ChallengeSUL : SUL {
  const Mealy &m; int cur = 0;
  int limit; long period;
  long g = 0; long epoch = -1; int tokens = 0;
  long suppressed = 0, granted = 0;
  ChallengeSUL(const Mealy &mm, int lim, long per) : m(mm), limit(lim), period(per) {}
  void reset() override { resets++; cur = 0; }   // NOTE: does not reset tokens
  int step(int a) override {
    steps++;
    long e = g / period; g++;
    if (e != epoch) { epoch = e; tokens = limit; }
    int out = m.o[cur][a];
    if (m.chal[cur][a]) {
      if (tokens > 0) { tokens--; granted++; }
      else { out = O_SILENT; suppressed++; }
    }
    cur = m.d[cur][a];
    return out;
  }
};

// Control A: a FLAKY mapper. Deterministic kernel, but the harness loses the
// output of a challenge-ACK transition with independent probability p (e.g. the
// quiescence window is shorter than the delayed-ACK timer, or libpcap drops).
struct FlakySUL : SUL {
  const Mealy &m; int cur = 0; double p; std::mt19937_64 rng;
  long lost = 0;
  FlakySUL(const Mealy &mm, double pp, uint64_t seed) : m(mm), p(pp), rng(seed) {}
  void reset() override { resets++; cur = 0; }
  int step(int a) override {
    steps++; int out = m.o[cur][a]; cur = m.d[cur][a];
    if (out != O_SILENT && std::uniform_real_distribution<double>(0,1)(rng) < p) { lost++; return O_SILENT; }
    return out;
  }
};

// Control B: a DETERMINISTIC mapper bug. The harness systematically mis-parses
// one output (challenge ACK read as silence, always).
struct DetBugSUL : SUL {
  const Mealy &m; int cur = 0;
  explicit DetBugSUL(const Mealy &mm) : m(mm) {}
  void reset() override { resets++; cur = 0; }
  int step(int a) override {
    steps++; int out = m.o[cur][a]; bool c = m.chal[cur][a]; cur = m.d[cur][a];
    return c ? O_SILENT : out;
  }
};

// ------------------------------------------------- prefix-closed query cache --
struct Cache {
  struct Node { std::vector<int> child, out; explicit Node(int k) : child(k, -1), out(k, -1) {} };
  int k; std::vector<Node> nodes;
  long hits = 0, misses = 0, hitSymbols = 0, prefixAudits = 0, contradictions = 0;
  std::vector<std::string> contraLog;
  explicit Cache(int kk) : k(kk) { nodes.emplace_back(k); }
  std::optional<OutWord> lookup(const Word &w) const {
    int u = 0; OutWord r;
    for (int a : w) { if (nodes[u].child[a] < 0) return std::nullopt; r.push_back(nodes[u].out[a]); u = nodes[u].child[a]; }
    return r;
  }
  // insert; every already-known edge on the path is a free re-observation check
  void insert(const Word &w, const OutWord &o, const std::vector<std::string> &iname) {
    int u = 0;
    for (size_t i = 0; i < w.size(); i++) {
      int a = w[i];
      if (nodes[u].child[a] < 0) { nodes[u].child[a] = (int)nodes.size(); nodes.emplace_back(k); nodes[u].out[a] = o[i]; }
      else {
        prefixAudits++;
        if (nodes[u].out[a] != o[i]) {
          contradictions++;
          if (contraLog.size() < 6) {
            std::ostringstream ss; ss << "prefix len " << (i + 1) << " of [";
            for (size_t j = 0; j < w.size(); j++) ss << (j ? " " : "") << iname[w[j]];
            ss << "] : stored out#" << nodes[u].out[a] << " fresh out#" << o[i];
            contraLog.push_back(ss.str());
          }
        }
      }
      u = nodes[u].child[a];
    }
  }
  long edges() const { long e = 0; for (auto &nd : nodes) for (int c : nd.child) if (c >= 0) e++; return e; }
};

struct Oracle {
  SUL &sul; Cache cache; const std::vector<std::string> &iname;
  double auditRate = 0.0;      // fraction of cache hits re-run against the SUL
  int repeats = 1;             // >1 => majority vote per position
  long mq = 0;                 // logical membership queries asked by learner
  long voteDisagreements = 0;
  long auditRuns = 0, auditContradictions = 0;
  std::mt19937_64 rng{12345};
  Oracle(SUL &s, int k, const std::vector<std::string> &in) : sul(s), cache(k), iname(in) {}

  OutWord raw(const Word &w) {
    sul.reset(); OutWord r; r.reserve(w.size());
    for (int a : w) r.push_back(sul.step(a));
    return r;
  }
  OutWord rawVoted(const Word &w) {
    if (repeats <= 1) return raw(w);
    std::vector<OutWord> runs;
    for (int i = 0; i < repeats; i++) runs.push_back(raw(w));
    OutWord r(w.size());
    bool dis = false;
    for (size_t i = 0; i < w.size(); i++) {
      std::map<int, int> cnt; for (auto &x : runs) cnt[x[i]]++;
      int best = -1, bc = -1; for (auto &[v, c] : cnt) if (c > bc) { bc = c; best = v; }
      if (cnt.size() > 1) dis = true;
      r[i] = best;
    }
    if (dis) voteDisagreements++;
    return r;
  }
  bool bypass = false;         // serve nothing from cache; still record+check
  OutWord query(const Word &w) {
    mq++;
    if (bypass) {
      auto fresh = rawVoted(w);
      cache.insert(w, fresh, iname);   // verifying-only cache
      cache.misses++;
      return fresh;
    }
    auto hit = cache.lookup(w);
    if (hit) {
      cache.hits++; cache.hitSymbols += (long)w.size();
      if (auditRate > 0 && std::uniform_real_distribution<double>(0, 1)(rng) < auditRate) {
        auditRuns++;
        auto fresh = rawVoted(w);
        if (fresh != *hit) {
          auditContradictions++;
          if (cache.contraLog.size() < 6) {
            std::ostringstream ss; ss << "audit of [";
            for (size_t j = 0; j < w.size(); j++) ss << (j ? " " : "") << iname[w[j]];
            ss << "] differs from cached answer";
            cache.contraLog.push_back(ss.str());
          }
        }
      }
      return *hit;
    }
    cache.misses++;
    auto fresh = rawVoted(w);
    cache.insert(w, fresh, iname);
    return fresh;
  }
};

// ----------------------------------------------------------------- helpers ---
static Word cat(const Word &a, const Word &b) { Word r = a; r.insert(r.end(), b.begin(), b.end()); return r; }
static Word cat1(const Word &a, int s) { Word r = a; r.push_back(s); return r; }
static OutWord lastN(const OutWord &o, size_t n) { return OutWord(o.end() - n, o.end()); }
static std::string wstr(const Word &w, const std::vector<std::string> &nm) {
  if (w.empty()) return "eps";
  std::string s; for (size_t i = 0; i < w.size(); i++) { if (i) s += "."; s += nm[w[i]]; } return s;
}

// -------------------------------------------------- characterizing set W -----
// Pairwise BFS for shortest separating words, then greedy set cover.
static std::vector<Word> characterizingSet(const Mealy &h) {
  int n = h.n;
  std::set<Word> cand;
  for (int p = 0; p < n; p++) for (int q = p + 1; q < n; q++) {
    std::set<std::pair<int,int>> seen; std::queue<std::pair<std::pair<int,int>, Word>> Q;
    Q.push({{p, q}, {}}); seen.insert({p, q}); bool found = false;
    while (!Q.empty() && !found) {
      auto [st, w] = Q.front(); Q.pop();
      for (int a = 0; a < h.k; a++) {
        if (h.o[st.first][a] != h.o[st.second][a]) { cand.insert(cat1(w, a)); found = true; break; }
        std::pair<int,int> ns{h.d[st.first][a], h.d[st.second][a]};
        if (ns.first > ns.second) std::swap(ns.first, ns.second);
        if (seen.insert(ns).second) Q.push({ns, cat1(w, a)});
      }
    }
  }
  std::vector<Word> pool(cand.begin(), cand.end());
  std::set<std::pair<int,int>> need;
  for (int p = 0; p < n; p++) for (int q = p + 1; q < n; q++) need.insert({p, q});
  std::vector<Word> W;
  while (!need.empty()) {
    const Word *best = nullptr; std::vector<std::pair<int,int>> bestCov;
    for (auto &w : pool) {
      std::vector<std::pair<int,int>> cov;
      for (auto &pq : need) if (h.run(pq.first, w) != h.run(pq.second, w)) cov.push_back(pq);
      if (cov.size() > bestCov.size()) { bestCov = cov; best = &w; }
    }
    if (!best) break;
    W.push_back(*best);
    for (auto &pq : bestCov) need.erase(pq);
  }
  return W;
}

// ------------------------------------------------------------------ learner --
struct Stats {
  long mq = 0, resets = 0, symbols = 0, cacheHits = 0, cacheMisses = 0;
  long rounds = 0, rsQueries = 0, ceCount = 0, eqSuiteSize = 0, eqTestsRun = 0;
  int finalStates = 0;
  bool terminated = false, correct = false;
  long d1_cacheContra = 0, d2_rsFirstSym = 0, d3_noNewState = 0,
       d4_dupRow = 0, d5_capHit = 0, d6_dupSuffix = 0, voteDisagree = 0;
  double seconds = 0;
};

struct Config {
  bool useE_as_W = false;   // take the characterizing set to be E (the pitfall)
  int mExtra = 0;           // m = n + mExtra  -> middle = Sigma^{<=1+mExtra}
  bool perfectEq = false;   // exact equivalence against the reference machine
  bool randomWalkEq = false; int rwTests = 20000; double rwStop = 0.06;
  bool trimCE = true;
  int maxRounds = 400, maxStates = 40;
  long maxMq = 4000000;
  bool verbose = false;
};

struct Learner {
  Oracle &orc; const Mealy &ref; int K; Config cfg;
  std::vector<Word> S, E;
  std::map<Word, std::vector<OutWord>> row;
  Mealy H;
  Stats st;
  std::mt19937_64 rng{777};

  Learner(Oracle &o, const Mealy &r, Config c) : orc(o), ref(r), K(r.k), cfg(c) {
    S.push_back({});
    for (int a = 0; a < K; a++) E.push_back(Word{a});
  }

  void fillRow(const Word &u) {
    auto &r = row[u];
    r.resize(E.size());
    for (size_t j = 0; j < E.size(); j++) {
      if (!r[j].empty()) continue;
      auto o = orc.query(cat(u, E[j]));
      r[j] = lastN(o, E[j].size());
    }
  }
  std::string key(const Word &u) {
    auto &r = row[u]; std::string s;
    for (auto &ow : r) { for (int x : ow) { s += (char)('0' + x); } s += '|'; }
    return s;
  }
  void fillAll() {
    for (auto &s : S) { fillRow(s); for (int a = 0; a < K; a++) fillRow(cat1(s, a)); }
  }
  bool closeOnce() {
    std::set<std::string> ks; for (auto &s : S) ks.insert(key(s));
    for (auto &s : S) for (int a = 0; a < K; a++) {
      Word la = cat1(s, a);
      if (!ks.count(key(la))) { S.push_back(la); fillAll(); return true; }
    }
    return false;
  }
  void buildHyp() {
    H = Mealy(); H.k = K; H.n = (int)S.size();
    H.iname = ref.iname; H.oname = ref.oname;
    H.d.assign(H.n, std::vector<int>(K, 0)); H.o.assign(H.n, std::vector<int>(K, 0));
    H.chal.assign(H.n, std::vector<char>(K, 0));
    std::map<std::string, int> idx;
    for (int i = 0; i < H.n; i++) {
      auto k2 = key(S[i]);
      if (idx.count(k2)) { st.d4_dupRow++; }
      idx[k2] = i;
    }
    for (int i = 0; i < H.n; i++) for (int a = 0; a < K; a++) {
      H.o[i][a] = row[S[i]][a][0];
      auto it = idx.find(key(cat1(S[i], a)));
      H.d[i][a] = (it == idx.end()) ? i : it->second;
    }
    for (int i = 0; i < H.n; i++) { H.sname.push_back(wstr(S[i], ref.iname)); }
  }
  int hypState(const Word &w) const { return H.reach(0, w); }

  // ------------------------------------------------- Rivest-Schapire ----
  // Returns the suffix added to E, or nullopt if non-determinism was detected.
  std::optional<Word> rivestSchapire(const Word &ce) {
    int k = (int)ce.size();
    auto beta = [&](int i) -> OutWord {   // SUL, access-sequence prefix + real suffix
      Word pre(ce.begin(), ce.begin() + i), suf(ce.begin() + i, ce.end());
      Word q = cat(S[hypState(pre)], suf);
      st.rsQueries++;
      auto o = orc.query(q);
      return lastN(o, suf.size());
    };
    auto hOut = [&](int i) -> OutWord {   // hypothesis, free
      Word pre(ce.begin(), ce.begin() + i), suf(ce.begin() + i, ce.end());
      return H.run(hypState(pre), suf);
    };
    // P(i) := beta(i) != hOut(i).  P(0)=true (ce is a counterexample), P(k)=false.
    auto P = [&](int i) { return beta(i) != hOut(i); };
    int lo = 0, hi = k;  // invariant: P(lo)==true, P(hi)==false
    while (hi - lo > 1) { int mid = lo + (hi - lo) / 2; if (P(mid)) lo = mid; else hi = mid; }
    // structural check: under a deterministic SUL the first output symbol of
    // beta(lo) must equal the table cell T(S[q_lo], ce[lo]).
    auto b = beta(lo), h = hOut(lo);
    if (b.empty() || b[0] != h[0]) { st.d2_rsFirstSym++; return std::nullopt; }
    Word suffix(ce.begin() + lo + 1, ce.end());
    if (suffix.empty()) { st.d2_rsFirstSym++; return std::nullopt; }
    for (auto &e : E) if (e == suffix) { st.d6_dupSuffix++; return std::nullopt; }
    return suffix;
  }

  // ------------------------------------------------- equivalence oracles ----
  std::optional<Word> eqPerfect() {
    // shortest separating word between H and ref via product BFS
    std::set<std::pair<int,int>> seen; std::queue<std::pair<std::pair<int,int>, Word>> Q;
    Q.push({{0, 0}, {}}); seen.insert({0, 0});
    while (!Q.empty()) {
      auto [st2, w] = Q.front(); Q.pop();
      for (int a = 0; a < K; a++) {
        if (H.o[st2.first][a] != ref.o[st2.second][a]) return cat1(w, a);
        std::pair<int,int> ns{H.d[st2.first][a], ref.d[st2.second][a]};
        if (seen.insert(ns).second) Q.push({ns, cat1(w, a)});
      }
    }
    return std::nullopt;
  }
  std::optional<Word> eqWMethod() {
    std::vector<Word> W = cfg.useE_as_W ? E : characterizingSet(H);
    if (W.empty()) W.push_back(Word{0});
    // middle = Sigma^{<= 1+mExtra}   (transition cover folds in one Sigma layer)
    std::vector<Word> mid{Word{}};
    std::vector<Word> frontier{Word{}};
    for (int lvl = 0; lvl < 1 + cfg.mExtra; lvl++) {
      std::vector<Word> nf;
      for (auto &f : frontier) for (int a = 0; a < K; a++) { nf.push_back(cat1(f, a)); }
      for (auto &x : nf) mid.push_back(x);
      frontier = nf;
    }
    std::set<Word> suite;
    for (auto &s : S) for (auto &mw : mid) for (auto &w : W) suite.insert(cat(cat(s, mw), w));
    st.eqSuiteSize = (long)suite.size();
    for (auto &t : suite) {
      st.eqTestsRun++;
      auto so = orc.query(t);
      auto ho = H.run(0, t);
      if (so != ho) return t;
    }
    return std::nullopt;
  }
  std::optional<Word> eqRandomWalk() {
    std::uniform_int_distribution<int> ua(0, K - 1);
    std::uniform_real_distribution<double> ur(0, 1);
    for (int t = 0; t < cfg.rwTests; t++) {
      Word w; w.push_back(ua(rng));
      while (ur(rng) > cfg.rwStop && w.size() < 60) w.push_back(ua(rng));
      st.eqTestsRun++;
      auto so = orc.query(w); auto ho = H.run(0, w);
      if (so != ho) return w;
    }
    return std::nullopt;
  }
  std::optional<Word> equivalence() {
    if (cfg.perfectEq) return eqPerfect();
    if (cfg.randomWalkEq) return eqRandomWalk();
    return eqWMethod();
  }

  Stats run() {
    auto t0 = std::chrono::steady_clock::now();
    fillAll();
    while (true) {
      while (closeOnce()) { if ((int)S.size() > cfg.maxStates) break; }
      // invariant: rows of S pairwise distinct
      { std::set<std::string> ks; for (auto &s : S) if (!ks.insert(key(s)).second) st.d4_dupRow++; }
      buildHyp();
      if ((int)S.size() > cfg.maxStates || st.rounds > cfg.maxRounds || orc.mq > cfg.maxMq) {
        st.d5_capHit++; break;
      }
      st.rounds++;
      if (cfg.verbose) std::printf("    round %2ld |S|=%2zu |E|=%2zu mq=%ld\n", st.rounds, S.size(), E.size(), orc.mq);
      auto ce = equivalence();
      if (!ce) { st.terminated = true; break; }
      st.ceCount++;
      Word c = *ce;
      if (cfg.trimCE) {
        auto so = orc.query(c); auto ho = H.run(0, c);
        size_t j = 0; while (j < c.size() && so[j] == ho[j]) j++;
        if (j < c.size()) c = Word(c.begin(), c.begin() + j + 1);
      }
      size_t before = S.size();
      auto suf = rivestSchapire(c);
      if (!suf) break;                      // non-determinism detected
      E.push_back(*suf);
      fillAll();
      while (closeOnce()) { if ((int)S.size() > cfg.maxStates) break; }
      if (S.size() == before) { st.d3_noNewState++; break; }
      buildHyp();
    }
    auto t1 = std::chrono::steady_clock::now();
    st.seconds = std::chrono::duration<double>(t1 - t0).count();
    st.mq = orc.mq; st.resets = orc.sul.resets; st.symbols = orc.sul.steps;
    st.cacheHits = orc.cache.hits; st.cacheMisses = orc.cache.misses;
    st.d1_cacheContra = orc.cache.contradictions + orc.auditContradictions;
    st.voteDisagree = orc.voteDisagreements;
    st.finalStates = (int)S.size();
    buildHyp();
    st.correct = st.terminated && !eqPerfect().has_value();
    return st;
  }
};

static void report(const std::string &tag, const Stats &s, size_t esz) {
  std::printf("%-34s states=%2d E=%2zu rounds=%2ld CE=%2ld | mq=%6ld resets=%6ld symbols=%7ld"
              " | hit%%=%5.1f | rsQ=%3ld suite=%6ld | %s%s\n",
              tag.c_str(), s.finalStates, esz, s.rounds, s.ceCount, s.mq, s.resets, s.symbols,
              100.0 * s.cacheHits / std::max(1L, s.cacheHits + s.cacheMisses), s.rsQueries,
              s.eqSuiteSize, s.terminated ? "terminated" : "STOPPED",
              s.correct ? " CORRECT" : " WRONG");
  if (s.d1_cacheContra || s.d2_rsFirstSym || s.d3_noNewState || s.d4_dupRow || s.d5_capHit || s.d6_dupSuffix || s.voteDisagree)
    std::printf("%34s detectors: D1cache=%ld D2rsFirstSym=%ld D3noNewState=%ld D4dupRow=%ld D5cap=%ld D6dupSuffix=%ld voteDisagree=%ld\n",
                "", s.d1_cacheContra, s.d2_rsFirstSym, s.d3_noNewState, s.d4_dupRow, s.d5_capHit, s.d6_dupSuffix, s.voteDisagree);
}

// ---------------------------------------------- standalone ND witness hunter --
// No learner, no observation table: just replay words and look for two runs of
// the SAME word with different outputs.  This is the tool that exonerates or
// convicts the mapper, because it shares nothing with the learner.
struct Hunt { bool found = false; Word w; int repsToDiverge = 0; long resets = 0; };

static Hunt huntWitness(const std::function<std::unique_ptr<SUL>()> &mk,
                        const std::vector<int> &alpha, int maxLen, int trials,
                        int maxReps, uint64_t seed) {
  std::mt19937_64 rng(seed);
  Hunt best;
  auto sul = mk();
  for (int t = 0; t < trials; t++) {
    int len = 1 + (int)(rng() % maxLen);
    Word w; for (int i = 0; i < len; i++) w.push_back(alpha[rng() % alpha.size()]);
    OutWord first;
    for (int r = 0; r < maxReps; r++) {
      sul->reset(); OutWord o;
      for (int a : w) o.push_back(sul->step(a));
      if (r == 0) first = o;
      else if (o != first) {
        if (!best.found || w.size() < best.w.size()) { best.found = true; best.w = w; best.repsToDiverge = r + 1; }
        break;
      }
    }
    if (best.found && best.w.size() <= 2) break;
  }
  best.resets = sul->resets;
  return best;
}

// ddmin over the input alphabet: smallest subset of Sigma that still exhibits ND
static std::vector<int> minimizeAlphabet(const std::function<std::unique_ptr<SUL>()> &mk,
                                         std::vector<int> alpha, int maxLen, int trials,
                                         int maxReps, uint64_t seed) {
  bool changed = true;
  while (changed) {
    changed = false;
    for (size_t i = 0; i < alpha.size(); i++) {
      std::vector<int> cand = alpha; cand.erase(cand.begin() + i);
      if (cand.empty()) continue;
      if (huntWitness(mk, cand, maxLen, trials, maxReps, seed + 31 * i).found) { alpha = cand; changed = true; break; }
    }
  }
  return alpha;
}

int main(int argc, char **argv) {
  Mealy ref = tcpServer();
  std::printf("reference machine: %d states (%d distinguishable), |Sigma|=%d\n",
              ref.n, minimalSize(ref), ref.k);
  {
    Mealy tmp = ref;
    auto W = characterizingSet(ref);
    std::printf("characterizing set of the reference machine: |W|=%zu  max|w|=%zu  W={",
                W.size(), std::max_element(W.begin(), W.end(), [](auto &a, auto &b){return a.size()<b.size();})->size());
    for (size_t i = 0; i < W.size(); i++) std::printf("%s%s", i ? ", " : "", wstr(W[i], ref.iname).c_str());
    std::printf("}\n\n");
  }

  auto runOne = [&](const std::string &tag, Config cfg, SUL &sul, int repeats, double audit) {
    Oracle orc(sul, ref.k, ref.iname);
    orc.repeats = repeats; orc.auditRate = audit;
    Learner L(orc, ref, cfg);
    auto s = L.run();
    report(tag, s, L.E.size());
    for (auto &c : orc.cache.contraLog) std::printf("%34s  witness: %s\n", "", c.c_str());
    return s;
  };

  std::printf("== deterministic SUL ==\n");
  { Config c; c.perfectEq = true;  RefSUL s(ref); runOne("perfect EQ oracle", c, s, 1, 0); }
  { Config c; c.mExtra = 0; c.useE_as_W = true;  RefSUL s(ref); runOne("W-method m=n, W:=E", c, s, 1, 0); }
  { Config c; c.mExtra = 1; c.useE_as_W = true;  RefSUL s(ref); runOne("W-method m=n+1, W:=E", c, s, 1, 0); }
  { Config c; c.mExtra = 2; c.useE_as_W = true;  RefSUL s(ref); runOne("W-method m=n+2, W:=E", c, s, 1, 0); }
  { Config c; c.mExtra = 0; RefSUL s(ref); runOne("W-method m=n, computed W", c, s, 1, 0); }
  { Config c; c.mExtra = 1; RefSUL s(ref); runOne("W-method m=n+1, computed W", c, s, 1, 0); }
  { Config c; c.mExtra = 1; c.trimCE = false; RefSUL s(ref); runOne("  ... without CE trimming", c, s, 1, 0); }
  { Config c; c.randomWalkEq = true; c.rwTests = 2000;  RefSUL s(ref); runOne("random walk 2000/p=.06", c, s, 1, 0); }
  { Config c; c.randomWalkEq = true; c.rwTests = 20000; RefSUL s(ref); runOne("random walk 20000/p=.06", c, s, 1, 0); }

  std::printf("\n== non-deterministic SUL: challengeack_limit token bucket ==\n");
  for (long per : {2000L, 500L, 100L}) {
    std::string t = "limit=10 period=" + std::to_string(per);
    Config c; c.mExtra = 1;
    ChallengeSUL s(ref, 10, per);
    auto r = runOne(t + " cache", c, s, 1, 0.0);
    std::printf("%34s   challenge ACKs granted=%ld suppressed=%ld\n", "", s.granted, s.suppressed);
    (void)r;
  }
  for (long per : {2000L, 500L, 100L}) {
    std::string t = "limit=10 period=" + std::to_string(per);
    Config c; c.mExtra = 1;
    ChallengeSUL s(ref, 10, per);
    runOne(t + " audit=1.0", c, s, 1, 1.0);
    std::printf("%34s   granted=%ld suppressed=%ld\n", "", s.granted, s.suppressed);
  }
  for (int rep : {3, 5}) {
    Config c; c.mExtra = 1;
    ChallengeSUL s(ref, 10, 500);
    runOne("limit=10 period=500 vote" + std::to_string(rep), c, s, rep, 0.0);
    std::printf("%34s   granted=%ld suppressed=%ld\n", "", s.granted, s.suppressed);
  }
  { // the proof-by-toggle: raise the sysctl, non-determinism vanishes
    Config c; c.mExtra = 1;
    ChallengeSUL s(ref, 1000000, 500);
    runOne("limit=1e6 (sysctl raised) audit=1.0", c, s, 1, 1.0);
    std::printf("%34s   granted=%ld suppressed=%ld\n", "", s.granted, s.suppressed);
  }

  std::printf("\n== cache bypass: which structural detectors actually fire? ==\n");
  for (long per : {2000L, 500L}) {
    Config c; c.mExtra = 1;
    ChallengeSUL s(ref, 10, per);
    Oracle orc(s, ref.k, ref.iname); orc.bypass = true;
    Learner L(orc, ref, c); auto r = L.run();
    report("no-cache limit=10 period=" + std::to_string(per), r, L.E.size());
  }

  std::printf("\n== controls: is it the SUL or is it my mapper? ==\n");
  { Config c; c.mExtra = 1; DetBugSUL s(ref); runOne("deterministic mapper bug", c, s, 1, 1.0); }
  { Config c; c.mExtra = 1; FlakySUL s(ref, 0.02, 9); runOne("flaky mapper p=0.02 vote1", c, s, 1, 1.0);
    std::printf("%34s   outputs lost=%ld\n", "", s.lost); }
  { Config c; c.mExtra = 1; FlakySUL s(ref, 0.02, 9); runOne("flaky mapper p=0.02 vote5", c, s, 5, 0.0);
    std::printf("%34s   outputs lost=%ld\n", "", s.lost); }
  { Config c; c.mExtra = 1; FlakySUL s(ref, 0.10, 9); runOne("flaky mapper p=0.10 vote5", c, s, 5, 0.0);
    std::printf("%34s   outputs lost=%ld\n", "", s.lost); }
  { Config c; c.mExtra = 1; FlakySUL s(ref, 0.10, 9); runOne("flaky mapper p=0.10 vote9", c, s, 9, 0.0);
    std::printf("%34s   outputs lost=%ld\n", "", s.lost); }

  std::printf("\n== witness hunt (no learner, no table) ==\n");
  std::vector<int> full{0,1,2,3,4,5};
  for (int lim : {1, 2, 5, 10, 20}) {
    auto mk = [&]() -> std::unique_ptr<SUL> { return std::make_unique<ChallengeSUL>(ref, lim, 1000000000L); };
    auto h = huntWitness(mk, full, 6, 400, lim + 40, 4242);
    std::printf("token bucket limit=%-3d  witness=%-22s reps to first divergence=%d (limit+1=%d) %s\n",
                lim, h.found ? wstr(h.w, ref.iname).c_str() : "none", h.repsToDiverge, lim + 1,
                h.repsToDiverge == lim + 1 ? "MATCH" : "no");
  }
  {
    auto mk = [&]() -> std::unique_ptr<SUL> { return std::make_unique<ChallengeSUL>(ref, 10, 1000000000L); };
    auto a = minimizeAlphabet(mk, full, 6, 400, 60, 4242);
    std::printf("ddmin over Sigma (token bucket): {");
    for (size_t i = 0; i < a.size(); i++) std::printf("%s%s", i ? "," : "", ref.iname[a[i]].c_str());
    std::printf("}\n");
    auto h = huntWitness(mk, a, 6, 2000, 60, 99);
    std::printf("   shortest witness over that Sigma: %s (reps=%d)\n",
                h.found ? wstr(h.w, ref.iname).c_str() : "none", h.repsToDiverge);
  }
  for (double p : {0.02, 0.10}) {
    auto mk = [&]() -> std::unique_ptr<SUL> { return std::make_unique<FlakySUL>(ref, p, 5); };
    std::vector<int> reps;
    for (int t = 0; t < 12; t++) { auto h = huntWitness(mk, full, 6, 200, 400, 1000 + t); reps.push_back(h.repsToDiverge); }
    std::printf("flaky mapper p=%.2f    reps to first divergence over 12 hunts:", p);
    for (int r : reps) std::printf(" %d", r);
    std::printf("   (no fixed value => not a counter)\n");
    auto a = minimizeAlphabet(mk, full, 6, 200, 400, 77);
    std::printf("   ddmin over Sigma: {");
    for (size_t i = 0; i < a.size(); i++) std::printf("%s%s", i ? "," : "", ref.iname[a[i]].c_str());
    std::printf("}\n");
  }

  std::printf("\n== saturation: challenge ACKs granted per epoch vs sysctl value ==\n");
  for (int lim : {1, 5, 10, 100}) {
    ChallengeSUL s(ref, lim, 100000);  // one epoch = 100000 steps, we use far fewer
    // drive to ESTAB then fire 200 challenge triggers inside one epoch
    s.reset(); s.step(SYN); s.step(ACK);
    for (int i = 0; i < 200; i++) s.step(SYN);
    std::printf("limit=%-4d  triggers=200  granted=%-4ld suppressed=%-4ld  granted==limit? %s\n",
                lim, s.granted, s.suppressed, s.granted == lim ? "YES" : "no");
  }
  return 0;
}
