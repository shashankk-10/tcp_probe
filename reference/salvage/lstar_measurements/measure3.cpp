// Equivalence-oracle comparison: W (m=n+k), Wp (m=n+k), random walk.
// Plus the project-shaped family: TCP-ish server Mealy CROSSED with a
// challenge-ACK counter 0..L (the per-connection limiter as extra states).
// build: clang++ -std=c++20 -O2 -o measure2 measure2.cpp
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <string>
#include <vector>

using Word = std::vector<int>;
using OutWord = std::vector<int>;

struct Mealy {
  int n = 0, k = 0, nout = 0;
  std::vector<std::vector<int>> d, o;
  std::vector<std::string> iname;
  OutWord run(int s, const Word &w) const { OutWord r; for (int a : w) { r.push_back(o[s][a]); s = d[s][a]; } return r; }
  int reach(int s, const Word &w) const { for (int a : w) s = d[s][a]; return s; }
};
static int minimalSize(const Mealy &m) {
  std::vector<int> cls(m.n);
  { std::map<std::vector<int>, int> sig; for (int s = 0; s < m.n; s++) cls[s] = sig.emplace(m.o[s], (int)sig.size()).first->second; }
  while (true) { std::map<std::vector<int>, int> sig; std::vector<int> nc(m.n);
    for (int s = 0; s < m.n; s++) { std::vector<int> key{cls[s]};
      for (int a = 0; a < m.k; a++) key.push_back(cls[m.d[s][a]]);
      nc[s] = sig.emplace(key, (int)sig.size()).first->second; }
    int old = *std::max_element(cls.begin(), cls.end()) + 1; cls = nc;
    if ((int)sig.size() == old) break; }
  return *std::max_element(cls.begin(), cls.end()) + 1;
}
static Mealy restrictReachable(const Mealy &m) {
  std::vector<int> id(m.n, -1); std::vector<int> ord; std::queue<int> q; q.push(0); id[0] = 0; ord.push_back(0);
  while (!q.empty()) { int s = q.front(); q.pop();
    for (int a = 0; a < m.k; a++) { int t = m.d[s][a]; if (id[t] < 0) { id[t] = (int)ord.size(); ord.push_back(t); q.push(t); } } }
  Mealy r; r.k = m.k; r.nout = m.nout; r.iname = m.iname; r.n = (int)ord.size();
  r.d.assign(r.n, std::vector<int>(r.k)); r.o.assign(r.n, std::vector<int>(r.k));
  for (int i = 0; i < r.n; i++) for (int a = 0; a < r.k; a++) { r.d[i][a] = id[m.d[ord[i]][a]]; r.o[i][a] = m.o[ord[i]][a]; }
  return r;
}

static const int SYN = 0, ACK = 1, FIN = 2, RST = 3, DATA = 4, CLOSE = 5;
static const int O_SILENT = 0, O_SYNACK = 1, O_ACK = 2, O_RST = 3, O_FINACK = 4;

// base TCP-ish server Mealy, same shape as reference/salvage/lstar.cpp
struct Base { Mealy m; std::vector<std::vector<char>> chal; };
static Base tcpBase() {
  Base b; Mealy &m = b.m; m.k = 6; m.nout = 5; m.n = 10;
  m.iname = {"SYN","ACK","FIN","RST","DATA","close()"};
  m.d.assign(10, std::vector<int>(6, 0)); m.o.assign(10, std::vector<int>(6, 0));
  b.chal.assign(10, std::vector<char>(6, 0));
  auto T = [&](int s,int a,int ns,int out,bool c=false){ m.d[s][a]=ns; m.o[s][a]=out; b.chal[s][a]=c; };
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
// CORRECT model of tcp_is_ack_ratelimited: the counter lives in the tcpcb, so it
// is per-connection and starts at 0 on every reset. Within one query (which is
// far shorter than the 1000 ms window) it is a pure monotone counter 0..L.
// State = (base, count). count saturates at L; at count==L the challenge output
// is suppressed to silence.
static Mealy tcpTimesCounter(const Base &b, int L) {
  Mealy m; m.k = b.m.k; m.nout = b.m.nout; m.iname = b.m.iname;
  int N = b.m.n, C = L + 1; m.n = N * C;
  m.d.assign(m.n, std::vector<int>(m.k)); m.o.assign(m.n, std::vector<int>(m.k));
  auto idx = [&](int s, int c) { return s * C + c; };
  for (int s = 0; s < N; s++) for (int c = 0; c < C; c++) for (int a = 0; a < m.k; a++) {
    int out = b.m.o[s][a], nc = c;
    if (b.chal[s][a]) { if (c < L) { nc = c + 1; } else { out = O_SILENT; } }
    m.d[idx(s,c)][a] = idx(b.m.d[s][a], nc);
    m.o[idx(s,c)][a] = out;
  }
  Mealy r = restrictReachable(m);
  return r;
}

// ---- oracle ----------------------------------------------------------------
struct Oracle {
  const Mealy &m; long mq = 0, resets = 0, symbols = 0, hits = 0, misses = 0, hitSymbols = 0, prefixAudits = 0;
  bool useCache = true;
  struct Node { std::vector<int> child, out; explicit Node(int k) : child(k,-1), out(k,-1) {} };
  std::vector<Node> nodes; int k;
  explicit Oracle(const Mealy &mm) : m(mm), k(mm.k) { nodes.emplace_back(k); }
  std::optional<OutWord> lookup(const Word &w) const { int u = 0; OutWord r;
    for (int a : w) { if (nodes[u].child[a] < 0) return std::nullopt; r.push_back(nodes[u].out[a]); u = nodes[u].child[a]; } return r; }
  void insert(const Word &w, const OutWord &o) { int u = 0;
    for (size_t i = 0; i < w.size(); i++) { int a = w[i];
      if (nodes[u].child[a] < 0) { nodes[u].child[a] = (int)nodes.size(); nodes.emplace_back(k); nodes[u].out[a] = o[i]; }
      else prefixAudits++;
      u = nodes[u].child[a]; } }
  OutWord query(const Word &w) { mq++;
    if (useCache) { auto h = lookup(w); if (h) { hits++; hitSymbols += (long)w.size(); return *h; } misses++; }
    resets++; symbols += (long)w.size(); auto o = m.run(0, w); if (useCache) insert(w, o); return o; }
};
static Word cat(const Word &a, const Word &b) { Word r = a; r.insert(r.end(), b.begin(), b.end()); return r; }
static Word cat1(const Word &a, int s) { Word r = a; r.push_back(s); return r; }
static OutWord lastN(const OutWord &o, size_t n) { return OutWord(o.end() - n, o.end()); }

// ---- W and per-state identification sets Wi --------------------------------
struct CharSet { std::vector<Word> W; std::vector<std::vector<int>> Wi; };  // Wi[s] = indices into W
static CharSet characterizing(const Mealy &h) {
  int n = h.n; std::set<Word> cand;
  std::map<std::pair<int,int>, Word> sep;
  for (int p = 0; p < n; p++) for (int q = p+1; q < n; q++) {
    std::set<std::pair<int,int>> seen; std::queue<std::pair<std::pair<int,int>,Word>> Q;
    Q.push({{p,q},{}}); seen.insert({p,q}); bool found = false;
    while (!Q.empty() && !found) { auto [st,w] = Q.front(); Q.pop();
      for (int a = 0; a < h.k; a++) {
        if (h.o[st.first][a] != h.o[st.second][a]) { cand.insert(cat1(w,a)); sep[{p,q}] = cat1(w,a); found = true; break; }
        std::pair<int,int> ns{h.d[st.first][a], h.d[st.second][a]};
        if (ns.first > ns.second) std::swap(ns.first, ns.second);
        if (seen.insert(ns).second) Q.push({ns, cat1(w,a)}); } } }
  std::vector<Word> pool(cand.begin(), cand.end());
  std::set<std::pair<int,int>> need;
  for (int p = 0; p < n; p++) for (int q = p+1; q < n; q++) need.insert({p,q});
  CharSet cs;
  while (!need.empty()) { const Word *best = nullptr; std::vector<std::pair<int,int>> bc;
    for (auto &w : pool) { std::vector<std::pair<int,int>> cov;
      for (auto &pq : need) if (h.run(pq.first,w) != h.run(pq.second,w)) cov.push_back(pq);
      if (cov.size() > bc.size()) { bc = cov; best = &w; } }
    if (!best) break; cs.W.push_back(*best); for (auto &pq : bc) need.erase(pq); }
  // Wi[s]: minimal subset of W separating s from every other state
  cs.Wi.assign(n, {});
  for (int s = 0; s < n; s++) {
    std::set<int> rest; for (int t = 0; t < n; t++) if (t != s) rest.insert(t);
    while (!rest.empty()) {
      int bi = -1; size_t bcov = 0;
      for (size_t i = 0; i < cs.W.size(); i++) { size_t c = 0;
        for (int t : rest) if (h.run(s, cs.W[i]) != h.run(t, cs.W[i])) c++;
        if (c > bcov) { bcov = c; bi = (int)i; } }
      if (bi < 0) break;
      cs.Wi[s].push_back(bi);
      for (auto it = rest.begin(); it != rest.end();) {
        if (h.run(s, cs.W[bi]) != h.run(*it, cs.W[bi])) it = rest.erase(it); else ++it; }
    }
  }
  return cs;
}

enum class EQMode { Perfect, W, Wp, RandomWalk };

struct Stats {
  long mq=0, resets=0, symbols=0, hits=0, misses=0, hitSymbols=0, prefixAudits=0;
  long rounds=0, ceCount=0, rsBin=0, fillQ=0, eqQ=0, suite=0, ceMax=0;
  int states=0, esize=0; bool correct=false;
};

struct Learner {
  Oracle &orc; const Mealy &ref; int K; EQMode eq; int mExtra;
  int rwTests; double rwStop;
  std::vector<Word> S, E; std::map<Word, std::vector<OutWord>> row; Mealy H; Stats st;
  std::mt19937_64 rng{0xC0FFEE};
  Learner(Oracle &o, const Mealy &r, EQMode e, int mx, int rt = 20000, double rs = 0.06)
      : orc(o), ref(r), K(r.k), eq(e), mExtra(mx), rwTests(rt), rwStop(rs) {
    S.push_back({}); for (int a = 0; a < K; a++) E.push_back(Word{a});
  }
  void fillRow(const Word &u) { auto &r = row[u]; r.resize(E.size());
    for (size_t j = 0; j < E.size(); j++) { if (!r[j].empty()) continue;
      long b = orc.mq; auto o = orc.query(cat(u, E[j])); st.fillQ += orc.mq - b; r[j] = lastN(o, E[j].size()); } }
  std::string key(const Word &u) { auto &r = row[u]; std::string s;
    for (auto &ow : r) { for (int x : ow) { s += std::to_string(x); s += ','; } s += '|'; } return s; }
  void fillAll() { for (auto &s : S) { fillRow(s); for (int a = 0; a < K; a++) fillRow(cat1(s, a)); } }
  bool closeOnce() { std::set<std::string> ks; for (auto &s : S) ks.insert(key(s));
    for (size_t i = 0; i < S.size(); i++) for (int a = 0; a < K; a++) { Word la = cat1(S[i], a);
      if (!ks.count(key(la))) { S.push_back(la); fillAll(); return true; } } return false; }
  void buildHyp() { H = Mealy(); H.k = K; H.n = (int)S.size(); H.nout = ref.nout; H.iname = ref.iname;
    H.d.assign(H.n, std::vector<int>(K,0)); H.o.assign(H.n, std::vector<int>(K,0));
    std::map<std::string,int> idx;
    for (int i = 0; i < H.n; i++) { auto k2 = key(S[i]); assert(!idx.count(k2)); idx[k2] = i; }
    for (int i = 0; i < H.n; i++) for (int a = 0; a < K; a++) { H.o[i][a] = row[S[i]][a][0];
      auto it = idx.find(key(cat1(S[i],a))); assert(it != idx.end()); H.d[i][a] = it->second; } }
  int hypState(const Word &w) const { return H.reach(0, w); }
  Word rivestSchapire(const Word &ce) {
    int k = (int)ce.size();
    auto beta = [&](int i) -> OutWord { Word pre(ce.begin(), ce.begin()+i), suf(ce.begin()+i, ce.end());
      Word q = cat(S[hypState(pre)], suf); long b = orc.mq; auto o = orc.query(q); st.rsBin += orc.mq - b; return lastN(o, suf.size()); };
    auto hOut = [&](int i) -> OutWord { Word pre(ce.begin(), ce.begin()+i), suf(ce.begin()+i, ce.end());
      return H.run(hypState(pre), suf); };
    int lo = 0, hi = k;
    while (hi - lo > 1) { int mid = lo + (hi-lo)/2; if (beta(mid) != hOut(mid)) lo = mid; else hi = mid; }
    Word suffix(ce.begin()+lo+1, ce.end());
    if (suffix.empty()) { std::fprintf(stderr, "ND: empty RS suffix\n"); exit(2); }
    for (auto &e : E) if (e == suffix) { std::fprintf(stderr, "ND: duplicate RS suffix\n"); exit(2); }
    return suffix;
  }
  std::optional<Word> eqPerfect() { std::set<std::pair<int,int>> seen; std::queue<std::pair<std::pair<int,int>,Word>> Q;
    Q.push({{0,0},{}}); seen.insert({0,0});
    while (!Q.empty()) { auto [s2,w] = Q.front(); Q.pop();
      for (int a = 0; a < K; a++) { if (H.o[s2.first][a] != ref.o[s2.second][a]) return cat1(w,a);
        std::pair<int,int> ns{H.d[s2.first][a], ref.d[s2.second][a]};
        if (seen.insert(ns).second) Q.push({ns, cat1(w,a)}); } } return std::nullopt; }
  std::vector<Word> middle() const { std::vector<Word> mid{Word{}}, fr{Word{}};
    for (int l = 0; l < mExtra; l++) { std::vector<Word> nf;
      for (auto &f : fr) for (int a = 0; a < K; a++) nf.push_back(cat1(f,a));
      for (auto &x : nf) mid.push_back(x); fr = nf; } return mid; }
  std::optional<Word> eqW() { auto cs = characterizing(H); if (cs.W.empty()) cs.W.push_back(Word{0});
    auto mid = middle(); std::set<Word> suite;
    // transition cover = S . Sigma  (fold one Sigma layer in, as W-method requires)
    std::vector<Word> cover = S; for (auto &s : S) for (int a = 0; a < K; a++) cover.push_back(cat1(s,a));
    for (auto &c : cover) for (auto &mw : mid) for (auto &w : cs.W) suite.insert(cat(cat(c,mw),w));
    st.suite = (long)suite.size();
    for (auto &t : suite) { long b = orc.mq; auto so = orc.query(t); st.eqQ += orc.mq - b;
      if (so != H.run(0,t)) return t; } return std::nullopt; }
  std::optional<Word> eqWp() { auto cs = characterizing(H); if (cs.W.empty()) { cs.W.push_back(Word{0}); cs.Wi.assign(H.n, {0}); }
    auto mid = middle(); std::set<Word> suite;
    for (auto &s : S) for (auto &w : cs.W) suite.insert(cat(s,w));            // phase 1: S . W
    std::set<Word> Sset(S.begin(), S.end());
    std::vector<Word> cover; for (auto &s : S) for (int a = 0; a < K; a++) cover.push_back(cat1(s,a));
    for (auto &c : cover) for (auto &mw : mid) { Word cm = cat(c, mw);
      if (Sset.count(cm)) continue; int q = hypState(cm);
      for (int wi : cs.Wi[q]) suite.insert(cat(cm, cs.W[wi])); }                // phase 2: Wi only
    st.suite = (long)suite.size();
    for (auto &t : suite) { long b = orc.mq; auto so = orc.query(t); st.eqQ += orc.mq - b;
      if (so != H.run(0,t)) return t; } return std::nullopt; }
  std::vector<double> rwW;   // per-symbol weight; empty => uniform
  std::optional<Word> eqRW() { std::uniform_int_distribution<int> ua(0, K-1); std::uniform_real_distribution<double> ur(0,1);
    std::discrete_distribution<int> ub(rwW.begin(), rwW.end());
    auto pick = [&]() { return rwW.empty() ? ua(rng) : ub(rng); };
    st.suite = rwTests;
    for (int t = 0; t < rwTests; t++) { Word w; w.push_back(pick());
      while (ur(rng) > rwStop && w.size() < 200) w.push_back(pick());
      long b = orc.mq; auto so = orc.query(w); st.eqQ += orc.mq - b;
      if (so != H.run(0,w)) return w; } return std::nullopt; }
  std::optional<Word> equivalence() { switch (eq) { case EQMode::Perfect: return eqPerfect();
    case EQMode::W: return eqW(); case EQMode::Wp: return eqWp(); default: return eqRW(); } }
  Stats run() { fillAll(); while (closeOnce()) {} buildHyp();
    for (int g = 0; g < 20000; g++) { st.rounds++; auto ce = equivalence(); if (!ce) break;
      st.ceCount++; st.ceMax = std::max(st.ceMax, (long)ce->size());
      size_t before = S.size(); E.push_back(rivestSchapire(*ce));
      fillAll(); while (closeOnce()) {} assert(S.size() > before); buildHyp(); }
    st.mq = orc.mq; st.resets = orc.resets; st.symbols = orc.symbols; st.hits = orc.hits;
    st.misses = orc.misses; st.hitSymbols = orc.hitSymbols; st.prefixAudits = orc.prefixAudits;
    st.states = (int)S.size(); st.esize = (int)E.size(); st.correct = !eqPerfect().has_value(); return st; }
};

static void hdr() { std::printf("%-26s %-5s %-12s | %8s %8s %8s %9s | %5s %4s %4s %6s | %8s %8s %8s | %6s %s\n",
    "machine","n","EQ oracle","mq","resets","misses","symbols","|S|","|E|","rnd","maxCE","fillQ","rsBin","eqQ","hit%","ok"); }
static void one(const char *tag, const Mealy &ref, EQMode e, int mx, const char *en, bool cacheOn,
                int rt = 20000, double rs = 0.06, std::vector<double> wts = {}) {
  Oracle orc(ref); orc.useCache = cacheOn; Learner L(orc, ref, e, mx, rt, rs); L.rwW = wts; auto s = L.run();
  std::printf("%-26s %-5d %-12s | %8ld %8ld %8ld %9ld | %5d %4d %4ld %6ld | %8ld %8ld %8ld | %5.1f %s\n",
      tag, ref.n, en, s.mq, s.resets, s.misses, s.symbols, s.states, s.esize, s.rounds, s.ceMax,
      s.fillQ, s.rsBin, s.eqQ, 100.0*s.hits/std::max(1L,s.hits+s.misses), s.correct ? "CORRECT" : "WRONG");
  std::printf("%26s   cache: exactHits=%ld (%ld symbols served with NO fresh observation) prefixAudits=%ld trieEdges~%zu\n",
      "", s.hits, s.hitSymbols, s.prefixAudits, orc.nodes.size() - 1);
}

int main() {
  Base b = tcpBase();
  std::printf("TCP base: n=%d distinguishable=%d |Sigma|=%d\n\n", b.m.n, minimalSize(b.m), b.m.k);

  std::printf("=== random-walk sweep vs the hidden challenge-counter chain (L=10, 80 states) ===\n"); hdr();
  Mealy p10 = tcpTimesCounter(b, 10);
  for (double ps : {0.20, 0.06, 0.02}) for (int nt : {2000, 20000, 200000}) {
    char en[32]; std::snprintf(en, sizeof en, "rw %dk p=%.2f", nt/1000, ps);
    one("tcp x counter L=10", p10, EQMode::RandomWalk, 0, en, true, nt, ps);
  }
  std::printf("\n=== SYN-biased random walk (weight SYN 4x, others 1x) L=10 ===\n"); hdr();
  for (double ps : {0.06, 0.02}) for (int nt : {2000, 20000}) {
    char en[32]; std::snprintf(en, sizeof en, "bias %dk p=%.2f", nt/1000, ps);
    one("tcp x counter L=10", p10, EQMode::RandomWalk, 0, en, true, nt, ps, {4,1,1,1,1,1});
  }
  std::printf("\n=== W vs Wp suite growth: m = n+k for k=1..3, L=2 (24 states) ===\n"); hdr();
  Mealy p2 = tcpTimesCounter(b, 2);
  for (int k = 1; k <= 3; k++) { char en[32];
    std::snprintf(en, sizeof en, "W m=n+%d", k);  one("tcp x counter L=2", p2, EQMode::W, k, en, true);
    std::snprintf(en, sizeof en, "Wp m=n+%d", k); one("tcp x counter L=2", p2, EQMode::Wp, k, en, true); }
  return 0;
}
