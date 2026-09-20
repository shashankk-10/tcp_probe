// Measurement harness: Mealy L* with Rivest-Schapire vs Maler-Pnueli CE handling,
// on random minimal Mealy machines of n = 10,15,25,40.
// Rebuilt from scratch (not the salvage file) with the salvage's bugs fixed:
//   * row key uses a delimited int encoding, not '0'+x
//   * buildHyp asserts closedness instead of silently self-looping
//   * RS binary-search queries counted separately from the verification query
//   * W-method middle = Sigma^{<=k} for m = n+k, W computed from H
// build: clang++ -std=c++20 -O2 -o measure measure.cpp
#include <algorithm>
#include <cassert>
#include <chrono>
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
  OutWord run(int s, const Word &w) const {
    OutWord r; r.reserve(w.size());
    for (int a : w) { r.push_back(o[s][a]); s = d[s][a]; }
    return r;
  }
  int reach(int s, const Word &w) const { for (int a : w) s = d[s][a]; return s; }
};

// ---- minimality via Moore partition refinement (Mealy variant) --------------
static int minimalSize(const Mealy &m) {
  std::vector<int> cls(m.n);
  { std::map<std::vector<int>, int> sig;
    for (int s = 0; s < m.n; s++) cls[s] = sig.emplace(m.o[s], (int)sig.size()).first->second; }
  while (true) {
    std::map<std::vector<int>, int> sig; std::vector<int> nc(m.n);
    for (int s = 0; s < m.n; s++) {
      std::vector<int> key{cls[s]};
      for (int a = 0; a < m.k; a++) key.push_back(cls[m.d[s][a]]);
      nc[s] = sig.emplace(key, (int)sig.size()).first->second;
    }
    int old = *std::max_element(cls.begin(), cls.end()) + 1;
    cls = nc;
    if ((int)sig.size() == old) break;
  }
  return *std::max_element(cls.begin(), cls.end()) + 1;
}
static bool allReachable(const Mealy &m) {
  std::vector<char> seen(m.n, 0); std::queue<int> q; q.push(0); seen[0] = 1; int c = 1;
  while (!q.empty()) { int s = q.front(); q.pop();
    for (int a = 0; a < m.k; a++) { int t = m.d[s][a]; if (!seen[t]) { seen[t] = 1; c++; q.push(t); } } }
  return c == m.n;
}
static Mealy randomMinimalMealy(int n, int k, int nout, uint64_t seed) {
  std::mt19937_64 rng(seed);
  for (int attempt = 0; attempt < 100000; attempt++) {
    Mealy m; m.n = n; m.k = k; m.nout = nout;
    m.d.assign(n, std::vector<int>(k)); m.o.assign(n, std::vector<int>(k));
    for (int s = 0; s < n; s++) for (int a = 0; a < k; a++) {
      m.d[s][a] = (int)(rng() % n); m.o[s][a] = (int)(rng() % nout);
    }
    // bias toward reachability: a random spanning chain
    for (int s = 1; s < n; s++) { int p = (int)(rng() % s); m.d[p][rng() % k] = s; }
    if (!allReachable(m)) continue;
    if (minimalSize(m) != n) continue;
    return m;
  }
  std::fprintf(stderr, "gen failed n=%d k=%d\n", n, k); exit(1);
}

// ---- HARD families: states separable only by LONG suffixes -----------------
// mod-n counter. symbol 0 = tick, symbols 1..k-1 = no-op. Output 1 only on the
// tick that wraps.  State i and j (i!=j) are separated only by 0^(n-i) ... so
// the shortest distinguishing suffix is Theta(n) and counterexamples are long.
static Mealy counterMealy(int n, int k) {
  Mealy m; m.n = n; m.k = k; m.nout = 2;
  m.d.assign(n, std::vector<int>(k)); m.o.assign(n, std::vector<int>(k));
  for (int s = 0; s < n; s++) for (int a = 0; a < k; a++) {
    if (a == 0) { m.d[s][a] = (s + 1) % n; m.o[s][a] = (s == n - 1) ? 1 : 0; }
    else { m.d[s][a] = s; m.o[s][a] = 0; }
  }
  return m;
}
// width-w shift register over a binary-ish alphabet: state = last w inputs
// (folded to 2 classes), output = the input that entered w steps ago.
// n = 2^w states, distinguishing suffixes of length up to w.
static Mealy shiftMealy(int w, int k) {
  int n = 1 << w;
  Mealy m; m.n = n; m.k = k; m.nout = 2;
  m.d.assign(n, std::vector<int>(k)); m.o.assign(n, std::vector<int>(k));
  for (int s = 0; s < n; s++) for (int a = 0; a < k; a++) {
    int bit = a & 1;
    m.o[s][a] = (s >> (w - 1)) & 1;            // oldest bit leaves
    m.d[s][a] = ((s << 1) | bit) & (n - 1);
  }
  return m;
}

// ---- SUL + cache -----------------------------------------------------------
struct Oracle {
  const Mealy &m;
  long mq = 0, resets = 0, symbols = 0, hits = 0, misses = 0;
  bool useCache = true;
  struct Node { std::vector<int> child, out; explicit Node(int k) : child(k, -1), out(k, -1) {} };
  std::vector<Node> nodes; int k;
  long cacheEdges = 0;
  explicit Oracle(const Mealy &mm) : m(mm), k(mm.k) { nodes.emplace_back(k); }
  std::optional<OutWord> lookup(const Word &w) const {
    int u = 0; OutWord r;
    for (int a : w) { if (nodes[u].child[a] < 0) return std::nullopt; r.push_back(nodes[u].out[a]); u = nodes[u].child[a]; }
    return r;
  }
  void insert(const Word &w, const OutWord &o) {
    int u = 0;
    for (size_t i = 0; i < w.size(); i++) { int a = w[i];
      if (nodes[u].child[a] < 0) { nodes[u].child[a] = (int)nodes.size(); nodes.emplace_back(k); nodes[u].out[a] = o[i]; cacheEdges++; }
      u = nodes[u].child[a]; }
  }
  OutWord query(const Word &w) {
    mq++;
    if (useCache) { auto h = lookup(w); if (h) { hits++; return *h; } misses++; }
    resets++; symbols += (long)w.size();
    auto o = m.run(0, w);
    if (useCache) insert(w, o);
    return o;
  }
};

static Word cat(const Word &a, const Word &b) { Word r = a; r.insert(r.end(), b.begin(), b.end()); return r; }
static Word cat1(const Word &a, int s) { Word r = a; r.push_back(s); return r; }
static OutWord lastN(const OutWord &o, size_t n) { return OutWord(o.end() - n, o.end()); }

// ---- characterising set W of H ---------------------------------------------
static std::vector<Word> characterizingSet(const Mealy &h) {
  int n = h.n; std::set<Word> cand;
  for (int p = 0; p < n; p++) for (int q = p + 1; q < n; q++) {
    std::set<std::pair<int,int>> seen; std::queue<std::pair<std::pair<int,int>, Word>> Q;
    Q.push({{p,q},{}}); seen.insert({p,q}); bool found = false;
    while (!Q.empty() && !found) { auto [st, w] = Q.front(); Q.pop();
      for (int a = 0; a < h.k; a++) {
        if (h.o[st.first][a] != h.o[st.second][a]) { cand.insert(cat1(w, a)); found = true; break; }
        std::pair<int,int> ns{h.d[st.first][a], h.d[st.second][a]};
        if (ns.first > ns.second) std::swap(ns.first, ns.second);
        if (seen.insert(ns).second) Q.push({ns, cat1(w, a)});
      } } }
  std::vector<Word> pool(cand.begin(), cand.end());
  std::set<std::pair<int,int>> need;
  for (int p = 0; p < n; p++) for (int q = p + 1; q < n; q++) need.insert({p,q});
  std::vector<Word> W;
  while (!need.empty()) {
    const Word *best = nullptr; std::vector<std::pair<int,int>> bestCov;
    for (auto &w : pool) { std::vector<std::pair<int,int>> cov;
      for (auto &pq : need) if (h.run(pq.first, w) != h.run(pq.second, w)) cov.push_back(pq);
      if (cov.size() > bestCov.size()) { bestCov = cov; best = &w; } }
    if (!best) break;
    W.push_back(*best); for (auto &pq : bestCov) need.erase(pq);
  }
  return W;
}

// ---- learner ---------------------------------------------------------------
enum class CEMode { RS, MalerPnueli };
enum class EQMode { Perfect, WMethod };

struct Stats {
  long mq = 0, resets = 0, symbols = 0, hits = 0, misses = 0;
  long rounds = 0, ceCount = 0, ceTotalLen = 0, ceMaxLen = 0;
  long rsBinQueries = 0, rsVerifyQueries = 0;
  long fillQueries = 0, eqQueries = 0, eqSuiteSize = 0;
  int states = 0, esize = 0; bool correct = false;
  double seconds = 0;
};

struct Learner {
  Oracle &orc; const Mealy &ref; int K;
  CEMode ce_mode; EQMode eq_mode; int mExtra;
  std::vector<Word> S, E;
  std::map<Word, std::vector<OutWord>> row;
  Mealy H; Stats st;

  Learner(Oracle &o, const Mealy &r, CEMode c, EQMode e, int mx)
      : orc(o), ref(r), K(r.k), ce_mode(c), eq_mode(e), mExtra(mx) {
    S.push_back({});
    for (int a = 0; a < K; a++) E.push_back(Word{a});
  }
  void fillRow(const Word &u) {
    auto &r = row[u]; r.resize(E.size());
    for (size_t j = 0; j < E.size(); j++) {
      if (!r[j].empty()) continue;
      long before = orc.mq; auto o = orc.query(cat(u, E[j])); st.fillQueries += orc.mq - before;
      r[j] = lastN(o, E[j].size());
    }
  }
  std::string key(const Word &u) {
    auto &r = row[u]; std::string s;
    for (auto &ow : r) { for (int x : ow) { s += std::to_string(x); s += ','; } s += '|'; }
    return s;
  }
  void fillAll() { for (auto &s : S) { fillRow(s); for (int a = 0; a < K; a++) fillRow(cat1(s, a)); } }
  bool closeOnce() {
    std::set<std::string> ks; for (auto &s : S) ks.insert(key(s));
    for (size_t i = 0; i < S.size(); i++) for (int a = 0; a < K; a++) {
      Word la = cat1(S[i], a);
      if (!ks.count(key(la))) { S.push_back(la); fillAll(); return true; }
    }
    return false;
  }
  void buildHyp() {
    H = Mealy(); H.k = K; H.n = (int)S.size(); H.nout = ref.nout;
    H.d.assign(H.n, std::vector<int>(K, 0)); H.o.assign(H.n, std::vector<int>(K, 0));
    std::map<std::string, int> idx;
    for (int i = 0; i < H.n; i++) { auto k2 = key(S[i]); assert(!idx.count(k2) && "S rows must be pairwise distinct"); idx[k2] = i; }
    for (int i = 0; i < H.n; i++) for (int a = 0; a < K; a++) {
      H.o[i][a] = row[S[i]][a][0];
      auto it = idx.find(key(cat1(S[i], a)));
      assert(it != idx.end() && "table must be closed");
      H.d[i][a] = it->second;
    }
  }
  int hypState(const Word &w) const { return H.reach(0, w); }

  // Rivest-Schapire: returns ONE distinguishing suffix.
  Word rivestSchapire(const Word &ce) {
    int k = (int)ce.size();
    auto beta = [&](int i, bool verify) -> OutWord {
      Word pre(ce.begin(), ce.begin() + i), suf(ce.begin() + i, ce.end());
      Word q = cat(S[hypState(pre)], suf);
      long b = orc.mq; auto o = orc.query(q); long used = orc.mq - b;
      if (verify) st.rsVerifyQueries += used; else st.rsBinQueries += used;
      return lastN(o, suf.size());
    };
    auto hOut = [&](int i) -> OutWord {
      Word pre(ce.begin(), ce.begin() + i), suf(ce.begin() + i, ce.end());
      return H.run(hypState(pre), suf);
    };
    int lo = 0, hi = k;                       // invariant P(lo)=true, P(hi)=false
    while (hi - lo > 1) { int mid = lo + (hi - lo) / 2;
      if (beta(mid, false) != hOut(mid)) lo = mid; else hi = mid; }
    auto b = beta(lo, true); auto h = hOut(lo);
    if (b.empty() || b[0] != h[0]) { std::fprintf(stderr, "RS: first-symbol mismatch (ND!)\n"); exit(2); }
    Word suffix(ce.begin() + lo + 1, ce.end());
    if (suffix.empty()) { std::fprintf(stderr, "RS: empty suffix (ND!)\n"); exit(2); }
    return suffix;
  }

  std::optional<Word> eqPerfect() {
    std::set<std::pair<int,int>> seen; std::queue<std::pair<std::pair<int,int>, Word>> Q;
    Q.push({{0,0},{}}); seen.insert({0,0});
    while (!Q.empty()) { auto [s2, w] = Q.front(); Q.pop();
      for (int a = 0; a < K; a++) {
        if (H.o[s2.first][a] != ref.o[s2.second][a]) return cat1(w, a);
        std::pair<int,int> ns{H.d[s2.first][a], ref.d[s2.second][a]};
        if (seen.insert(ns).second) Q.push({ns, cat1(w, a)});
      } }
    return std::nullopt;
  }
  std::optional<Word> eqWMethod() {
    auto W = characterizingSet(H); if (W.empty()) W.push_back(Word{0});
    std::vector<Word> mid{Word{}}, frontier{Word{}};
    for (int lvl = 0; lvl < 1 + mExtra; lvl++) {
      std::vector<Word> nf;
      for (auto &f : frontier) for (int a = 0; a < K; a++) nf.push_back(cat1(f, a));
      for (auto &x : nf) mid.push_back(x);
      frontier = nf;
    }
    std::set<Word> suite;
    for (auto &s : S) for (auto &mw : mid) for (auto &w : W) suite.insert(cat(cat(s, mw), w));
    st.eqSuiteSize = (long)suite.size();
    for (auto &t : suite) { long b = orc.mq; auto so = orc.query(t); st.eqQueries += orc.mq - b;
      if (so != H.run(0, t)) return t; }
    return std::nullopt;
  }
  std::optional<Word> equivalence() { return eq_mode == EQMode::Perfect ? eqPerfect() : eqWMethod(); }

  Stats run() {
    auto t0 = std::chrono::steady_clock::now();
    fillAll(); while (closeOnce()) {}
    buildHyp();
    for (int guard = 0; guard < 5000; guard++) {
      st.rounds++;
      auto ce = equivalence();
      if (!ce) break;
      st.ceCount++; st.ceTotalLen += (long)ce->size();
      st.ceMaxLen = std::max(st.ceMaxLen, (long)ce->size());
      size_t before = S.size();
      if (ce_mode == CEMode::RS) {
        E.push_back(rivestSchapire(*ce));
      } else {  // Maler-Pnueli: add ALL suffixes of the CE
        std::set<Word> have(E.begin(), E.end());
        for (size_t i = 0; i < ce->size(); i++) {
          Word suf(ce->begin() + i, ce->end());
          if (have.insert(suf).second) E.push_back(suf);
        }
      }
      fillAll(); while (closeOnce()) {}
      assert(S.size() > before && "CE must split a pair");
      buildHyp();
    }
    auto t1 = std::chrono::steady_clock::now();
    st.seconds = std::chrono::duration<double>(t1 - t0).count();
    st.mq = orc.mq; st.resets = orc.resets; st.symbols = orc.symbols;
    st.hits = orc.hits; st.misses = orc.misses;
    st.states = (int)S.size(); st.esize = (int)E.size();
    st.correct = !eqPerfect().has_value();
    return st;
  }
};

static void hdr() {
  std::printf("%-18s %-4s %-3s %-3s %-7s %-9s | %7s %7s %7s %9s | %4s %4s %4s %6s %6s | %7s %6s %6s %7s | %s\n",
              "family", "n", "|Sg|", "|O|", "CEmode", "EQmode", "mq", "resets", "misses", "symbols",
              "|S|", "|E|", "rnd", "sumCE", "maxCE", "fillQ", "rsBin", "rsVer", "eqQ", "ok");
}
static void runFamily(const char *fam, const Mealy &ref, bool cacheOn, bool withW) {
  struct Cfg { CEMode c; EQMode e; int mx; const char *cn; const char *en; };
  std::vector<Cfg> cfgs = {
      {CEMode::RS, EQMode::Perfect, 0, "RS", "perfect"},
      {CEMode::MalerPnueli, EQMode::Perfect, 0, "MP", "perfect"},
  };
  if (withW) {
    cfgs.push_back({CEMode::RS, EQMode::WMethod, 1, "RS", "W m=n+1"});
    cfgs.push_back({CEMode::RS, EQMode::WMethod, 0, "RS", "W m=n"});
    cfgs.push_back({CEMode::MalerPnueli, EQMode::WMethod, 1, "MP", "W m=n+1"});
  }
  for (auto &cf : cfgs) {
    Oracle orc(ref); orc.useCache = cacheOn;
    Learner L(orc, ref, cf.c, cf.e, cf.mx);
    auto s = L.run();
    std::printf("%-18s %-4d %-4d %-3d %-7s %-9s | %7ld %7ld %7ld %9ld | %4d %4d %4ld %6ld %6ld | %7ld %6ld %6ld %7ld | %s\n",
                fam, ref.n, ref.k, ref.nout, cf.cn, cf.en, s.mq, s.resets, s.misses, s.symbols,
                s.states, s.esize, s.rounds, s.ceTotalLen, s.ceMaxLen,
                s.fillQueries, s.rsBinQueries, s.rsVerifyQueries, s.eqQueries,
                s.correct ? "CORRECT" : "WRONG");
  }
  std::printf("\n");
}

int main(int argc, char **argv) {
  bool cacheOn = !(argc > 1 && std::string(argv[1]) == "nocache");
  std::printf("cache=%s\n\n", cacheOn ? "ON (prefix-closed trie)" : "OFF");

  std::printf("=== A. random minimal Mealy, |O|=3 (EASY: E=Sigma already separates) ===\n");
  hdr();
  for (int n : {10, 15, 25, 40})
    for (int k : {2, 6}) {
      Mealy ref = randomMinimalMealy(n, k, 3, 0x9E3779B97F4A7C15ULL ^ (uint64_t)(n * 131 + k));
      runFamily("random|O|=3", ref, cacheOn, true);
    }

  std::printf("=== B. random minimal Mealy, |O|=2 (harder) ===\n");
  hdr();
  for (int n : {10, 15, 25, 40})
    for (int k : {2, 6}) {
      Mealy ref = randomMinimalMealy(n, k, 2, 0xD1B54A32D192ED03ULL ^ (uint64_t)(n * 977 + k));
      runFamily("random|O|=2", ref, cacheOn, true);
    }

  std::printf("=== C. mod-n counter (HARD: shortest distinguishing suffix is Theta(n)) ===\n");
  hdr();
  for (int n : {10, 15, 25, 40})
    for (int k : {2, 6}) {
      Mealy ref = counterMealy(n, k);
      assert(minimalSize(ref) == n);
      runFamily("counter", ref, cacheOn, n <= 15);
    }

  std::printf("=== D. width-w shift register (n=2^w, suffixes up to w) ===\n");
  hdr();
  for (int w : {3, 4, 5}) {
    Mealy ref = shiftMealy(w, 2);
    assert(minimalSize(ref) == ref.n);
    runFamily("shift", ref, cacheOn, true);
  }
  return 0;
}
