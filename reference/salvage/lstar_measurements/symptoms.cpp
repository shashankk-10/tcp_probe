// Which L* invariant breaks first under each class of non-determinism, and what
// the OBSERVABLE symptom is. All invariant checks are counters, never asserts,
// so the learner keeps going and we see the full failure sequence.
// build: clang++ -std=c++20 -O2 -o symptoms symptoms.cpp
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <string>
#include <vector>

using Word = std::vector<int>;
using OutWord = std::vector<int>;
static const int SYN = 0, ACK = 1, FIN = 2, RST = 3, DATA = 4, CLOSE = 5;
static const int O_SILENT = 0, O_SYNACK = 1, O_ACK = 2, O_RST = 3, O_FINACK = 4;

struct Base { int n = 10, k = 6; std::vector<std::vector<int>> d, o; std::vector<std::vector<char>> chal; };
static Base tcpBase() {
  Base b; b.d.assign(10, std::vector<int>(6,0)); b.o.assign(10, std::vector<int>(6,0)); b.chal.assign(10, std::vector<char>(6,0));
  auto T=[&](int s,int a,int ns,int out,bool c=false){ b.d[s][a]=ns; b.o[s][a]=out; b.chal[s][a]=c; };
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
struct SUL { const Base &b; int cur = 0; long resets = 0, steps = 0; double clockMs = 0;
  explicit SUL(const Base &bb) : b(bb) {}
  virtual ~SUL() = default; virtual void reset() { resets++; cur = 0; } virtual int step(int a) = 0; };
struct S_Det : SUL { explicit S_Det(const Base &b) : SUL(b) {}
  int step(int a) override { steps++; int o = b.o[cur][a]; cur = b.d[cur][a]; return o; } };
struct S_Global : SUL { int L, cnt = 0; double anchor = -1;
  S_Global(const Base &b, int l) : SUL(b), L(l) {} void reset() override { resets++; cur = 0; }
  int step(int a) override { steps++; clockMs += 0.2; int o = b.o[cur][a];
    if (b.chal[cur][a]) { if (anchor < 0 || clockMs - anchor >= 1000) { anchor = clockMs; cnt = 1; }
      else if (cnt < L) cnt++; else o = O_SILENT; } cur = b.d[cur][a]; return o; } };
struct S_Straddle : SUL { int L, cnt = 0; double anchor = -1, jit; std::mt19937_64 rng;
  S_Straddle(const Base &b, int l, double j, uint64_t sd) : SUL(b), L(l), jit(j), rng(sd) {}
  void reset() override { resets++; cur = 0; cnt = 0; anchor = -1; }
  int step(int a) override { steps++; clockMs += 60.0 + ((rng()%8==0)?jit:0.0); int o = b.o[cur][a];
    if (b.chal[cur][a]) { if (anchor < 0 || clockMs - anchor >= 1000) { anchor = clockMs; cnt = 1; }
      else if (cnt < L) cnt++; else o = O_SILENT; } cur = b.d[cur][a]; return o; } };
struct S_Lost : SUL { double p; std::mt19937_64 rng;
  S_Lost(const Base &b, double pp, uint64_t sd) : SUL(b), p(pp), rng(sd) {}
  int step(int a) override { steps++; int o = b.o[cur][a]; cur = b.d[cur][a];
    if (o != O_SILENT && std::uniform_real_distribution<double>(0,1)(rng) < p) return O_SILENT; return o; } };
struct S_MapBug : SUL { explicit S_MapBug(const Base &b) : SUL(b) {}
  int step(int a) override { steps++; int o = b.o[cur][a]; bool c = b.chal[cur][a]; cur = b.d[cur][a]; return c ? O_SILENT : o; } };
struct S_Leak : SUL { int carried = 0; explicit S_Leak(const Base &b) : SUL(b) {}
  void reset() override { resets++; cur = carried; }
  int step(int a) override { steps++; int o = b.o[cur][a]; cur = b.d[cur][a]; carried = cur; return o; } };

struct Mealy { int n=0,k=0; std::vector<std::vector<int>> d,o;
  OutWord run(int s, const Word &w) const { OutWord r; for (int a:w){ r.push_back(o[s][a]); s=d[s][a];} return r; }
  int reach(int s, const Word &w) const { for (int a:w) s=d[s][a]; return s; } };
static Word cat(const Word&a,const Word&b){Word r=a;r.insert(r.end(),b.begin(),b.end());return r;}
static Word cat1(const Word&a,int s){Word r=a;r.push_back(s);return r;}
static OutWord lastN(const OutWord&o,size_t n){return OutWord(o.end()-n,o.end());}

struct Invariants {
  long I1_dupRow=0, I2_unclosed=0, I3_rsFirstSym=0, I4_dupSuffix=0, I5_noNewState=0,
       I6_cacheContra=0, I7_stateBlowup=0, I9_ceNotConsumed=0;
  bool terminated=false, correct=false, capped=false;
  long mq=0, resets=0; int states=0, esize=0, rounds=0;
  std::string firstSymptom = "-";
  void note(const char *s) { if (firstSymptom == "-") firstSymptom = s; }
};

struct Cache {
  struct Node { std::vector<int> child,out; explicit Node(int k):child(k,-1),out(k,-1){} };
  int k; std::vector<Node> nodes; long contradictions=0, hits=0, misses=0;
  bool serve = true;
  explicit Cache(int kk):k(kk){ nodes.emplace_back(k); }
  std::optional<OutWord> lookup(const Word&w) const { int u=0; OutWord r;
    for(int a:w){ if(nodes[u].child[a]<0) return std::nullopt; r.push_back(nodes[u].out[a]); u=nodes[u].child[a]; } return r; }
  void insert(const Word&w,const OutWord&o){ int u=0;
    for(size_t i=0;i<w.size();i++){ int a=w[i];
      if(nodes[u].child[a]<0){ nodes[u].child[a]=(int)nodes.size(); nodes.emplace_back(k); nodes[u].out[a]=o[i]; }
      else if(nodes[u].out[a]!=o[i]) contradictions++;
      u=nodes[u].child[a]; } }
};
struct Oracle { SUL &s; Cache c; Invariants &inv; int repeats=1; long mq=0;
  Oracle(SUL &ss,int k,Invariants &iv):s(ss),c(k),inv(iv){}
  OutWord raw(const Word&w){ s.reset(); OutWord r; for(int a:w) r.push_back(s.step(a)); return r; }
  OutWord voted(const Word&w){ if(repeats<=1) return raw(w);
    std::vector<OutWord> R; for(int i=0;i<repeats;i++) R.push_back(raw(w));
    OutWord r(w.size()); for(size_t i=0;i<w.size();i++){ std::map<int,int> cnt; for(auto&x:R) cnt[x[i]]++;
      int bv=-1,bc=-1; for(auto&[v,n]:cnt) if(n>bc){bc=n;bv=v;} r[i]=bv; } return r; }
  OutWord query(const Word&w){ mq++;
    if (c.serve) { auto h=c.lookup(w); if(h){ c.hits++; return *h; } c.misses++; }
    auto f=voted(w); c.insert(w,f); return f; }
};

struct Learner {
  Oracle &orc; const Base &ref; int K; int mExtra; int capStates;
  std::vector<Word> S,E; std::map<Word,std::vector<OutWord>> row; Mealy H; Invariants &inv;
  std::mt19937_64 rng{555}; int rwTests; double rwStop; std::vector<double> rwW;
  Learner(Oracle &o, const Base &r, Invariants &iv, int mx, int cap, int rt, double rs, std::vector<double> w)
      : orc(o), ref(r), K(r.k), mExtra(mx), capStates(cap), inv(iv), rwTests(rt), rwStop(rs), rwW(w) {
    S.push_back({}); for(int a=0;a<K;a++) E.push_back(Word{a}); }
  void fillRow(const Word&u){ auto &r=row[u]; r.resize(E.size());
    for(size_t j=0;j<E.size();j++){ if(!r[j].empty()) continue; auto o=orc.query(cat(u,E[j])); r[j]=lastN(o,E[j].size()); } }
  std::string key(const Word&u){ auto &r=row[u]; std::string s;
    for(auto&ow:r){ for(int x:ow){ s+=std::to_string(x); s+=','; } s+='|'; } return s; }
  void fillAll(){ for(auto&s:S){ fillRow(s); for(int a=0;a<K;a++) fillRow(cat1(s,a)); } }
  bool closeOnce(){ std::set<std::string> ks; for(auto&s:S) ks.insert(key(s));
    for(size_t i=0;i<S.size();i++) for(int a=0;a<K;a++){ Word la=cat1(S[i],a);
      if(!ks.count(key(la))){ S.push_back(la); fillAll(); return true; } } return false; }
  void closeLoop(){ int g=0; while(closeOnce()){ if((int)S.size()>capStates){ inv.I7_stateBlowup++; inv.note("I7 |S| blowup"); return; }
      if(++g>10000) return; } }
  void buildHyp(){ H=Mealy(); H.k=K; H.n=(int)S.size();
    H.d.assign(H.n,std::vector<int>(K,0)); H.o.assign(H.n,std::vector<int>(K,0));
    std::map<std::string,int> idx;
    for(int i=0;i<H.n;i++){ auto k2=key(S[i]);
      if(idx.count(k2)){ inv.I1_dupRow++; inv.note("I1 duplicate S row"); } idx[k2]=i; }
    for(int i=0;i<H.n;i++) for(int a=0;a<K;a++){ H.o[i][a]=row[S[i]][a][0];
      auto it=idx.find(key(cat1(S[i],a)));
      if(it==idx.end()){ inv.I2_unclosed++; inv.note("I2 table not closed"); H.d[i][a]=i; }
      else H.d[i][a]=it->second; } }
  int hypState(const Word&w) const { return H.reach(0,w); }
  std::optional<Word> rs(const Word &ce){
    int k=(int)ce.size();
    auto beta=[&](int i)->OutWord{ Word pre(ce.begin(),ce.begin()+i),suf(ce.begin()+i,ce.end());
      Word q=cat(S[hypState(pre)],suf); auto o=orc.query(q); return lastN(o,suf.size()); };
    auto hOut=[&](int i)->OutWord{ Word pre(ce.begin(),ce.begin()+i),suf(ce.begin()+i,ce.end());
      return H.run(hypState(pre),suf); };
    int lo=0,hi=k; while(hi-lo>1){ int mid=lo+(hi-lo)/2; if(beta(mid)!=hOut(mid)) lo=mid; else hi=mid; }
    auto bb=beta(lo), hh=hOut(lo);
    if(bb.empty()||bb[0]!=hh[0]){ inv.I3_rsFirstSym++; inv.note("I3 RS first-symbol mismatch"); return std::nullopt; }
    Word suf(ce.begin()+lo+1,ce.end());
    if(suf.empty()){ inv.I3_rsFirstSym++; inv.note("I3 RS empty suffix"); return std::nullopt; }
    for(auto&e:E) if(e==suf){ inv.I4_dupSuffix++; inv.note("I4 RS suffix already in E"); return std::nullopt; }
    return suf; }
  std::optional<Word> eqRW(){ std::uniform_int_distribution<int> ua(0,K-1);
    std::discrete_distribution<int> ub(rwW.begin(), rwW.end());
    std::uniform_real_distribution<double> ur(0,1);
    auto pick=[&]{ return rwW.empty()?ua(rng):ub(rng); };
    for(int t=0;t<rwTests;t++){ Word w; w.push_back(pick());
      while(ur(rng)>rwStop && w.size()<80) w.push_back(pick());
      auto so=orc.query(w); if(so!=H.run(0,w)) return w; } return std::nullopt; }
  void run(){ fillAll(); closeLoop(); buildHyp();
    for(int g=0; g<200; g++){ inv.rounds++;
      if((int)S.size()>capStates){ inv.capped=true; inv.note("I7 |S| blowup"); break; }
      auto ce=eqRW(); if(!ce){ inv.terminated=true; break; }
      size_t before=S.size(); auto suf=rs(*ce); if(!suf) break;
      E.push_back(*suf); fillAll(); closeLoop();
      if(S.size()==before){ inv.I5_noNewState++; inv.note("I5 CE added no state"); break; }
      buildHyp();
      auto so=orc.query(*ce); if(so==H.run(0,*ce)) {} else { inv.I9_ceNotConsumed++; }
    }
    inv.I6_cacheContra=orc.c.contradictions; if(inv.I6_cacheContra && inv.firstSymptom=="-") inv.note("I6 cache contradiction");
    inv.mq=orc.mq; inv.resets=orc.s.resets; inv.states=(int)S.size(); inv.esize=(int)E.size();
  }
};

// exact check of the final hypothesis against the deterministic reference
static bool hypCorrect(const Mealy &H, const Base &b) {
  if (H.n == 0) return false;
  std::set<std::pair<int,int>> seen; std::queue<std::pair<int,int>> Q;
  Q.push({0,0}); seen.insert({0,0});
  while(!Q.empty()){ auto [h,r]=Q.front(); Q.pop();
    for(int a=0;a<b.k;a++){ if(H.o[h][a]!=b.o[r][a]) return false;
      std::pair<int,int> ns{H.d[h][a], b.d[r][a]}; if(seen.insert(ns).second) Q.push(ns); } }
  return true;
}

int main() {
  Base b = tcpBase();
  const int L = 10, CAP = 400;
  struct Row { const char *nm; std::function<std::unique_ptr<SUL>(uint64_t)> mk; };
  std::vector<Row> rows = {
    {"S1 deterministic",     [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_Det(b)); }},
    {"S3 host-global cnt",   [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_Global(b, L)); }},
    {"S4 window straddle",   [&](uint64_t s){ return std::unique_ptr<SUL>(new S_Straddle(b, L, 700.0, s)); }},
    {"S5 lost pkt p=0.02",   [&](uint64_t s){ return std::unique_ptr<SUL>(new S_Lost(b, 0.02, s)); }},
    {"S5 lost pkt p=0.10",   [&](uint64_t s){ return std::unique_ptr<SUL>(new S_Lost(b, 0.10, s)); }},
    {"S6 mapper bug (det)",  [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_MapBug(b)); }},
    {"S7 prev-query leak",   [&](uint64_t  ){ return std::unique_ptr<SUL>(new S_Leak(b)); }},
  };
  struct Mode { const char *nm; bool serveCache; int repeats; };
  std::vector<Mode> modes = { {"cache,vote1", true, 1}, {"nocache,vote1", false, 1},
                              {"nocache,vote5", false, 5}, {"nocache,vote9", false, 9} };

  std::printf("SYN-biased random-walk EQ oracle (2000 tests, p_stop=0.06), |S| cap=%d, 20 seeds each.\n", CAP);
  std::printf("Symptom legend: I1 dup S row | I2 unclosed | I3 RS first-symbol | I4 dup suffix\n"
              "                I5 CE added no state | I6 cache contradiction | I7 |S| blowup\n\n");
  std::printf("%-20s %-14s | %5s %5s %5s | %-28s | %s\n",
              "SUL", "mode", "term", "corr", "wrong", "first symptom histogram", "median |S| (true=80/10)");
  for (auto &r : rows) for (auto &md : modes) {
    std::map<std::string,int> hist; int term=0, corr=0, silentWrong=0; std::vector<int> sizes; long mqs=0;
    for (uint64_t sd = 0; sd < 20; sd++) {
      Invariants inv; auto sul = r.mk(1000 + 7919*sd);
      Oracle orc(*sul, b.k, inv); orc.c.serve = md.serveCache; orc.repeats = md.repeats;
      Learner LL(orc, b, inv, 0, CAP, 2000, 0.06, {4,1,1,1,1,1});
      LL.run();
      bool ok = hypCorrect(LL.H, b);
      if (inv.terminated) term++;
      if (ok) corr++;
      if (inv.terminated && !ok && inv.firstSymptom == "-") silentWrong++;
      hist[inv.firstSymptom]++; sizes.push_back(inv.states); mqs += inv.mq;
    }
    std::sort(sizes.begin(), sizes.end());
    std::string hs; for (auto &[k2,v] : hist) { if (!hs.empty()) hs += " "; hs += k2.substr(0,2) + ":" + std::to_string(v); }
    std::printf("%-20s %-14s | %5d %5d %5d | %-28s | %d  (mq avg %ld)\n",
                r.nm, md.nm, term, corr, silentWrong, hs.c_str(), sizes[sizes.size()/2], mqs/20);
  }
  std::printf("\nNOTE: 'corr' means the final hypothesis is exactly the DETERMINISTIC reference\n"
              "(10 states). For S3/S4 no correct answer exists -- the SUL is not a Mealy machine.\n");
  return 0;
}
