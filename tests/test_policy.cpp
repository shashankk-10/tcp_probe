// Which segments the peer pretends not to have received.
//
// The policy decides what the experiment actually tests. A rule that silently
// never fires produces a clean run that looks like a result and measured
// nothing, so unfired() is part of the contract and is asserted on here.

#include "tp/policy.hpp"

#include "check.hpp"

using namespace tp;

int main() {
  // ---- a rule fires once by default: the original is lost, the first
  // retransmission gets through. That is what makes the run measure recovery
  // rather than the backoff ladder.
  {
    LossPolicy p;
    p.add({1000, 1001, 1, 0});
    CHECK(p.drop(1000, 100));   // segment [1000,1100) overlaps
    CHECK(!p.drop(1000, 100));  // the retransmission is let through
    CHECK_EQ(p.total_dropped(), 1);
    CHECK_EQ(p.unfired().size(), 0u);
  }

  // ---- overlap, not containment. The kernel chooses segment boundaries, so a
  // rule naming one byte must catch whatever segment carries it.
  {
    LossPolicy p;
    p.add({4096, 4097, 1, 0});
    CHECK(!p.drop(0, 1024));      // [0,1024)
    CHECK(!p.drop(3072, 1024));   // [3072,4096) -- ends exactly at lo, no overlap
    CHECK(p.drop(4096, 1024));    // [4096,5120) -- contains it
  }

  // ---- a segment ending exactly at `lo` must not match; half-open ranges are
  // the whole reason the boundary cases are unambiguous.
  {
    LossPolicy p;
    p.add({100, 200, 1, 0});
    CHECK(!p.drop(0, 100));    // [0,100)
    CHECK(p.drop(199, 1));     // [199,200) -- last byte inside
  }

  // ---- times > 1 drops the retransmissions too, which is how the backoff
  // ladder gets measured.
  {
    LossPolicy p;
    p.add({0, 1024, 3, 0});
    CHECK(p.drop(0, 512));
    CHECK(p.drop(0, 512));
    CHECK(p.drop(0, 512));
    CHECK(!p.drop(0, 512));
    CHECK_EQ(p.total_dropped(), 3);
  }

  // ---- zero-length segments are never dropped. A pure ACK or a bare FIN
  // carries no data, and discarding it would test connection teardown rather
  // than loss recovery.
  {
    LossPolicy p;
    p.add({0, 100000, 10, 0});
    CHECK(!p.drop(0, 0));
    CHECK_EQ(p.total_dropped(), 0);
  }

  // ---- a rule that never matched is reported. An experiment whose rule never
  // fired did not test what its name claims.
  {
    LossPolicy p;
    p.add({0, 100, 1, 0});
    p.add({999000, 999100, 1, 0});
    CHECK(p.drop(0, 50));
    auto u = p.unfired();
    CHECK_EQ(u.size(), 1u);
    if (u.size() == 1) CHECK_EQ(u[0], 1u);
  }

  // ---- first matching rule wins, and only it is charged. Two rules covering
  // one segment must not both count it, or total_dropped double-counts a
  // single lost segment.
  {
    LossPolicy p;
    p.add({0, 100, 1, 0});
    p.add({50, 150, 1, 0});
    CHECK(p.drop(40, 40));  // overlaps both
    CHECK_EQ(p.total_dropped(), 1);
    CHECK_EQ(p.rules()[0].fired, 1);
    CHECK_EQ(p.rules()[1].fired, 0);
  }

  return check::finish("policy");
}
