// The receiver's in-order frontier. This is where the head-of-line delay comes
// from, so an error here does not crash -- it reports a wrong headline number.

#include "tp/reassembly.hpp"

#include "check.hpp"

using namespace tp;

int main() {
  const uint32_t kIsn = 1000;

  // ---- in-order arrival advances the frontier every time.
  {
    Reassembly r(kIsn);
    CHECK_EQ(r.delivered(), 0u);
    CHECK(r.accept(1000, 100, 1.0));
    CHECK_EQ(r.rcv_nxt(), 1100u);
    CHECK(r.accept(1100, 100, 2.0));
    CHECK_EQ(r.delivered(), 200u);
    CHECK(!r.has_gap());
    CHECK_EQ(r.ooo_segments(), 0u);
  }

  // ---- a hole: later data is held, the frontier does not move, and the held
  // range is what a SACK block should describe.
  {
    Reassembly r(kIsn);
    CHECK(r.accept(1000, 100, 1.0));       // [1000,1100)
    CHECK(!r.accept(1200, 100, 2.0));      // [1200,1300), hole at [1100,1200)
    CHECK_EQ(r.rcv_nxt(), 1100u);
    CHECK(r.has_gap());
    CHECK_EQ(r.ooo_segments(), 1u);
    auto b = r.sack_blocks();
    CHECK_EQ(b.size(), 1u);
    if (b.size() == 1) {
      CHECK_EQ(b[0].start, 1200u);
      CHECK_EQ(b[0].end, 1300u);
    }

    // Filling the hole must release everything contiguous behind it in one go.
    CHECK(r.accept(1100, 100, 9.0));
    CHECK_EQ(r.rcv_nxt(), 1300u);
    CHECK(!r.has_gap());
    CHECK_EQ(r.sack_blocks().size(), 0u);
  }

  // ---- two holes collapse correctly when filled out of order.
  {
    Reassembly r(kIsn);
    r.accept(1000, 100, 1.0);   // [1000,1100)
    r.accept(1200, 100, 2.0);   // hole A [1100,1200)
    r.accept(1400, 100, 3.0);   // hole B [1300,1400)
    CHECK_EQ(r.sack_blocks().size(), 2u);
    r.accept(1300, 100, 4.0);   // merges the two held blocks, frontier still stuck
    CHECK_EQ(r.rcv_nxt(), 1100u);
    CHECK_EQ(r.sack_blocks().size(), 1u);
    r.accept(1100, 100, 5.0);   // fills A -> everything drains
    CHECK_EQ(r.rcv_nxt(), 1500u);
    CHECK(!r.has_gap());
  }

  // ---- a pure duplicate advances nothing and is counted as a duplicate, not
  // as out-of-order. Conflating the two would make a retransmission look like
  // reordering in the summary.
  {
    Reassembly r(kIsn);
    r.accept(1000, 100, 1.0);
    CHECK(!r.accept(1000, 100, 2.0));
    CHECK_EQ(r.dup_segments(), 1u);
    CHECK_EQ(r.ooo_segments(), 0u);
    CHECK_EQ(r.rcv_nxt(), 1100u);
  }

  // ---- a retransmission that straddles the frontier carries new bytes in its
  // tail. Treating it as a whole duplicate would lose them and stall forever.
  {
    Reassembly r(kIsn);
    r.accept(1000, 100, 1.0);            // frontier 1100
    CHECK(r.accept(1050, 100, 2.0));     // [1050,1150): 50 old + 50 new
    CHECK_EQ(r.rcv_nxt(), 1150u);
  }

  // ---- adjacency must merge. Two touching held ranges left unmerged would be
  // reported as two SACK blocks describing one contiguous region, which is
  // legal but would misrepresent what the receiver holds.
  {
    Reassembly r(kIsn);
    r.accept(1000, 100, 1.0);
    r.accept(1200, 100, 2.0);
    r.accept(1300, 100, 3.0);  // touches the previous block exactly
    CHECK_EQ(r.sack_blocks().size(), 1u);
    auto b = r.sack_blocks();
    if (b.size() == 1) {
      CHECK_EQ(b[0].start, 1200u);
      CHECK_EQ(b[0].end, 1400u);
    }
  }

  // ---- time_reached is the measurement. It must report the time the frontier
  // CROSSED a sequence number, not the time the segment carrying it arrived --
  // for data behind a hole those differ, and the difference is the result.
  {
    Reassembly r(kIsn);
    r.accept(1000, 100, 10.0);   // frontier -> 1100 at t=10
    r.accept(1200, 100, 20.0);   // held; frontier does not move
    r.accept(1100, 100, 350.0);  // hole filled at t=350 -> frontier 1300

    CHECK_EQ(r.time_reached(1100), 10.0);
    // Byte 1200 arrived at t=20 but only became deliverable at t=350.
    CHECK_EQ(r.time_reached(1201), 350.0);
    CHECK_EQ(r.time_reached(1300), 350.0);
    CHECK_EQ(r.time_reached(9999), -1.0);  // never reached
  }

  // ---- zero-length segments are not data and must not disturb the frontier.
  {
    Reassembly r(kIsn);
    CHECK(!r.accept(1000, 0, 1.0));
    CHECK_EQ(r.delivered(), 0u);
  }

  // ---- sequence-space wraparound. Nothing here runs long enough to wrap, so
  // a bug in this would stay silent: near 2^32 a comparison written with <
  // instead of seq_lt() sends the frontier backwards.
  {
    const uint32_t near_wrap = 0xffffff00u;
    Reassembly r(near_wrap);
    CHECK(r.accept(near_wrap, 0x80, 1.0));
    CHECK_EQ(r.rcv_nxt(), 0xffffff80u);
    CHECK(r.accept(0xffffff80u, 0x100, 2.0));  // crosses zero
    CHECK_EQ(r.rcv_nxt(), 0x00000080u);
    CHECK_EQ(r.delivered(), 0x180u);
    CHECK(!r.has_gap());
  }

  // ---- a hole that spans the wrap point still resolves.
  {
    const uint32_t near_wrap = 0xfffffe00u;
    Reassembly r(near_wrap);
    r.accept(near_wrap, 0x100, 1.0);            // [fffffe00, ffffff00)
    CHECK(!r.accept(0x00000000u, 0x100, 2.0));  // held across the wrap
    CHECK_EQ(r.rcv_nxt(), 0xffffff00u);
    CHECK(r.has_gap());
    CHECK(r.accept(0xffffff00u, 0x100, 3.0));   // fills it
    CHECK_EQ(r.rcv_nxt(), 0x00000100u);
    CHECK(!r.has_gap());
  }

  // ---- held_ must come out sorted from the merge walk itself. The merge used
  // to sort its output afterwards, which hid whether the walk actually
  // maintained the ordering it assumes on entry. These two shapes are the ones
  // that would expose a mis-ordered emit: a range that lands below everything
  // held, and a range that swallows a middle block while higher blocks survive.
  // sack_blocks() reports held_ in reverse, so descending starts here means
  // ascending in held_.
  {
    Reassembly r(kIsn);
    r.accept(1000, 100, 1.0);   // frontier -> 1100
    r.accept(1600, 100, 2.0);   // held
    r.accept(1800, 100, 3.0);   // held
    r.accept(1200, 100, 4.0);   // below both held blocks
    auto b = r.sack_blocks();
    CHECK_EQ(b.size(), 3u);
    if (b.size() == 3) {
      CHECK_EQ(b[0].start, 1800u);
      CHECK_EQ(b[1].start, 1600u);
      CHECK_EQ(b[2].start, 1200u);
    }
    CHECK_EQ(r.rcv_nxt(), 1100u);  // still stuck behind [1100,1200)

    // Bridge the middle pair into one block; the top block must stay put and
    // stay last.
    r.accept(1300, 300, 5.0);  // [1300,1600) joins [1200,1300) and [1600,1700)
    auto c = r.sack_blocks();
    CHECK_EQ(c.size(), 2u);
    if (c.size() == 2) {
      CHECK_EQ(c[0].start, 1800u);
      CHECK_EQ(c[1].start, 1200u);
      CHECK_EQ(c[1].end, 1700u);
    }
  }

  return check::finish("reassembly");
}
