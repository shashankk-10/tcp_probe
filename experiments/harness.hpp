#pragma once

// Shared setup for the root-only experiments: bring up a utun, bind a
// listener on the kernel side of it, and run one loss scenario end to end.
//
// Every experiment prints the sysctl snapshot before its table. A retransmit
// timing table is meaningless without it -- the same binary on the same
// machine produces different numbers if rtt_min or rexmt_slop was touched, and
// nothing else in the output would say so.

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "tp/clock.hpp"
#include "tp/peer.hpp"
#include "tp/policy.hpp"
#include "tp/sysctl.hpp"
#include "tp/trace.hpp"
#include "tp/utun.hpp"

namespace tp {

// 10.90.0.0/24 was checked unrouted on this host, and utun0-3 (VPN) carry IPv6
// only, so nothing competes for it.
constexpr const char* kLocal = "10.90.0.1";
constexpr const char* kPeer = "10.90.0.2";
constexpr uint16_t kPort = 9999;

struct Lab {
  Utun utun;
  int listen_fd = -1;
  TcpKnobs knobs;

  ~Lab() {
    if (listen_fd >= 0) close(listen_fd);
  }

  bool start(const char* title, std::string* err) {
    if (geteuid() != 0) {
      *err = "needs root: creating a utun goes through PF_SYSTEM/SYSPROTO_CONTROL";
      return false;
    }
    printf("==============================================================\n");
    printf("%s\n", title);
    printf("==============================================================\n");
    knobs = read_knobs();
    print_knobs(knobs);

    if (!utun.open(kLocal, kPeer, err)) return false;
    printf("interface         : %s  (%s <-> %s, port %u)\n\n", utun.ifname().c_str(),
           kLocal, kPeer, kPort);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
      *err = "socket(listen)";
      return false;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_len = sizeof la;
    la.sin_port = htons(kPort);
    inet_pton(AF_INET, kLocal, &la.sin_addr);
    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&la), sizeof la) < 0) {
      *err = "bind(10.90.0.1:9999) -- did ifconfig assign the address?";
      return false;
    }
    if (listen(listen_fd, 16) < 0) {
      *err = "listen()";
      return false;
    }
    return true;
  }
};

struct Outcome {
  bool ok = false;
  std::string err;
  RunSummary sum;
  Trace trace;
  double handshake_rtt_ms = -1;
  bool sack_negotiated = false;
  uint16_t peer_mss = 0;
  // Bytes the kernel accepted from write(). A short write silently changes how
  // much data is under test, so the count comes back with the result.
  uint32_t bytes_written = 0;
};

// Stands up one connection, has the KERNEL send `bytes`, and receives them
// under `loss`. The kernel is the sender on purpose: every retransmission
// decision then belongs to XNU rather than to this program.
inline Outcome run_scenario(Lab& lab, const PeerConfig& cfg, uint32_t bytes,
                            double timeout_ms, LossPolicy& loss) {
  Outcome o;
  Peer p(lab.utun, o.trace, cfg);
  if (!p.establish(lab.listen_fd, &o.err)) return o;

  o.handshake_rtt_ms = p.handshake_rtt_ms();
  o.sack_negotiated = p.peer_sack_ok();
  o.peer_mss = p.peer_mss();

  std::vector<uint8_t> buf(bytes);
  // A recognisable pattern rather than zeros: if the reassembly ever hands
  // back the wrong bytes, zeros would look correct.
  for (uint32_t i = 0; i < bytes; ++i) buf[i] = uint8_t(i * 31 + 7);

  // The whole transfer is handed to the kernel in one blocking write BEFORE the
  // peer starts reading, so all of it has to fit in the socket send buffer.
  // Nothing drains it in the meantime -- the only reader is p.receive(), below.
  // Ask for more than sendspace and write() blocks forever with no output, which
  // reads as a hung experiment rather than a misconfigured one.
  if (lab.knobs.sendspace > 0 && bytes > uint32_t(lab.knobs.sendspace)) {
    o.err = "requested " + std::to_string(bytes) +
            " bytes but net.inet.tcp.sendspace is " +
            std::to_string(lab.knobs.sendspace) +
            "; the write would block before the peer ever reads";
    p.reset();
    return o;
  }

  ssize_t w = write(p.accepted_fd(), buf.data(), buf.size());
  if (w < 0) {
    o.err = std::string("write() on the accepted socket: ") + strerror(errno);
    p.reset();
    return o;
  }
  o.bytes_written = uint32_t(w);
  // A short write means the kernel is sending less than the experiment names,
  // which surfaces downstream as "incomplete" and gets misread as a timeout.
  if (o.bytes_written != bytes) {
    o.err = "short write: " + std::to_string(o.bytes_written) + " of " +
            std::to_string(bytes) + " bytes accepted";
    p.reset();
    return o;
  }

  o.sum = p.receive(bytes, timeout_ms, loss);
  o.ok = true;
  p.reset();
  // The kernel's socket needs a moment to finish tearing down before the next
  // scenario binds a new 4-tuple; without it the first segment of the next run
  // can race the RST of this one.
  sleep_ms(60);
  return o;
}

// Prints the counters that say whether the harness itself perturbed the
// measurement. A drop on this side manufactures the exact event under study,
// so these are printed at the end of every experiment, not hidden behind a
// verbose flag.
inline void print_integrity(const Lab& lab) {
  printf("\nharness integrity: frames written %llu, segments read %llu, "
         "non-IPv4 %llu, unparseable %llu\n",
         (unsigned long long)lab.utun.frames_written(),
         (unsigned long long)lab.utun.segments_read(),
         (unsigned long long)lab.utun.non_ipv4_frames(),
         (unsigned long long)lab.utun.unparseable());

  const int granted = lab.utun.rcvbuf_granted();
  const uint64_t peak = lab.utun.peak_burst_bytes();
  printf("  utun rcvbuf granted %d bytes, deepest drain %llu frames / %llu bytes "
         "(%.1f%% of buffer)\n",
         granted, (unsigned long long)lab.utun.peak_burst_frames(),
         (unsigned long long)peak,
         granted > 0 ? 100.0 * double(peak) / double(granted) : 0.0);

  if (lab.utun.unparseable() > 0)
    printf("  WARNING: unparseable frames > 0 -- the read path is truncating and "
           "every timing above is suspect.\n");
  // An overflow on the control socket leaves no trace at all: the frame is
  // discarded before read() could see it, and there is no counter for it. So the
  // only defensible statement is how deep the queue is KNOWN to have got. Half
  // the buffer is an arbitrary line, but an arbitrary line that is stated beats
  // a silent assumption that the harness was fine.
  if (granted > 0 && peak * 2 > uint64_t(granted))
    printf("  WARNING: peak queue depth passed half the receive buffer -- a "
           "harness-side drop cannot be ruled out, and it would look exactly "
           "like the loss under study.\n");
}

}  // namespace tp
