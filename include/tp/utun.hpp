#pragma once

// A utun interface, opened through PF_SYSTEM/SYSPROTO_CONTROL.
//
// utun is a point-to-point interface whose "remote" end is this process. A
// frame written to the fd is handed to ip_input() as if it had arrived on a
// NIC, and a frame the stack routes to the peer address comes back out of the
// fd. That is the entire mechanism the project rests on: it puts a userspace
// program in the position of the network, with the real kernel TCP on the
// other side.
//
// Creating one needs root, and there is no unprivileged fallback. Falling back
// to loopback would have been easy and wrong: it exercises a different path
// through the stack, and the results would carry the same labels.

#include <netinet/in.h>

#include <cstdint>
#include <string>
#include <vector>

#include "tp/segment.hpp"

namespace tp {

class Utun {
 public:
  Utun() = default;
  ~Utun();
  Utun(const Utun&) = delete;
  Utun& operator=(const Utun&) = delete;

  // Opens the first free unit, assigns the point-to-point addresses, and
  // brings the interface up. Returns false and fills `err` on failure.
  bool open(const char* local, const char* peer, std::string* err);

  const std::string& ifname() const { return ifname_; }
  in_addr local() const { return local_; }
  in_addr peer() const { return peer_; }
  int fd() const { return fd_; }

  // Writes one segment from `peer` to `local`. Returns false on a short or
  // failed write.
  bool send(const Seg& s, std::string* err);

  // Reactive drain: waits up to `timeout_ms` for the FIRST segment, then takes
  // everything already queued and returns. This is what a peer that has to
  // acknowledge promptly needs -- see the comment in the implementation for
  // what the obvious alternative cost.
  void drain(double timeout_ms, std::vector<Seg>* out);

  // Collects for the FULL duration regardless of what arrives. Needed when the
  // question is "how many replies did that provoke in total", where returning
  // as soon as the first one lands undercounts by everything still in flight.
  // Using drain() for that turned a burst of 10 challenge ACKs into a count of
  // 1, so the two semantics are separate methods rather than a bool.
  void drain_for(double duration_ms, std::vector<Seg>* out);

  uint64_t frames_written() const { return written_; }
  uint64_t segments_read() const { return read_; }
  uint64_t non_ipv4_frames() const { return non_ipv4_; }
  // Frames that were IPv4 TCP but failed parse(). Should be zero; a nonzero
  // count means the read path is truncating and every timing below it is
  // suspect, so experiments print it rather than hiding it.
  uint64_t unparseable() const { return unparseable_; }

  // What the kernel actually granted for SO_RCVBUF, which is not what was
  // asked for -- it is clamped against kern.ipc.maxsockbuf without an error.
  // -1 if it could not be read back.
  int rcvbuf_granted() const { return rcvbuf_granted_; }
  // The most frames, and the most bytes, ever taken from the fd in one
  // uninterrupted drain -- i.e. the deepest the queue is known to have been.
  // A kernel control socket that overflows discards the frame before read()
  // could see it and keeps no counter, so there is no way to prove zero drops.
  // This is a measured LOWER BOUND on occupancy: if it approaches
  // rcvbuf_granted(), a harness-side drop is plausible and every timing in the
  // run is suspect. If it stays a tiny fraction, the reader kept up.
  uint64_t peak_burst_frames() const { return peak_burst_frames_; }
  uint64_t peak_burst_bytes() const { return peak_burst_bytes_; }

 private:
  int fd_ = -1;
  std::string ifname_;
  in_addr local_{};
  in_addr peer_{};
  uint16_t ip_id_ = 1;
  uint64_t written_ = 0, read_ = 0, non_ipv4_ = 0, unparseable_ = 0;
  int rcvbuf_granted_ = -1;
  uint64_t peak_burst_frames_ = 0, peak_burst_bytes_ = 0;
};

}  // namespace tp
