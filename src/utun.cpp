#include "tp/utun.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if_utun.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "tp/clock.hpp"

namespace tp {
namespace {

void run_cmd(const char* fmt, ...) {
  char cmd[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(cmd, sizeof cmd, fmt, ap);
  va_end(ap);
  int rc = system(cmd);
  (void)rc;  // ifconfig on an already-configured interface is not an error
}

}  // namespace

Utun::~Utun() {
  // Closing the kernel control socket is what tears the interface down; there
  // is no explicit destroy ioctl.
  if (fd_ >= 0) close(fd_);
}

bool Utun::open(const char* local, const char* peer, std::string* err) {
  inet_pton(AF_INET, local, &local_);
  inet_pton(AF_INET, peer, &peer_);

  struct ctl_info ci;
  memset(&ci, 0, sizeof ci);
  strlcpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof ci.ctl_name);

  // The kernel names the interface after the control unit, and units 1..4 are
  // normally taken by utun0..3 (VPN). Probe upward. Each attempt needs a fresh
  // socket: a kernel control socket whose connect() failed is not reusable.
  for (uint32_t unit = 1; unit <= 64; ++unit) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
      *err = std::string("socket(PF_SYSTEM): ") + strerror(errno);
      return false;
    }
    if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
      *err = std::string("ioctl(CTLIOCGINFO): ") + strerror(errno);
      close(fd);
      return false;
    }
    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof sc);
    sc.sc_len = sizeof sc;
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ci.ctl_id;
    sc.sc_unit = unit;

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&sc), sizeof sc) == 0) {
      char name[IFNAMSIZ] = {0};
      socklen_t nlen = sizeof name;
      if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &nlen) < 0) {
        *err = std::string("getsockopt(UTUN_OPT_IFNAME): ") + strerror(errno);
        close(fd);
        return false;
      }
      ifname_ = name;
      fd_ = fd;

      // A single reader on a small socket buffer is how you silently lose
      // packets and then publish the loss as protocol behaviour. This project
      // measures retransmission timing, so a harness-side drop does not just
      // add noise -- it manufactures the exact event under study.
      //
      // Asking is not getting: the kernel clamps SO_RCVBUF against
      // kern.ipc.maxsockbuf, silently, so the granted size gets read back
      // below. There is no counter for a kernel-control
      // socket overflowing -- the frame is gone before read() is reachable --
      // so the granted size and the high-water mark below are the only evidence
      // available that the harness did not cause what it measured.
      int rcvbuf = 1 << 21;
      setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
      socklen_t blen = sizeof rcvbuf_granted_;
      if (getsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf_granted_, &blen) < 0)
        rcvbuf_granted_ = -1;

      run_cmd("ifconfig %s inet %s %s netmask 255.255.255.255 up", ifname_.c_str(),
              local, peer);
      run_cmd("route -qn add -host %s -interface %s 2>/dev/null", peer, ifname_.c_str());
      return true;
    }
    int e = errno;
    close(fd);
    if (e == EPERM) {
      *err = "connect() to the utun control socket returned EPERM -- run under sudo";
      return false;
    }
    if (e != EBUSY && e != EADDRINUSE && e != EEXIST) {
      *err = std::string("connect(utun control): ") + strerror(e);
      return false;
    }
  }
  *err = "no free utun unit in 1..64";
  return false;
}

bool Utun::send(const Seg& s, std::string* err) {
  uint8_t pkt[4 + 1500];
  size_t n = build(pkt, sizeof pkt, peer_, local_, s, ip_id_++);
  if (n == 0) {
    *err = "segment does not fit in a 1500-byte frame";
    return false;
  }
  ssize_t w = write(fd_, pkt, n);
  if (w < 0) {
    *err = std::string("write(utun): ") + strerror(errno);
    return false;
  }
  if (size_t(w) != n) {
    *err = "short write to utun";
    return false;
  }
  ++written_;
  return true;
}

void Utun::drain(double timeout_ms, std::vector<Seg>* out) {
  const double deadline = now_ms() + timeout_ms;
  bool got_any = false;

  // Frames taken in this one uninterrupted burst, i.e. how many were sitting on
  // the fd at once. Recorded on every exit path, hence the destructor.
  //
  // This replaces a FIONREAD-based queue-depth probe that did not work. On an
  // AF_INET datagram socket FIONREAD returns the whole queue (sb_cc); on a
  // PF_SYSTEM kernel-control socket it returns only the NEXT datagram's size.
  // The symptom was a "peak queued" that read exactly 1068 bytes
  // (1024 MSS + 20 IP + 20 TCP + 4 utun AF prefix) in four experiments whose
  // traffic differed by 4x -- a constant, not a measurement. Counting reads
  // needs no ioctl and cannot be fooled that way.
  struct Tally {
    uint64_t& peak_frames;
    uint64_t& peak_bytes;
    uint64_t frames = 0, bytes = 0;
    ~Tally() {
      if (frames > peak_frames) peak_frames = frames;
      if (bytes > peak_bytes) peak_bytes = bytes;
    }
  } tally{peak_burst_frames_, peak_burst_bytes_, 0, 0};

  for (;;) {
    // Wait up to the deadline for the FIRST segment, then take only what is
    // already queued and return.
    //
    // The obvious implementation -- poll for the whole slice every time --
    // costs the full slice after the last segment of every burst, because
    // poll only returns 0 when it times out. With a 20 ms slice that put 20 ms
    // of dead wait between receiving a burst and acknowledging it, which the
    // kernel then measured as RTT. It inflated the first run's mid-stream
    // recovery from about a millisecond to 21.4 ms, i.e. the number was almost
    // entirely this function. Reactive drain is not an optimisation here, it
    // is a correctness requirement for every timing in the repo.
    int wait_ms;
    if (got_any) {
      wait_ms = 0;
    } else {
      const double left = deadline - now_ms();
      if (left <= 0) return;
      wait_ms = int(left) + 1;
    }
    struct pollfd pfd{fd_, POLLIN, 0};
    int pr = poll(&pfd, 1, wait_ms);
    if (pr < 0) {
      if (errno == EINTR) continue;
      return;
    }
    if (pr == 0) return;  // nothing more is immediately available

    uint8_t buf[4 + 2048];
    ssize_t n = read(fd_, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      return;
    }
    // Stamp before parsing. Parsing is cheap, but the stamp is the measurement
    // and it should not include work this program chose to do.
    const double t = now_ms();
    ++tally.frames;
    tally.bytes += uint64_t(n);
    if (n < 4) continue;
    uint32_t af;
    memcpy(&af, buf, 4);
    if (ntohl(af) != AF_INET) {
      ++non_ipv4_;
      continue;
    }
    Seg s;
    if (!parse(buf, size_t(n), &s)) {
      ++unparseable_;
      continue;
    }
    s.t_ms = t;
    out->push_back(std::move(s));
    ++read_;
    got_any = true;
  }
}

void Utun::drain_for(double duration_ms, std::vector<Seg>* out) {
  const double deadline = now_ms() + duration_ms;
  for (;;) {
    const double left = deadline - now_ms();
    if (left <= 0) return;
    // Reuse the reactive drain in slices. It returns as soon as the queue is
    // empty, so this loop costs one poll wakeup per idle slice rather than
    // spinning, and the caller still gets the full collection window.
    drain(left, out);
  }
}

}  // namespace tp
