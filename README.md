# tcp_probe

Measures what one lost TCP segment costs the application waiting for the data.

A small userspace program acts as one end of a TCP connection over a `utun`
interface. The real kernel stack is the other end, and it does the sending. We
drop segments on purpose and time how long the data behind the hole takes to show
up.

The kernel makes every retransmit and timer decision. We only pick what to ACK,
and when.

```
    kernel TCP (the sender)                this process (the receiver)
   ┌────────────────────────┐            ┌──────────────────────────────┐
   │ listen() / accept()    │            │  Peer: handshake, ACK policy │
   │ write(fd, 96 KB)       │            │  LossPolicy: what to discard │
   │ tcp_output()           │            │  Reassembly: in-order front  │
   └──────────┬─────────────┘            └───────────────┬──────────────┘
              │            utun (point-to-point)         │
              └──────────────────────────────────────────┘
                        10.90.0.1  <──>  10.90.0.2
```

## Main result

| Arm | App stalls for | Repaired by |
|---|---|---|
| mid-stream loss, no SACK | 0.742 ms | fast retransmit |
| mid-stream loss, SACK | 0.744 ms | fast retransmit |
| **tail loss, no SACK** | **229.6 ms** | retransmit timer |
| **tail loss, SACK** | **2.9 ms** | tail loss probe |

- Same 96 KB transfer, same dropped byte, same kernel.
- The only difference in the two tail rows: did our SYN carry the 2-byte
  SACK-permitted option.
- `tcp_output.c:2966` arms the Tail Loss Probe only if SACK was agreed. Without
  it, a loss at the end of a transfer waits out the full retransmit timeout.
- A loss in the middle is cheap either way. Segments after it trigger duplicate
  ACKs, so the kernel resends without waiting for a timer.

## The "3 duplicate ACKs" rule is wrong

- Textbook: fast retransmit needs 3 duplicate ACKs.
- We placed the drop so exactly N segments follow it, then swept N. No step at 3.
- N=1 through N=5 all recovered in under 0.3 ms. Even N=1, where only one
  duplicate ACK can ever be sent.
- Why: `tcp_early_rexmt_check` (`tcp_input.c:1491`) lowers the threshold per
  connection to `max(osegs-1, 1)` when fewer than 4 segments are outstanding. The
  threshold drops as fast as we can cap the input, so the sweep can never find a
  step.

The real limit is a count, not a time. Early retransmit gets 10 uses per 60 s
unless SACK is on. 14 losses in a row on one connection:

| Round | 0–9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|
| **no SACK** | 0.054–0.134 ms | **232.7** | **233.4** | **234.7** | **230.4** |
| **SACK** | 0.050–0.155 ms | 0.066 | 0.054 | 0.063 | 0.067 |

- 10 fast, then a cliff. The SACK connection never slows down.
- `TCP_EARLY_REXMT_LIMIT` is 10. The cliff lands on that exact number.
- A timer cannot make a cliff at a count.

## Two predictions were wrong

All predictions were written from the pinned kernel source before any run. Two
failed, and the fixes are the better results.

- **The threshold is not a fixed 3.** It adapts per connection, as above.
- **The RTO floor is ~230 ms, not 300 ms.** `rtt_min`(100) + `rexmt_slop`(200)
  looks like 300. But the slop is added *after* the backoff multiply:
  `RTO = slop + base × backoff[shift]`, and the base is ~30 ms.
- Subtract the slop and `tcp_backoff[]` shows up directly: 1, 2, 1, 2, 4, 8, 16,
  32, 64, 64, 64.

Still open: the leading `1, 2, 1, 2`. Something resets `t_rxtshift` once early in
the ladder. Pinning that to a line needs `bsd/netinet/tcp_timer.h`, which is not
in the reference tree.

## Build and run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j8
(cd build && ctest --output-on-failure)   # 6/6, no root needed
sudo ./scripts/run_all.sh                 # the experiments
```

- Unit tests need no root. They cover the parts that fail silently: sequence
  wraparound, reassembly, TCP option encoding, the loss policy. So you can check
  the measuring code without trusting a `sudo` binary.
- Experiments need root. Creating a `utun` goes through `PF_SYSTEM`.
- `run_all.sh` builds as you, not as root. It writes transcripts to `results/`,
  and checks the sysctls it touched are back to their old values before it exits.
- Every number above comes from `results/`. `run-metadata.txt` records the exact
  kernel build and hardware.

## Layout

```
include/tp/   segment (wire + options), reassembly, policy, peer, utun,
              trace, sysctl, seq, clock, checksum
src/          implementations
tests/        4 suites + 2 ASan/UBSan variants, no root
experiments/  baseline, hol, dupack, rto, challenge_ack, root only
results/      transcripts + kernel/hardware metadata
reference/    pinned XNU sources + RFCs (not committed, see below)
```

## Limits

- **No real network.** `utun` is software, so a round trip is far under a
  millisecond. The RTO numbers are mostly the kernel's floor. `exp_rto` sweeps an
  injected delay to show how much of it is floor.
- **Injected delay is one way**, on our ACKs only. We cannot hold back a packet
  the kernel already handed to `utun`.
- **These numbers are XNU's.** The mechanisms are RFC standard and exist in every
  stack, but the constants do not. Linux arms TLP without needing SACK.
- **No window scale, no timestamps.** So the window caps at 65535, and RTT
  sampling falls back on Karn's algorithm.
- **Loss is chosen, not random.** Good for repeatability. Not a model of real
  loss, and no claim is made about one.
- **We cannot prove the harness never dropped a packet.** If the control socket
  overflows, the frame is gone before `read()` sees it and nothing counts it.
  Instead we track how deep the receive queue actually got, print it on every
  run, and warn if it passes half the buffer.

`reference/` is not committed. To rebuild it, fetch the `bsd/netinet` sources at
the tag in `reference/xnu/VERSION` and `shasum` them against it. A probe once
pulled a wrong tag that looked right.
