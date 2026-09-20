# tcp_probe

Measures what one lost TCP segment costs the application waiting for it.

A userspace program is one end of a TCP connection over a `utun` interface. The
real kernel stack is the other end and does the sending. We drop segments on
purpose and time how long the data behind the hole takes to arrive. Every
retransmit and timer decision is the kernel's; we only pick what to ACK and when.

## What one lost segment costs

| Arm | App stalls for | Repaired by |
|---|---|---|
| mid-stream loss, no SACK | 0.742 ms | fast retransmit |
| mid-stream loss, SACK | 0.744 ms | fast retransmit |
| **tail loss, no SACK** | **229.6 ms** | retransmit timer |
| **tail loss, SACK** | **2.9 ms** | tail loss probe |

Same 96 KB transfer, same dropped byte, same kernel. The only difference in the
two tail rows is whether our SYN carried the 2-byte SACK-permitted option.
`tcp_output.c:2966` arms the Tail Loss Probe only if SACK was agreed, so without
it a loss at the end of a transfer waits out the full retransmit timeout.

A loss in the middle is cheap either way: segments after it trigger duplicate
ACKs, and the kernel resends without waiting for a timer.

## The "3 duplicate ACKs" rule is wrong

Place the drop so exactly N segments follow it, then sweep N. There is no step at
3. N=1 through N=5 all recover in under 0.3 ms, including N=1, where only one
duplicate ACK can ever be sent. `tcp_early_rexmt_check` (`tcp_input.c:1491`)
lowers the threshold per connection to `max(osegs-1, 1)`, so it falls as fast as
we can cap the input.

The real limit is a count, not a time: 10 uses per 60 s unless SACK is on. 14
losses in a row on one connection:

| Round | 0–9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|
| **no SACK** | 0.054–0.134 ms | **232.7** | **233.4** | **234.7** | **230.4** |
| **SACK** | 0.050–0.155 ms | 0.066 | 0.054 | 0.063 | 0.067 |

`TCP_EARLY_REXMT_LIMIT` is 10 and the cliff lands on it. A timer cannot make a
cliff at a count.

## The RTO floor is 230 ms, not 300 ms

Predictions were written from the pinned kernel source before any run. This one
was wrong. `rtt_min`(100) + `rexmt_slop`(200) looks like 300, but the slop is
added *after* the backoff multiply (`RTO = slop + base × backoff[shift]`) and the
base is ~30 ms. Subtract the slop and `tcp_backoff[]` appears directly: 1, 2, 1,
2, 4, 8, 16, 32, 64, 64, 64.

The leading `1, 2, 1, 2` is unexplained. Something resets `t_rxtshift` once early
on, and pinning that to a line needs `tcp_timer.h`, which is not in the reference
tree.

## Run it

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j8
(cd build && ctest --output-on-failure)   # 6/6, no root
sudo ./scripts/run_all.sh                 # the experiments
```

Unit tests need no root and cover what fails silently: sequence wraparound,
reassembly, TCP option encoding, the loss policy. The experiments need root
because `utun` goes through `PF_SYSTEM`. Transcripts land in `results/` with the
kernel build and hardware in `run-metadata.txt`. Every number above is from there.

## Limits

- `utun` is software, so there is no real network latency. The RTO numbers are
  mostly the kernel's floor; `exp_rto` sweeps an injected delay to show how much.
  The injected delay is one way, on our ACKs only.
- The constants are XNU's. The mechanisms are RFC standard and in every stack,
  but Linux arms TLP without needing SACK.
- Loss is chosen, not random. Repeatable, but not a model of real loss. No
  window scale or timestamps, so the window caps at 65535.
- I cannot prove the harness never dropped a frame: a control socket that
  overflows keeps no counter. Each run instead prints how deep the receive queue
  actually got, and warns if it passes half the buffer.

`reference/` (pinned XNU sources and RFCs) is not committed. Refetch at the tag
in `reference/xnu/VERSION` and `shasum` against it.
