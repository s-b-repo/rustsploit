# io_uring migration — performance baseline (BEFORE)

Captured **2026-06-27**, before any io_uring/tokio-uring work, so the post-migration
run is an apples-to-apples comparison on the same host.

## What is measured

The framework's real connect-probe hot path — the one the mass-scan scheduler
fans out across a sweep:

```
tcp_port_open(ip, port, timeout)  ->  tcp_connect_addr(SocketAddr)  ->  TcpStream::connect
```

(`src/utils/network.rs`). This is the path the io_uring migration is meant to
accelerate (batched connect submission, fewer syscalls per op), so it is the
right thing to baseline.

Two scenarios:

- **closed-port (ECONNREFUSED)** — connect to a reserved-then-released ephemeral
  port. Fast `connect()` → RST, leaves no TIME_WAIT. This is the syscall-bound
  case that dominates a real internet sweep (most ports are shut).
- **open-port (full handshake)** — connect to a live accept loop that drops each
  socket. Exercises the full SYN/SYN-ACK/ACK + close cycle.

## Harness

`#[cfg(test)] mod connect_bench` at the bottom of `src/utils/network.rs`.
Gated on `BENCH_RUN=1` (not `#[ignore]`, which the bad-pattern audit forbids),
so a normal `cargo test` skips it. It builds a multi-thread Tokio runtime
mirroring the app's `#[tokio::main]` (`worker_threads = CPU count`, all drivers
enabled) and reports, per scenario:

| metric      | source                                   | why                                              |
|-------------|------------------------------------------|--------------------------------------------------|
| throughput  | completed attempts / wall-clock seconds  | app-level result the operator feels              |
| cpu_sys     | `/proc/self/stat` stime (all threads)    | per-op **syscall overhead** — what io_uring cuts |
| cpu_user    | `/proc/self/stat` utime                  | userland cost                                    |
| peak_rss    | `/proc/self/status` VmHWM                | catch any memory regression from batching        |

CPU is read from `/proc` (no `libc`/`unsafe`, no `strace`/`perf`/`time -v`,
none of which are installed here). Jiffies → seconds assumes `SC_CLK_TCK = 100`
(standard on this kernel); for before/after the units are identical either way.

### Reproduce

```bash
BENCH_RUN=1 cargo test --no-default-features --bin rustsploit \
    connect_bench -- --nocapture --test-threads=1
# tunables (env): BENCH_CLOSED=30000  BENCH_OPEN=10000  BENCH_CONCURRENCY=1000
```

## Host / toolchain

| | |
|---|---|
| date            | 2026-06-27 |
| cpu             | 13th Gen Intel Core i7-1355U, 12 logical cores |
| kernel          | Linux 6.19.14+kali-amd64 x86_64 |
| rustc / cargo   | 1.95.0 (59807616e 2026-04-14) |
| runtime         | tokio 1.51, multi_thread, worker_threads=12 |
| build           | `--no-default-features` (no Bluetooth), dev/test profile (unopt + debuginfo) |
| ephemeral ports | 32768–60999 |
| tcp_tw_reuse    | 2 |

> Note: dev/test profile is **unoptimized**. A `--release` baseline will show
> higher absolute numbers; keep the profile identical when measuring the AFTER.

## Results — BEFORE (tokio multi-thread, 3 runs)

### closed-port ECONNREFUSED — 30,000 attempts, concurrency 1000

| run | elapsed | throughput   | cpu_user | cpu_sys | peak_rss |
|-----|---------|--------------|----------|---------|----------|
| 1   | 0.266s  | 112,738 c/s  | 0.47s    | 1.20s   | 49,976 kB |
| 2   | 0.271s  | 110,794 c/s  | 0.43s    | 1.28s   | 49,140 kB |
| 3   | 0.277s  | 108,237 c/s  | 0.50s    | 1.19s   | 49,476 kB |
| **median** | **0.271s** | **110,794 c/s** | **0.47s** | **1.20s** | **~49.5 MB** |

### open-port full handshake — 10,000 attempts, concurrency 1000

| run | elapsed | throughput | cpu_user | cpu_sys | opened | peak_rss |
|-----|---------|------------|----------|---------|--------|----------|
| 1*  | 4.024s  | 2,485 c/s  | 0.26s    | 1.09s   | 9,192  | 49,976 kB |
| 2   | 2.010s  | 4,974 c/s  | 0.49s    | 1.03s   | 9,635  | 49,140 kB |
| 3   | 2.015s  | 4,962 c/s  | 0.34s    | 0.84s   | 9,668  | 49,476 kB |
| **median (2–3)** | **2.01s** | **~4,968 c/s** | **~0.42s** | **~0.94s** | **~9,650** | **~49.5 MB** |

\* Run 1 is a cold-start outlier (first handshake batch + TIME_WAIT churn from the
preceding closed run); runs 2–3 are the steady state. `opened < 10000` is expected:
some connects overflow the single accept loop's backlog (SOMAXCONN) and get reset —
they still count as completed attempts for throughput. This is constant across
before/after so it does not affect the comparison.

## Interpretation — what the AFTER should move

- **closed-port path is syscall-bound:** sys CPU (~1.20s) is ~2.6× user CPU
  (~0.47s) — ~72% of CPU is in the kernel, ~40 µs of sys CPU per connect attempt.
  This is the headroom io_uring targets: batching connect SQEs should cut the
  per-op syscall count and drop **cpu_sys** the most.
- **Primary success metrics for the migration:**
  1. lower **cpu_sys** per attempt (syscalls amortized by the ring),
  2. equal-or-higher **throughput** — note the io_uring runtime is *current-thread*
     (1 thread) vs this multi-thread (12) baseline, so watch whether one
     ring-driven thread matches 12 reactor threads,
  3. no regression in **peak_rss**.

## Results — AFTER (io_uring connect service, 3 runs)

Identical harness/host/profile; main runtime still multi-thread, but
`tcp_port_open` now routes the probe to the dedicated io_uring ring thread
(`utils::uring_connect`). Label: `tokio mt x12 + io_uring connect service`.

### closed-port ECONNREFUSED — 30,000 attempts, concurrency 1000

| run | elapsed | throughput  | cpu_user | cpu_sys | peak_rss |
|-----|---------|-------------|----------|---------|----------|
| 1   | 0.506s  | 59,294 c/s  | 0.36s    | 0.40s   | 55,416 kB |
| 2   | 0.494s  | 60,763 c/s  | 0.30s    | 0.44s   | 56,016 kB |
| 3   | 0.572s  | 52,415 c/s  | 0.44s    | 0.40s   | 55,452 kB |
| **median** | **0.506s** | **59,294 c/s** | **0.36s** | **0.40s** | **~55.5 MB** |

### open-port full handshake — 10,000 attempts, concurrency 1000

| run | elapsed | throughput | cpu_user | cpu_sys | opened | peak_rss |
|-----|---------|------------|----------|---------|--------|----------|
| 1   | 1.278s  | 7,825 c/s  | 0.20s    | 0.56s   | 10,000 | 55,416 kB |
| 2   | 1.143s  | 8,750 c/s  | 0.18s    | 0.41s   | 10,000 | 56,016 kB |
| 3   | 1.393s  | 7,180 c/s  | 0.34s    | 0.54s   | 10,000 | 55,452 kB |
| **median** | **1.278s** | **7,825 c/s** | **0.20s** | **0.54s** | **10,000** | **~55.5 MB** |

## Before → after deltas

| scenario | metric | before | after | Δ |
|----------|--------|--------|-------|---|
| closed-port | throughput | 110,794 c/s | 59,294 c/s | **−46%** |
| closed-port | **cpu_sys** | 1.20s | 0.40s | **−67%** |
| closed-port | cpu_user | 0.47s | 0.36s | −23% |
| closed-port | total CPU | 1.67s | 0.76s | **−54%** |
| open-port | throughput | 4,968 c/s | 7,825 c/s | **+58%** |
| open-port | cpu_sys | 0.94s | 0.54s | −43% |
| open-port | completion | 9,650 / 10k | 10,000 / 10k | **no dropped connects** |
| both | peak_rss | ~49.5 MB | ~55.5 MB | +12% (ring thread + ring buffers) |

## Interpretation — what actually happened

The prediction held on **CPU/syscalls** and split on **wall-clock**:

- **io_uring slashed kernel time as expected** — `cpu_sys` −67% (closed) / −43%
  (open), total CPU roughly halved. The ring genuinely amortizes the per-connect
  syscalls. That was the whole thesis, and it's confirmed.
- **Real connections got faster *and* more reliable** — open-port handshakes
  **+58% throughput** and **0 dropped connects** (10,000/10,000 vs ~9,650 before).
  When a connect has real work to do, one ring driving thousands of concurrent
  ops beats 12 epoll threads.
- **The cheap closed-port refused storm regressed on wall-clock (−46%)** even
  though it used **half the CPU**. Reason: every probe now funnels through **one**
  ring thread (vs 12 tokio worker threads) plus a per-probe channel round-trip.
  For a zero-latency localhost `connect()→RST`, that single-thread dispatch is the
  bottleneck — this localhost test is the *worst case* for io_uring (no network
  latency to hide behind) and the *best case* for multi-thread tokio.

**Caveat for the real use case:** a real internet sweep has RTT latency per
connect, so thousands of connects sit in-flight on the ring concurrently and the
single-thread dispatch stops being the limiter — the −46% localhost figure
overstates the downside there, while the −54% CPU and the +58%/zero-drop
handshake behavior carry over. To confirm on real latency, re-run against a
high-RTT target (or `tc qdisc add ... netem delay 50ms`) — left as follow-up.

**Knobs if pursuing the closed-port case:** shard probes across a pool of ring
threads to recover multi-core throughput while keeping the CPU win. **This was
implemented** — see below.

## Results — AFTER, sharded (multi-ring, hardware-determined)

The single ring was the closed-port bottleneck, so the service was changed to a
**pool of N ring threads** (one io_uring ring each), round-robin dispatch, with
**N = `available_parallelism()`** (12 here), overridable via
`RUSTSPLOIT_URING_RINGS`. Label: `tokio mt x12 + io_uring x12 rings`.

### closed-port ECONNREFUSED — 30,000 attempts, 12 rings (hardware default), 3 runs

| run | elapsed | throughput   | cpu_user | cpu_sys | peak_rss |
|-----|---------|--------------|----------|---------|----------|
| 1   | 0.294s  | 102,012 c/s  | 0.55s    | 0.96s   | 57,328 kB |
| 2   | 0.241s  | 124,583 c/s  | 0.53s    | 0.93s   | 58,500 kB |
| 3   | 0.244s  | 123,187 c/s  | 0.57s    | 0.86s   | 57,908 kB |
| **median** | **0.244s** | **123,187 c/s** | **0.55s** | **0.93s** | **~58 MB** |

(Open-port under sharding is **acceptor-bound** — 12 rings overrun the test's
single accept loop's SYN backlog, causing drops/retries — so it is not a clean
signal here. A real sweep hits distinct hosts, so there is no shared-acceptor
bottleneck.)

### Ring-count scaling (closed-port, 30k attempts)

| rings | closed-port throughput | note |
|-------|------------------------|------|
| 1     | ~36–59k c/s            | single ring = the −46% regression |
| 2     | ~82–95k c/s            | |
| 4     | ~96–100k c/s           | |
| 8     | ~97–118k c/s           | ≈ tokio baseline |
| **12 (= cores, default)** | **~110–124k c/s** | **beats tokio baseline** |
| 16    | ~134–146k c/s          | peak (+25–30% vs tokio) |
| 24    | ~107–112k c/s          | oversubscribed (>2× cores w/ main rt), regresses |

### Sharded deltas vs the original tokio baseline

| metric | tokio baseline | io_uring ×12 rings | Δ |
|--------|----------------|--------------------|---|
| closed-port throughput | 110,794 c/s | 123,187 c/s | **+11%** |
| closed-port cpu_sys | 1.20s | 0.93s | **−22%** |
| closed-port throughput vs single-ring | 59,294 c/s | 123,187 c/s | **+108%** |

**Conclusion:** at the hardware-determined default (rings = CPU count), io_uring
**beats** the multi-thread-tokio baseline on the closed-port connect storm on
*both* throughput (+11%) and kernel CPU (−22%), and there is headroom above
(≈16 rings peaks ~+30%). The earlier single-ring localhost regression was a
dispatch-serialization artifact, now resolved by sharding. CPU per op stays at
or below tokio across the whole curve until oversubscription (>2× cores).
