# io_uring migration — plan & progress

Started 2026-06-27. Companion to [io_uring-baseline.md](io_uring-baseline.md) (benchmark numbers, before/after).

## Design pivot (2026-06-27) — read this first

The original plan was a **runtime-driver swap**: run `main` under
`tokio_uring::start` (current-thread io_uring reactor) and give the connect
probe uring-native sockets. **That does not compile.** Concretely:

- `tokio_uring::net::TcpStream` is **`!Send`**, and `tokio_uring::spawn` is
  `tokio::task::spawn_local` (panics outside the uring `LocalSet`).
- The framework's `Module` trait returns **`Send`** futures, and the scheduler
  drives them with `tokio::spawn` (which requires `Send`).
- Making `tcp_port_open` await a uring stream turned its future `!Send`, which
  cascaded into **~72 `!Send` trait-bound errors** across the module set.

A true current-thread migration would mean feature-gating the `Send` bound off
the `Module` trait and converting every `tokio::spawn` in the dispatch core to
`spawn_local` — the multi-week, high-risk rewrite flagged at the outset.

**Resolution (what was actually built):** run io_uring on a **dedicated thread**
with its own `tokio_uring` runtime, and bridge to it with a **`Send` channel
API**. Only `SocketAddr` / `Duration` / `Option<bool>` cross the boundary, so
`tcp_port_open` stays `Send` and the modules are untouched. The **main
runtime stays multi-thread** — which is strictly better here: it keeps 12-core
parallelism for bruteforce/PQ crypto *and* adds io_uring for the connect hot
path. This is the io_uring integration that the Send-based architecture allows.

## Plan (the 4 steps) + status

| # | step | files | status |
|---|------|-------|--------|
| 1 | `io_uring` cargo feature + optional `tokio-uring` dep | `Cargo.toml` | ✅ done |
| 2 | Dedicated io_uring connect-service thread (Send channel bridge) | `src/utils/uring_connect.rs`, `src/utils/mod.rs`, `src/main.rs` (reverted to `#[tokio::main]`) | ✅ done |
| 3 | Route mass-scan probe through the ring service; bench measures both paths | `src/utils/network.rs` | ✅ done |
| 4 | CPU-bound work off the single-thread reactor | (design) | ✅ moot by design — see below |
| 5 | Re-run bench, fill AFTER table, compute deltas | `docs/perf/io_uring-baseline.md` | ✅ done |
| 6 | Shard across N hardware-determined rings (round-robin) | `src/utils/uring_connect.rs` | ✅ done |

### Step 4 note

Originally a concern because the swap would have made the *whole app* single-
threaded. With the dedicated-thread design the **main runtime stays
multi-thread**, so all existing CPU-bound work (already wrapped in 92
`spawn_blocking` sites, incl. the bruteforce modules) runs exactly as before.
The only single-thread context is the ring service thread, and it does **pure
network connect I/O — zero CPU crypto**. So nothing serializes; step 4 needs no
code change.

## Architecture (as built)

```
 module run() future (Send, on the multi-thread runtime)
        │  tcp_port_open(ip, port, timeout)
        ▼
 utils::uring_connect::probe(addr, timeout) -> Option<bool>      [Send]
        │  ConnectReq{addr,timeout, oneshot reply}  -> round-robin pick a ring
        ▼
 ┌──── pool of N ring threads, N = available_parallelism() (env-overridable) ────┐
 │ each: tokio_uring::start(loop { rx.recv() -> tokio_uring::spawn(connect) })     │
 │   many concurrent connects per ring; work spread across all cores              │
 └────────────────────────────────────────────────────────────────────────────────┘
        │  Some(true)=open  Some(false)=shut/filtered  None=ring failure
        ▼
 None  ->  self-heal: fall back to tokio tcp_connect_addr()
```

Self-healing: a `None` verdict (service couldn't start, channel closed, or a
ring-level error like a missing connect opcode / EMFILE) makes the caller fall
back to the standard tokio connect, so the ring path can never produce a false
"port closed".

## Build / run matrix

```bash
# default (unchanged): multi-thread tokio, tokio connect
cargo build
cargo test --no-default-features --bin rustsploit

# io_uring connect service (Linux):
cargo build --no-default-features --features io_uring
BENCH_RUN=1 cargo test --no-default-features --features io_uring \
    --bin rustsploit connect_bench -- --nocapture --test-threads=1
```

## Progress log

- 2026-06-27 — baseline captured (`io_uring-baseline.md`); plan written.
- 2026-06-27 — steps 1–3 implemented; hit the `!Send` wall on the runtime-swap
  approach (72 errors), pivoted to the dedicated-thread + Send-bridge design;
  both build configs compiling; step 4 moot by design.
- 2026-06-27 — AFTER benchmark done (see baseline doc). Result: io_uring cut
  **total CPU ~54% / cpu_sys −67%** as predicted; **open-port handshakes +58%
  throughput with zero dropped connects**; **closed-port localhost storm −46%
  wall-clock** (single ring thread vs 12 tokio threads — localhost zero-latency
  is io_uring's worst case). All 5 steps complete; default build unchanged/green.
- 2026-06-27 — **sharded to N rings** (N = `available_parallelism()` = 12 here,
  `RUSTSPLOIT_URING_RINGS` override), round-robin dispatch. Closed-port at the
  hardware default now **123k c/s (+11% vs tokio baseline, cpu_sys −22%)**, i.e.
  the single-ring −46% regression is reversed into a gain; ring-count curve peaks
  ~+30% at 16 rings, oversubscribes past ~24. See baseline doc.
- Follow-up (done 2026-06-30): capped default rings to 16 (peak benchmark throughput).
  Re-bench under real RTT left for future work.
- Follow-up (done 2026-06-30): stream-connect added. RingRequest::Connect dispatches
  full TCP connects on the ring thread; connect_stream_once bridges the !Send
  tokio_uring::net::TcpStream via dup(2) → std::net::TcpStream. tcp_connect_addr
  and tcp_connect_str in network.rs route through io_uring when the feature is
  on and no source port is set. All modules (468 as of v0.5.1) benefit automatically.
