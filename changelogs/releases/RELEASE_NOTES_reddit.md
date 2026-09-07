 Rustsploit update: ported Recog, JARM/JA3, the official MCP SDK + a SecLists catalog — and a cautionary tale about letting agents write tests

Rustsploit is a Rust offensive-security framework (RouterSploit/Metasploit-style) — one binary, ~389 self-registering modules, exposed through an interactive shell, a CLI runner, a PQ-encrypted REST/WS API, and an MCP server.

This release ports four upstream projects in (all permissively licensed) and fixes a pile of mass-scan UX/correctness bugs. The writeup's a bit long because the interesting part isn't the features — it's what didn't ship.

 Ports

- MCP server → official `rmcp` SDK (v1.7). Ripped out ~350 lines of hand-rolled JSON-RPC-over-stdio and dropped in the official Rust MCP SDK. All 29 tools + 7 resources kept; `server.rs` is now just a `ServerHandler` adapter mapping our existing tool/resource types to rmcp's. The tool logic didn't change at all — the SDK owns protocol framing, transport, and version negotiation now. Validated with a live `initialize` + `tools/list` handshake over stdio.
- Recog (Rapid7, BSD-2). XML fingerprint DB loader + matcher (regexes pre-compiled behind `once_cell::Lazy`), wired into the service scanner so banners resolve to real product/version/CPE instead of substring guesses.
- JARM + JA3/JA3S (Salesforce, BSD-3). 10 hand-crafted TLS ClientHellos sent over a raw tokio socket → 62-char JARM hash; plus JA3/JA3S string builders + MD5. The ServerHello parser is fully bounds-checked (returns `None` on garbage, never panics).
- SecLists (MIT). Seeded the previously-empty, checksum-pinned wordlist catalog with 6 curated entries; `resolve()` downloads + SHA-256-verifies on first use.

 The cautionary tale

I had isolated subagents do most of the porting. They couldn't run the test harness in their sandbox — so they shipped tests they had never executed. When I finally ran the suite: 7 failures.

- 3 JA3/JA3S "known vector" tests had fabricated MD5 constants. The implementation was actually correct — `md5sum` of the JA3 string matched what the code produced. The agent just made up the expected hashes and asserted against them.
- 4 Recog tests exposed a real matcher bug: a `<param>` carrying both a `value` template and a `pos` attribute stored the bare capture group instead of the interpolated CPE (so `cpe23` came out as `"1.3.5b"` instead of `"cpe:/a:proftpd:proftpd:1.3.5b"`). Plus a MariaDB regex that rejected a colon in the distro suffix.

Caught and fixed all 7. The lesson is blunt: "the agent says the tests pass" is worth nothing if the agent never ran them. Generated tests are a liability until something actually executes them.

 The judgment call

The curated Recog DBs the agent hand-authored are small. The obvious "win" was swapping in the full Rapid7 set (~1,024 fingerprints). I tried it — 13/20 tests instantly failed, and not because the tests were wrong:

- Real Recog SSH patterns anchor on the version comment (`^OpenSSH_(...)$`) — they expect the substring after `SSH-2.0-`, not the full banner line the scanner currently feeds them.
- Real field values differ (Apache → `service.product = "HTTPD"`, not the curated `"HTTP Server"`).

So adopting the full DBs is a per-DB input-normalization layer, not a data swap. Shipping them as-is would have silently broken matching end-to-end (raw banners vs. normalized-input patterns → zero matches in practice). Reverted, kept the internally-consistent curated DBs, and wrote the real design up as a future feature instead of shipping something that looked done.

 Perf

~300 sites construct reqwest clients; 184 go through one helper that rebuilt a fresh client every call — re-initializing the TLS config and allocating a new empty connection pool each time (i.e. once per host in HTTP mass scans). Cached it by `(timeout, tls-strictness)` and hand out `Arc` clones, so the pool + TLS setup are reused across runs. Keyed on tls-strictness so toggling strict-TLS at runtime still takes effect. Bounded the idle timeout on the shared client so long sweeps don't pile up idle keepalives.

 Final state

Clean build (0 warnings), 40/40 tests green, bad-patterns lint clean on every changed file.

Happy to answer questions about the rmcp migration or the Recog matcher specifically.
