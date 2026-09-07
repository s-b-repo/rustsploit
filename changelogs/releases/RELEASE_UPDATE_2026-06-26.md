Rustsploit June 2026 Update: The Open-Source Rust Penetration Testing Framework Adds an MCP Server, TLS Fingerprinting, and Hydra-Style Brute Forcing

Rustsploit is a free and open-source offensive security framework written in Rust and inspired by Metasploit and RouterSploit. It ships as a single binary that exposes the same library of 389 security modules through four interfaces: an interactive console, a command-line runner, a post-quantum-encrypted REST and WebSocket API, and a Model Context Protocol (MCP) server for AI assistants and agents. This release was merged on June 26, 2026, and pulls together months of new modules, real performance gains, and a deep correctness audit of the credential-testing engine. The whole project builds clean, with zero errors and zero warnings.

If you are looking for a modern, memory-safe alternative to Metasploit or RouterSploit for network scanning, service fingerprinting, vulnerability exploitation, and password auditing, this update is a big step forward.


What Is New at a Glance

- Four well-known security tools were ported in: the official MCP Rust SDK, Rapid7 Recog service fingerprinting, Salesforce JARM and JA3 TLS fingerprinting, and a SecLists wordlist catalog.
- The brute-force engine reached feature parity with Hydra and Medusa, with charset masks, combo files, resume support, and per-username password rules.
- Every credential-testing module was audited for accuracy, removing false-positive logins, fixing lockout misclassification, and recovering valid credentials that were being missed.
- Mass scanning across the entire public internet is faster and safer, with smarter host caps, exclusions, and retry-and-continue behavior.
- The core framework was hardened against crashes, silent errors, and data leaks between tenants.


New Fingerprinting and Protocol Engines (All Permissively Licensed)

- Official MCP server using the rmcp SDK (version 1.7, Apache 2.0). The old hand-written JSON-RPC-over-stdio server was replaced with a thin adapter on top of the official Model Context Protocol Rust SDK. All 29 tools and 7 resources are kept, along with the per-call timeout and the standard-output isolation guard. This makes Rustsploit a reliable backend for AI agents and assistants.
- Recog service and version fingerprinting from Rapid7 (BSD 2-Clause). A new XML fingerprint-database loader and matcher resolves raw network banners into real product, version, and CPE identifiers, wired directly into the service scanner.
- JARM, JA3, and JA3S TLS fingerprinting from Salesforce (BSD 3-Clause). Ten hand-crafted TLS ClientHello probes are sent over a raw socket to build the standard 62-character JARM hash, plus JA3 and JA3S client and server fingerprints. A new scanner module, jarm scan, reports all three on port 443.
- SecLists wordlist catalog (MIT). Six popular password, username, web-content, and subdomain lists are pinned by SHA-256 checksum and verified automatically on first download.


New and Updated Exploit and Scanner Modules

- WhisperPair (CVE-2025-36911), the Google Fast Pair Bluetooth attack, was rebuilt into a full module directory covering the cryptography, device database, GATT layer, and protocol, including a dataset of device model identifiers.
- A complete H3C baseboard management controller suite: firewall checks, IPMI hash extraction, KVM probing, Redfish data dumps, and CloudOS API enumeration.
- Fortinet SSL-VPN and the FortiOS magic-token vulnerability (CVE-2018-13382).
- Microsoft SharePoint document harvesting, Microsoft 365 ActiveSync password spraying, and Active Directory LDAP anonymous spraying.
- Additional web application modules for PHP, Git exposure, and Apache Tapestry.


A Brute-Force Engine With Hydra and Medusa Feature Parity

The shared brute-force engine and credential helper gained the high-value features that power users expect from Hydra and Medusa. Everything is controlled through simple global settings and shown in the options table.

- Extra password rules (the Hydra dash-e nsr option): for each username you can also try an empty password, the username itself as the password, and the reversed username. This is opt-in and automatically de-duplicated against built-in defaults.
- Wordlists are now optional when a module already ships sensible defaults. A scan with no wordlist set will simply run the defaults instead of failing on every host.
- Combo-file support (the Hydra dash-C option): load a user-and-password pairs file, with an exclusive mode that uses only that file and ignores other wordlists.
- Charset mask brute forcing (the Hydra dash-x option): generate password candidates from a minimum length, maximum length, and character set, with a safety cap.
- Stop modes that match Hydra and Medusa behavior: stop the whole host on the first success, stop per username once its password is found, or keep going to find every valid credential.
- Configurable connection retries (the Medusa dash-r option) for transient and connection errors.
- Configurable delay and jitter between attempts (the Hydra dash-w option) to control speed and avoid lockouts.
- Resumable large-wordlist runs: progress is checkpointed in batches so an interrupted scan picks up where it left off and clears the marker on a clean finish.
- Smarter lockout handling: a host is abandoned after repeated lockout pauses with no success, the give-up decision now carries across batches, and per-host concurrency is capped during mass scans so the tool never runs out of network sockets.
- A memory fix: stopping on the first success no longer leaks a background reader that kept scanning a multi-gigabyte wordlist in the background.


A Top-to-Bottom Credential Testing Accuracy Audit

Every brute-force and credential module was reviewed by hand. The result is far fewer false results and far more real ones.

False-positive logins removed (cases where a wrong password was being saved as a valid credential):

- SNMP now structurally parses the response and requires a proper GetResponse message instead of matching a stray byte.
- HTTP and SOCKS proxy checks now parse the real status line rather than matching the number 200 anywhere in the response.
- Elasticsearch now confirms that an unauthenticated request is actually rejected before trusting any login, so an open node no longer reports every password as valid.
- CouchDB now requires a genuine success body, and Memcached validates a real authentication reply.
- L2TP, HTTP Basic auth, and the sample credential check now baseline the unauthenticated response before trusting a result.
- VNC now negotiates the correct RFB protocol version, fixing a handshake desync that reported empty passwords as valid.
- The Fortinet FortiOS check (CVE-2018-13382) now confirms a real login with the new password before flagging a host as vulnerable, so patched devices are no longer reported as exploitable.
- The H3C Redfish and KVM modules now require a real authentication token instead of a placeholder.

Lockout misclassification fixed (cases where a clear negative from a live server was treated as a retryable error, which made responding hosts look dead and triggered long pauses):

- RTSP now reads the real status code, so a wrong stream path returning 404 is treated as a clean negative instead of an error.
- FTP, MySQL, and HTTP Basic auth now correctly classify definitive rejection responses.

Valid credentials recovered (cases where real logins were being missed):

- PostgreSQL now connects to the maintenance database, so a valid superuser is no longer rejected.
- SSH brute forcing and spraying now only treat a true authentication failure as a wrong password, and SSH spraying now resolves hostnames instead of requiring raw IP addresses.
- Microsoft 365 ActiveSync now recognizes valid-but-flagged accounts (expired, disabled, multi-factor required, conditional access) as real credential hits.

SSH username enumeration was rewritten to use a statistical timing baseline instead of a fixed threshold, timing only the authentication step, which removes most of the noise and false results.


Faster and Safer Internet-Wide Mass Scanning

- Typing a full-internet target now reliably scans every public host instead of silently stopping at ten thousand on one code path.
- The full-sweep confirmation prompt now runs before any work begins, and the placeholder host used to collect your answers is no longer scanned.
- Service-scanner output in mass scans no longer floods the console or races to overwrite the same results file.
- The scheduler now applies exclusion lists and a service-port pre-check on range and file scans, with accurate counts of hosts considered and skipped.
- Mass scanning works the same way across all four interfaces, including a background-job option for the MCP server so very long scans do not time out.
- The options table now shows the previously hidden settings for scan order, exclusions, and rate limits.


Core Framework Hardening and Reliability

- Retry and continue: every per-host scan retries once on a transient failure and then carries on, so a single bad host never aborts a whole sweep.
- Crash fixes: the shell auto-completer no longer panics on multi-byte characters, and internal fan-out errors are reported cleanly instead of crashing.
- A WebSocket framing bug that could permanently break an encrypted connection now closes the connection cleanly instead.
- MCP background jobs can now be listed and stopped correctly per tenant, and invalid port or option values are rejected with a clear message.
- Server-side request forgery protection now clearly separates a blocked internal target from a normal target error, and fails safely by default.
- Stored credentials, loot, and workspace data are de-duplicated and scrubbed, and tenants are isolated so one user's data never leaks into another's.
- A sweep of the whole codebase removed silently swallowed errors, so failures are now logged and surfaced instead of hidden.
- Dead code was removed, including the old non-destructive check subsystem, an unused output accumulator, and a no-op output-format flag.


Performance Improvements

- The HTTP client is now cached and shared instead of being rebuilt for every request. Warm connections and TLS setup are reused across runs, which is a major speedup during HTTP-based mass scans. Idle connections are reaped automatically so long internet-wide sweeps do not pile up stale connections.


Better Output and Everyday Usability

- Automatic per-run output saving: every console and command-line run now appends all of its output to a timestamped results file under the loot folder, so multi-host scan results accumulate in one place instead of overwriting each other.
- The shell no longer prints a confusing error on first launch when the command-history file does not exist yet.


Build and Housekeeping

- The dependency lock file was restored so a fresh clone builds correctly out of the box.
- A gitignore file was added to keep build artifacts, local configuration, and engagement data out of the repository.
- The documentation was corrected to reflect the current exploitation-only design and the compile-time module registration system.


Open-Source Licenses for Ported Components

Recog is BSD 2-Clause, JARM and JA3 are BSD 3-Clause, the rmcp MCP SDK is Apache 2.0, SecLists is MIT, and the ZMap address iterator is Apache 2.0. Rustsploit itself remains free and open source.
