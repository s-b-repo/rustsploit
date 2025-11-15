Hardened rtsp_bruteforce_advanced by validating path, username, and password wordlists before spinning up tasks, and by falling back to a safe root path when a path list is empty to avoid runtime panics.

Added identical early-exit checks and trimming for the SSH brute-force runner so it fails fast when wordlists are empty instead of silently doing nothing.

Brought the FTP brute-force helper in line with the others by trimming entries, rejecting empty wordlists, and ensuring helper utilities only return meaningful credentials.


Proxy Improvements

Refined proxy loading to validate schemes/hosts/ports, capture parse errors, and expose optional connectivity testing via utils::load_proxies_from_file and utils::test_proxies, keeping only working entries when requested.

Enhanced shell commands: proxy_load now prompts for a path when omitted, reports skipped entries, offers a recommended “test proxies” prompt, and added a dedicated proxy_test command plus reusable prompt helpers.

Implemented interactive proxy-test workflow that gathers URL/timeouts/concurrency, filters failing proxies, and auto-disables proxy mode when none survive.


Shell UX Refresh
Reworked command parsing to support ergonomic aliases (help/h/?, modules/ls/m, find/f1, proxy_load/pl, etc.) and keep everything case-insensitive and whitespace tolerant.

Added a richer, colorized help palette that lists shortcuts and usage tips so “f1 ssh” style workflows are obvious.

Introduced helpers (split_command, resolve_command) to drive the new UX without changing existing behavior, plus guarded prompt utilities already in place.


README Refresh

Rebuilt the README into a professional GitHub-ready document with a TOC, feature highlights, module catalog summary, quick start commands, shell walkthrough (including the new shortcuts), CLI usage, proxy workflow, module discovery flow, and contributing/credits notes.

README Suite Updated

README.md already reflects the full feature set; no further changes needed.
docs/readme.md rewritten into a comprehensive developer guide covering architecture, module discovery, shell internals, proxy system, authoring practices, and roadmap items.
lists/readme.md expanded to document shipped wordlists, usage guidelines, and contribution notes so operators know how data files tie into modules.

Pingsweep.rs 

improved and reworked


Added an API launch mode to RustSploit with the requested features.
Features implemented
API launch mode: --api flag to start the API server
API key authentication: --api-key flag (required when using --api)
Dynamic API key rotation: manual via /api/rotate-key endpoint and automatic when hardening triggers
Hardening mode: --harden flag enables IP-based protection
Auto-rotation: when unique IPs exceed the limit (default: 10), the API key auto-rotates
Notifications: alerts in terminal and log file (rustsploit_api.log in the same directory)
Interface selection: --interface flag (defaults to 0.0.0.0), supports IP/interface or full address with port
API endpoints
GET /health - Health check (no auth required)
GET /api/modules - List all available modules
POST /api/run - Run a module on a target
GET /api/status - Get API server status
POST /api/rotate-key - Manually rotate the API key

Usage examples
# Basic API server on 0.0.0.0:8080./rustsploit --api --api-key my-secret-key# With hardening enabled (auto-rotate on >10 unique IPs)./rustsploit --api --api-key my-secret-key --harden# Custom interface and IP limit./rustsploit --api --api-key my-secret-key --harden --interface 127.0.0.1 --ip-limit 5# Custom port./rustsploit --api --api-key my-secret-key --interface 0.0.0.0:9000

Security features
API key authentication on all protected endpoints
IP tracking and monitoring
Automatic key rotation when suspicious activity is detected
Logging to both terminal and file for audit trails
IP limit enforcement with configurable thresholds

All IpTracker fields are used:
ip: Used in logging, status endpoint, and the new /api/ips endpoint
first_seen: Used in logging to show when IP was first detected, and in both endpoints
last_seen: Used in status and /api/ips endpoints
request_count: Used in logging and both endpoints
New endpoint added: /api/ips - Returns all tracked IP addresses with full details including all fields
Enhanced get_status endpoint: Now includes detailed IP tracking information with all fields from each IpTracker
Enhanced track_ip method: Now logs detailed information using all fields, including duration calculations
Added serde feature to chrono: Enables DateTime<Utc> serialization
All routes properly wired: The new /api/ips endpoint is added to the protected routes
The code should compile without any dead code warnings. All fields are actively used in:
Logging operations
API responses
Status reporting
IP tracking calculations



Added authorization rate limiting with the following features:
Rate limiting logic:
Tracks failed authentication attempts per IP
Blocks IPs for 30 seconds after 3 failed attempts
Automatically resets the counter after the block period expires
Resets the counter on successful authentication
New AuthFailureTracker struct:
ip: IP address being tracked
failed_attempts: Number of failed attempts
first_failure: Timestamp of first failure
blocked_until: Timestamp when block expires (if blocked)
Enhanced auth middleware:
Checks rate limit before processing authentication
Records failures when invalid keys are provided
Resets counter on successful authentication
Returns 429 Too Many Requests when blocked
Logging:
Logs all rate limit events to terminal and log file
Shows remaining block time
Tracks duration since first failure
New API endpoint:
GET /api/auth-failures - Returns all IPs with authentication failures and their status
Enhanced existing endpoints:
/api/ips now includes auth failure information for each IP

Updated Files
1. README.md


Added API Server Mode to the table of contents
Added REST API Server to highlights
Added an API Server Mode section with:
Starting the API server (cargo commands)
API flags table
All endpoints with curl examples
Security features (rate limiting, hardening, logging)
Example workflow
2. docs/readme.md (Developer Guide)
Added API Server Architecture to the table of contents
Updated code layout to include api.rs
Added an API Server Architecture section with:
Architecture overview
State management details
Authentication middleware explanation
Rate limiting and hardening mode details
Key components with code examples
API endpoints list
Logging information
CLI usage examples
Documentation Highlights
The docs now include:
Cargo commands for starting the API server
All available flags (--api, --api-key, --harden, --interface, --ip-limit)
Complete endpoint documentation with curl examples
Security features explanation (rate limiting, hardening, logging)
Architecture details for developers
Example workflows


Improving build.rs with better error handling, short name support, sorting, and other enhancements:
build.rs


Removing the unused import:
build.rs


Improvements
Error handling
Replaced .unwrap() with Result types
Clear error messages with context
Validates directory existence before processing
Short name support
Generates match arms for both short names (e.g., port_scanner) and full paths (e.g., scanners/port_scanner)
Matches the pattern used in the generated dispatcher files

Deterministic output
Sorts mappings and directory entries for consistent builds
Easier to review generated code in version control
Deduplication
Uses HashSet to avoid duplicate module registrations
Documentation
Added doc comments explaining the script's purpose and behavior
Regex
More flexible pattern that handles different parameter names (e.g., target, _target)
Code organization
Uses a vector of tuples to iterate over categories, reducing duplication
More maintainable structure

Verbose mode
Optional verbose warnings via RUSTSPLOIT_VERBOSE_BUILD environment variable
Reduces noise during normal builds
Better path handling
More robust path operations with proper error handling
Handles edge cases better
Output quality
Adds header comments to generated files
Includes documentation in generated code
Better formatted output
The build script is now more robust, maintainable, and feature-complete. It should handle edge cases better and provide clearer feedback during the build process.


ping_sweep.rs improvements
Progress reporting: real-time progress with percentage, hosts up count, and scan rate
Parallel TCP probing: ports are probed in parallel for better performance
Better ICMP detection: detects and uses the correct ping command (ping vs ping6, handles IPv6 with -6 flag)
Error handling: clearer error messages when ping commands are missing
Progress cleanup: clears progress line at completion for cleaner output


ssdp_msearch.rs improvements
Multiple search targets: supports upnp:rootdevice, ssdp:all, and custom ST values
Configurable timeout: user can set timeout (default 3 seconds)
Retry logic: configurable retries (default 1, max 10) with delays between attempts
Verbose mode: optional verbose output showing requests and detailed errors
Enhanced response parsing: extracts additional SSDP headers (ST, NT, Cache-Control, EXT)
Better error handling: proper error context and messages throughout
Larger buffer: increased from 2048 to 4096 bytes for larger SSDP responses
User-Agent header: adds RustSploit user-agent to requests
Better output formatting: improved response display with additional header information
Both modules now have:
Better error handling
More features and configurability
Improved performance
Better user experience with progress indicators and verbose modes
More robust cross-platform support



Created Files:

src/modules/exploits/flowise/cve_2025_59528_flowise_rce.rs - Main exploit module
src/modules/exploits/flowise/mod.rs - Module registration file
Updated src/modules/exploits/mod.rs - Added flowise module


Features:
Banner display - ASCII art banner matching the original Python version
Interactive prompts - Prompts for email, password, and command (like other modules)
Authentication - Login functionality with proper headers
RCE execution - Executes commands via the customMCP endpoint vulnerability
Error handling - Proper error handling with colored output
Cookie support - Uses reqwest's cookie store to maintain session
401 retry logic - Automatically retries with internal header if needed
Framework Integration:
The module is automatically detected by the framework's build script (build.rs) because it:
Exports pub async fn run(target: &str) -> Result<()>
Is located in src/modules/exploits/flowise/
Is registered in the mod.rs files
The module will be available as:
flowise/cve_2025_59528_flowise_rce (full path)
cve_2025_59528_flowise_rce (short name)



 panos module
Added improvements from the new version:
Better error handling with Context for more informative error messages
Enhanced file reading that filters empty lines and comments (lines starting with #)
Colored output:
Yellow for testing/info messages
Green for vulnerable findings
Red for errors/not vulnerable
Cyan for headers and vulnerable URLs
Better feedback messages showing what's being tested
Summary statistics showing vulnerable count for batch scans
Proper error propagation with ? operator


Flowise RCE Module (CVE-2025-59528)

Location: src/modules/exploits/flowise/cve_2025_59528_flowise_rce.rs
Status: Fully implemented
Has pub async fn run(target: &str) -> Result<()> signature
Registered in src/modules/exploits/flowise/mod.rs
Listed in src/modules/exploits/mod.rs

Features:

Banner display
Interactive prompts (email, password, command)
Login functionality
RCE execution via customMCP endpoint
Error handling with colored output
Cookie-based session management
401 retry logic

Framework Integration:

Auto-discovered by build script
Available as: flowise/cve_2025_59528_flowise_rce or cve_2025_59528_flowise_rce
HTTP/2 Rapid Reset DoS Module (CVE-2023-44487)
Location: src/modules/exploits/http2/cve_2023_44487_http2_rapid_reset.rs
Status: Fully implemented
Has pub async fn run(target: &str) -> Result<()> signature
Registered in src/modules/exploits/http2/mod.rs
Listed in src/modules/exploits/mod.rs

Features:

Banner display with legal disclaimer
Interactive prompts (port, SSL, streams, delay, baseline)
Baseline test functionality
Rapid reset attack implementation
Vulnerability analysis with risk assessment
IPv6 support
SSL/TLS support via tokio-rustls
Error handling with colored output

Framework Integration:

Auto-discovered by build script
Available as: http2/cve_2023_44487_http2_rapid_reset or cve_2023_44487_http2_rapid_reset

Dependencies Added:

h2 = "0.3" - HTTP/2 protocol implementation
tokio-rustls = "0.24" - Async TLS support
http = "1.0" - HTTP types


Implementation status
Module structure:
Exported in src/modules/exploits/http2/mod.rs
Auto-discovered by the build script (registered as http2/cve_2023_44487_http2_rapid_reset)
Core functions:
banner() — displays module banner
normalize_host() — handles IPv6 address formatting
baseline_test() — performs baseline HTTP/2 requests (SSL and non-SSL)
rapid_reset_test() — performs the rapid reset attack test (SSL and non-SSL)
run() — main entry point with interactive prompts
Features:
SSL/TLS support with proper certificate handling
Non-SSL support for plain HTTP/2
Baseline testing before the attack
Rapid stream creation and reset
Vulnerability analysis with risk assessment
Interactive configuration (port, SSL, streams, delay)
Legal disclaimer and permission check
Fixes applied:
Fixed http version conflict (0.2 to match h2)
Added bytes dependency
Fixed type inference for handshake calls
Fixed send_request API usage
Fixed send_reset return type handling
Removed unused mut keywords
Consistent TLS configuration
Code quality:
No linter errors
No warnings
Proper error handling
Clean code structure
The module is ready to use. You can run it via:
Interactive shell: run exploits/http2/cve_2023_44487_http2_rapid_reset <target>
Or the short form: run http2/cve_2023_44487_http2_rapid_reset <target>



Updated packages
All dependencies now use version ranges (e.g., "0.12" instead of "0.12.15"), allowing Cargo to fetch the latest patch versions.
Kept compatible versions for:
h2 = "0.3" (upgrading to 0.4 would require http 1.0+ and code changes)
http = "0.2" (required by h2 0.3)
tokio-rustls = "0.24" (compatible with current setup)
Updated to latest ranges:
reqwest = "0.12" (was 0.12.15)
tokio = "1.44" (was 1.44.2)
clap = "4.5" (was 4.5.35)
rustls = "0.23" (was 0.23.26)
bytes = "1.0" (was 1.0)
And all other packages



Improved http_title_scanner to be more robust and flexible:
Added interactive workflow: collects initial target, optional comma-separated list, and/or file-based target list.
Lets you choose whether to probe HTTP, HTTPS, or both; validates choices and prompts for timeout, verbosity, and optional report saving.
Uses a shared reqwest client with user-agent, redirect limit, and configurable timeout; extracts titles via an improved regex, sanitizes output, and captures status/timing details.
Handles errors gracefully, prints concise or verbose output, and writes an optional timestamped report (http_title_scan_YYYYMMDD_HHMMSS.txt) with per-target results.
Removed dead code and ensured no unwrap panics on network paths.


Added input validation and sanitization to the API:
New validation helpers:
sanitize_for_log: strips CR/LF/tab and truncates long values before logging
validate_api_key_format: length and ASCII checks
validate_module_name: allows only expected forms (exploits|scanners|creds/... with safe chars)
validate_target: basic length, printable ASCII, trimmed, and injection-safe checks
Applied protections:
Middleware now rejects malformed API keys early
run_module validates module and target before dispatch; logs use sanitized values
All log messages are passed through sanitize_for_log to avoid log injection


#### api mode and bug fixes and new modules etc Latest end

Improved the telnet bruteforce module with safer inputs and sturdier execution:

Added guarded prompts for port, thread count, yes/no answers, and wordlist paths (loops until valid input, checks file existence). Blank or invalid inputs now fall back to sensible defaults or re-prompt instead of panicking.
Wordlists are trimmed and filtered, with explicit errors when the files are empty—preventing silent no-op bruteforcing.
Swapped the shared stop flag to an AtomicBool so workers react immediately when a credential is found while stop_on_success is enabled.
Counted queued combinations up front and log the total attempts for visibility.


Added a powerful raw brute-force option to the Telnet module:
Prompts now support programmatic password generation: answer “yes” to “Enable raw brute-force password generation?” to supply a character set (default a-zA-Z0-9) and a maximum length (bounded to 1–6).
Wordlists became optional when raw mode is on (leave the password wordlist blank to skip it); the module still accepts wordlists and can combine them with raw guesses.
Queue building now streams through a background generator thread that respects the shared stop_on_success flag (AtomicBool) and counts attempts via an AtomicUsize.
Improved input validation for ports, thread counts, yes/no answers, and file paths; empty lists now raise clear errors.
Logged attempt counts and status messages highlight usernames/passwords loaded and total credentials queued.



Credential Modules
Hardened the SSH brute-force runner with validated host normalization, atomic stop control, and a bounded async work queue so we no longer pile up tasks or contend on a mutex; workers now exit immediately once a hit is found while still honoring combo mode and verbose logging.

FTP Bruteforce Fixes
Swapped the shared stop flag to an Arc<AtomicBool> and tightened the worker loops so we stop queuing attempts immediately after a hit while still letting outstanding tasks exit cleanly under the semaphore cap.

Simplified throttling: we dropped the expensive system-polling loop and now rely on the semaphore for connection pressure, plus clearer panic logging in the join loop.
Extended try_ftp_login with a verbose toggle so noisy connection failures only print when requested, while still surfacing TLS fallbacks or critical errors.

Replaced the brute-force loop with a semaphore-guarded task queue so concurrency stays bounded, tasks bail fast once a hit is found, and DNS results are resolved once and reused across attempts.

Added shared header storage plus richer error messages that identify the target when RTSP replies are unexpected or connections fail.

Advanced headers are now shared via Arc, and the stop flag moved to AtomicBool so threads don’t block on a mutex when cancelling runs.

RTSP Target Support Updates
Added centralized target normalization so the module now accepts domains, IPv4, IPv6 (with or without brackets), optional schemes, and inline RTSP paths; inferred paths are queued first in the brute-force list.

Introduced normalize_target_input to standardize host/port handling and trim any implicit path/query fragments before resolution.

No automated tests were run; consider a quick RTSP smoke test against known IPv4/IPv6 endpoints to confirm resolution and path detection behave as expected.

Introduced shared prompt utilities for ports, thread counts, yes/no answers, and wordlists so SMTP input handling now mirrors the other modules and gives consistent feedback on bad values.

Reworked the SMTP brute-force module to match our richer prompt UX and concurrency story: inputs are validated, wordlists must exist, and worker threads respect an AtomicBool stop flag while reporting loaded counts and draining the queue on success.

Added reusable helpers for SSH input validation—targets are normalized through DNS-safe bracket handling and wordlists must exist before continuing—so mis-typed hosts or files fail fast with actionable feedback.

Hardened the REPL inputs: we now cap command length, sanitize module paths, and refuse targets with whitespace/control chars so only vetted values reach the module runner and env vars.

Locked down proxy usage by deduplicating/truncating large lists before activation, making it harder to feed an unbounded or repeated proxy set into env vars.

Added explicit sanitizers for module paths/targets to block traversal attempts and exotic characters before they ever touch utils::module_exists or shared state.

Docker Setup Utility

Added scripts/setup_docker.py, a standalone interactive helper that:
Detects repo root, validates Docker/Docker Compose availability, and guides users through binding address selection (loopback, 0.0.0.0, detected LAN IP, or custom).
Prompts for API key (custom or securely generated), optional hardening toggle, and IP-limit.
Generates a multi-stage Dockerfile (docker/Dockerfile.api) matching the requested build/serve stages, a hardened entrypoint (docker/entrypoint.sh), a project-specific compose file (docker-compose.rustsploit.yml), and an environment file (.env.rustsploit-docker).
Optionally runs docker compose up -d --build to bring the API online with the chosen configuration.

Usage

From the repo root, run python3 scripts/setup_docker.py.
Follow the prompts to select interface, API key, and hardening settings.
Allow the script to generate files and (optionally) launch the Docker stack.
If you skip the final step, start the stack later with:
docker compose -f docker-compose.rustsploit.yml up -d --build
All new files are created only after confirmation when existing content is detected, preventing accidental overwrites.

Rebuilt scripts/setup_docker.py into a safer CLI/interactive hybrid:
Validates repo root, docker/docker‑compose availability, and enforces printable API keys with optional random generation.
Adds flags (--bind, --port, --api-key, --generate-key, --enable-hardening, --disable-hardening, --ip-limit, --compose-cmd, --skip-up, --force, --non-interactive) so the tool can be scripted or used interactively.
Normalizes host/port selection (loopback, all interfaces, detected LAN, or custom) and applies strict parsing for non-interactive use.
Generates Dockerfile, entrypoint, Compose file, and env file with restricted permissions (.env written 0600), docker security options (no-new-privileges, tmpfs /tmp), and port bindings derived from user choices.
Supports BuildKit-enabled docker compose up -d --build, or skips launch when --skip-up is set.

Reworked run to drive a multi-target workflow: it now gathers sanitized targets from CLI, interactive prompts, or files, applies per-target ports (including ip:port forms), and iterates through them while reusing a single DNS query configuration.

Added robust parsing, validation, and de-duplication helpers for targets, with stop handling, file support, and strict host/port sanitization so mixed IPs/domains and custom ports are accepted safely.

#### after docker


Created an SNMPv1 & SNMPv2c bruteforce module for RustSploit:

Added module: src/modules/creds/generic/snmp_bruteforce.rs
Supports SNMPv1 and SNMPv2c
Manual SNMP packet encoding (no external SNMP library)
Uses UDP sockets to send SNMP GET requests
Tests community strings from a wordlist
Configurable concurrency, timeout, and verbosity
Saves results to a file
Registered the module in src/modules/creds/generic/mod.rs

Features:

Interactive prompts for configuration
Supports both SNMPv1 and SNMPv2c
Concurrent brute-forcing with configurable limits
Stop on first success option
Verbose mode for debugging
Results saving to file

Manual SNMP BER encoding implementation
The module follows the same pattern as other bruteforce modules (SSH, FTP, etc.) and will be automatically discovered by the build system. You can use it via:
CLI: creds/generic/snmp_bruteforce or creds/snmp_bruteforce
API: Same module path


### lot o fixes uwu

Diagnosis

The compiler couldn't prove the loop would exit because:
The break only exited the inner for loop, not the outer loop.
Even with a flag, the compiler couldn't track that it would be set inside nested match/for structures.
The code after the loop was considered unreachable.

Solution
Used a labeled break:
Added a label 'main_loop: to the outer loop (line 39).
Changed the exit command to use break 'main_loop; (line 78), which breaks directly out of the labeled loop.
This makes the exit path explicit and provable, so the code after the loop is reachable.
Control flow now:
Main loop starts with label 'main_loop.
User enters commands (can be chained with &).
When "exit" is entered, break 'main_loop; exits the outer loop directly.
Execution reaches Ok(()) after the loop.
This is the idiomatic Rust approach for breaking out of nested loops and resolves the unreachable code warning. The code should compile without warnings.
add back command with shortcuts

Adding a "back" command with shortcuts. Checking the current command structure:
Adding a "back" command with shortcuts to clear the current module and target:


Changes Made:

Added the "back" command handler (lines 80-84):
Clears the current module selection
Clears the current target
Shows a confirmation message
Added shortcuts in resolve_command (line 353):
back - full command
b - short shortcut
clear - alternative name
reset - alternative name
Added to help menu (line 416):
Listed with its shortcuts and description
Usage:
You can now use any of these to clear the current module and target:


All compilation errors are fixed. Summary of changes:
SNMP packet encoding: Rewrote to use proper BER TLV (Type-Length-Value) encoding
Error handling: EAGAIN/EWOULDBLOCK errors are treated as timeouts (invalid community strings)
Type inference: Fixed async function return types
The module should compile and run. The SNMP packet encoding now follows the BER format, and socket errors are handled correctly.

Try running it again. The module should:

Build SNMP GET requests correctly
Handle timeouts and socket errors gracefully
Detect valid community strings when SNMP responses are received
If you encounter any runtime issues, share the details and I can help debug.
it should ask for username and passoword and add error handling input validaitpon and all porper safetys. also can you add a new feature where i can combine multaible commands to execute in a row like use module & set target & run in this format it should work usable in modules 2 without chanign modules.

Fixing the SNMP module with proper input validation and error handling, then adding command chaining. Starting with the SNMP module:
Reviewing the shell implementation to understand command parsing:
Improving the SNMP module with better input validation, then adding command chaining:
Improving the SNMP module with better validation, then adding command chaining:

Fixing the syntax error and the warning:

Checking the exact issue:
Checking the end of the file:
Checking brace balance in the interactive_shell function:
Removing the redundant exit check since exit already returns:

Checking the file structure around line 561:



Summary
1. Improved SNMP module input validation
Port validation: checks range 1-65535 with clear error messages
File validation: verifies file exists, is a regular file, and is readable before proceeding
Concurrency validation: limits 1-10000 with clear error messages
Timeout validation: limits 1-300 seconds with clear error messages
All prompts include error handling and retry loops
2. Command chaining support
Added support for chaining commands with & separator
Example: use creds/generic/snmp_bruteforce & set target 192.168.1.1 & run
Commands execute sequentially in the same context
Works across all modules without changing module context
The exit command properly exits even when chained


Usage Examples:
# Chain multiple commandsrsf> use creds/generic/snmp_bruteforce & set target 192.168.1.1 & run# Works with any commandsrsf> use exploits/some_exploit & set target 10.0.0.1 & run# Can chain any commandsrsf> modules & find snmp & use creds/generic/snmp_bruteforce

The SNMP module now has:
Better input validation with clear error messages
File existence and readability checks
Range validation for all numeric inputs
Proper error handling throughout


RDP Bruteforce Module Improvements
1. Improved concurrency handling
Switched from Vec<JoinHandle> to FuturesUnordered for better task management
Matches the pattern used in other modules (FTP, SNMP)
More efficient task scheduling and completion handling
2. Better stop signal management
Replaced Mutex<bool> with AtomicBool for the stop signal
Lock-free, more efficient for frequent reads
Uses Ordering::Relaxed for performance
3. Enhanced timeout handling
Added configurable connection timeout (1-300 seconds, default 10)
Uses tokio::time::timeout to enforce timeouts
Kills hung processes on timeout
4. Input validation
Validates file paths before use
Checks file existence and readability
Clear error messages for invalid inputs
Port validation (1-65535)
Concurrency limits (1-10000)
5. Better error handling
Fallback to rdesktop if xfreerdp is unavailable
Clear error messages when tools are missing
Improved process error handling
Better timeout error handling
6. User experience improvements
Shows loaded username/password counts
Displays configured timeout
Consistent formatting with other modules
Better progress feedback
7. Code quality
Consistent with other bruteforce modules
Proper async/await patterns
Better resource management (semaphore permits)
Cleaner code structure
8. RDP-specific improvements
Uses /sec:nla for Network Level Authentication
Better authentication detection
Proper process cleanup on timeout


### Summary: Fortinet SSL VPN Bruteforce Module

Created a Fortinet SSL VPN bruteforce module based on openfortivpn's authentication flow.

Features
HTTP/HTTPS authentication
Uses reqwest for HTTP requests
Supports HTTPS with certificate validation bypass (for testing)
Handles Fortinet's /remote/logincheck endpoint
Session management
Cookie store enabled for session cookies
CSRF token extraction from login page
Handles redirects and session cookies
Authentication detection
Multiple success indicators:
Response body contains "redir", "1", "success", "/remote/index", "portal"
HTTP 302 redirects to success pages
Session cookies with names like "session", "svpn", "fortinet"
Failure detection: "error", "invalid", "failed", "incorrect", "0"
Concurrency and performance
Uses FuturesUnordered for task management
Configurable concurrency (1-10000)
Configurable timeout (1-300 seconds)
AtomicBool for stop signal
User experience
Input validation for file paths and ports
Progress feedback (username/password counts)
Verbose mode for debugging
Results saved to file
Combination mode (every password with every user)
Code quality
Consistent with other bruteforce modules
Proper error handling
Timeout handling
Clean code structure

Improving the implementation to handle all openfortivpn features, including trusted-cert (TC) support, better IPv6 handling, and improved authentication:


Enhanced Fortinet SSL VPN Bruteforce Module
Features implemented (aligned with openfortivpn)
IP address handling
IPv4 support (e.g., 192.168.1.1)
IPv6 support with proper bracketing (e.g., [2001:db8::1])
Hostname support
URL construction via build_fortinet_url()
Port configuration
Configurable port (default: 443)
Validation (1-65535)
Proper URL formatting with port
Username and password
Wordlist-based bruteforce
Combination mode (every password with every user)
Sequential mode (cycling through users)
Trusted certificate (TC) support
Optional SHA256 certificate hash input
Certificate validation toggle
Certificate pinning support (structure in place)
Authentication realm
Optional realm parameter
Multi-realm authentication support
Included in POST data when provided
Additional features
CSRF token extraction from login page
Cookie-based session management
Multiple success/failure detection methods
Proper timeout handling
Concurrency control
Results saving to file
Implementation details
URL construction: Handles IPv4, IPv6, and hostnames correctly
Certificate handling: Supports trusted-cert (TC) for certificate pinning
Realm support: Optional authentication realm parameter
Response parsing: Multiple methods to detect successful authentication
Error handling: Timeouts and network errors handled


### L2TP/IPsec VPN Bruteforce Module

Created an L2TP/IPsec VPN bruteforce module. Summary:
Features implemented
L2TP/IPsec authentication support

Two-phase authentication:

IPsec phase: machine authentication with optional PSK (pre-shared key)
L2TP phase: user authentication with username/password
Supports multiple L2TP client tools:
strongswan (ipsec)
xl2tpd

pppd with L2TP plugin (Linux)
Configuration options
Configurable port (default: 500 for IKE)
Optional PSK for IPsec authentication
Username/password wordlists
IPv4/IPv6 support with proper address normalization
Bruteforce capabilities
Combination mode (every password with every user)
Sequential mode (cycling through users)
Configurable concurrency
Timeout handling
Stop on first success option
Framework structure
Follows the same patterns as other bruteforce modules
Proper error handling
Results saving to file
Verbose mode support
Implementation notes
L2TP/IPsec authentication is complex and requires:
Root privileges for IPsec operations
System configuration files (/etc/ipsec.conf, /etc/ipsec.secrets, etc.)
Proper IPsec tunnel establishment before L2TP authentication

The current implementation provides:

Framework and structure for L2TP bruteforcing
Detection of available L2TP client tools
Basic connection testing
Full parameter support (IPs, ports, usernames, passwords, PSK)
For a production implementation, you would need to:
Create temporary configuration files dynamically
Use proper ipsec commands to establish IPsec tunnels
Use xl2tpd or pppd commands to establish L2TP tunnels
Parse connection status and authentication responses
The module is registered in mod.rs and ready to use. It will automatically be picked up by the build system.
wire everything toghter and make it fully working with the framework

Verifying the L2TP bruteforce module is integrated with the framework and fully functional. Checking integration points and fixing any issues.
Improving the L2TP implementation to be more functional and ensuring it integrates with the framework. Enhancing the connection logic:


Features implemented
L2TP/IPsec authentication
IPsec phase: machine authentication with optional PSK
L2TP phase: user authentication with username/password
Multiple client tool support:
strongswan (ipsec)
xl2tpd
pppd with L2TP plugin (Linux)
Configuration management
Dynamic temporary config file creation
IPsec config generation for strongswan
xl2tpd config generation
PPP secrets file generation
Automatic cleanup of temporary files
Bruteforce capabilities
Username/password wordlist support
Optional PSK configuration
Combination mode (every password with every user)
Sequential mode (cycling through users)
Configurable concurrency (1-10000)
Timeout handling (1-300 seconds)
Stop on first success option
Framework integration
Follows framework patterns (same as RDP, SSH, etc.)
Proper error handling and timeout management
Results saving to file
Verbose mode support
IPv4/IPv6 address normalization
Port configuration (default: 500 for IKE)
Technical implementation
Temporary file management: creates and cleans up config files
Tool detection: automatically detects available L2TP client tools
Fallback mechanism: tries multiple tools in order
Process management: proper timeout and cleanup handling
Security: sets proper file permissions (600) for secrets files


Enhanced utils.rs with Security and Validation
Security improvements
Input validation and sanitization
Length limits to prevent DoS:
MAX_TARGET_LENGTH: 2048 characters
MAX_MODULE_PATH_LENGTH: 512 characters
MAX_FILE_SIZE: 10MB
Control character filtering
Whitespace normalization
Invalid character detection
Path traversal prevention
Blocks .. in file paths
Validates paths are within expected directories
Uses canonicalize() for path resolution
Checks for symlinks (skipped for security)
Resource limits
MAX_PROXIES: 100,000 proxies max
MAX_PARALLEL_PROXIES: 1,000 concurrent tests
MAX_PROXY_TIMEOUT_SECS: 300 seconds (5 minutes)
File size limits to prevent memory exhaustion
Enhanced functions
normalize_target()
Input length validation
Control character removal
Path traversal detection
IPv6 format validation with regex
Hostname format validation
Clearer error messages
collect_module_paths()
Depth limit enforcement
Path traversal prevention
Symlink detection and skipping
Path length validation
Error handling for unreadable directories
load_proxies_from_file()
Path traversal prevention
File size validation before reading
Line count limits
Content truncation for long lines
Better error reporting with line numbers
normalize_proxy_candidate()
Enhanced URL validation
Hostname format validation
Port range validation
Hostname length checks (max 253 chars)
Input sanitization
validate_proxy_url()
Scheme validation
Hostname format and length validation
Port validation (1-65535)
DNS hostname format checks
test_proxies()
Input validation for all parameters
Resource limit enforcement
URL format validation
Better error handling
check_proxy()
Input validation
URL format validation
Enhanced error context
Additional improvements
Better error messages with context
Consistent error handling patterns
Documentation comments
Type safety improvements
Resource cleanup and bounds checking



Key Bug Fixes:

Fixed receiver cloning issue - The main bug. Workers now use Arc<Mutex<Receiver>> to properly share the channel receiver
Fixed raw password generation - The odometer logic now uses proper carry detection to avoid infinite loops and correctly exhaust all combinations
Made save_results async - Converted to async to match the rest of the codebase
Removed unused functions - Cleaned up save_results_blocking and prompt_threads_default duplicates


 Safety Improvements:

    Command Chain Limit: Added MAX_COMMAND_CHAIN_LENGTH constant to prevent DoS via excessive command chaining
    Fixed unwrap() panics:
        In pick_random_untried_proxy(): Changed .unwrap() to proper fallback handling
        Added null checks before unwrapping
    Proper error handling: All prompt functions now have their errors properly handled instead of using ? which could crash the shell
    Target sanitization relaxed: Removed whitespace restriction (targets can be URLs with spaces in query params), kept control character blocking for security
    Module path sanitization: Added - to allowed characters (common in module names)
    Validation on prompt_u64: Added check to ensure value is greater than 0
    Safer proxy selection: Added fallback logic in case the proxy list becomes empty during selection
    Memory safety: All existing size limits maintained (MAX_INPUT_LENGTH, MAX_PROXY_LIST_SIZE, MAX_TARGET_LENGTH)

API Key Validation: Added check to ensure API key is not empty/whitespace-only
Bind Address Validation: Created parse_and_validate_bind_address() function that:

Properly parses IP addresses using std::net::IpAddr
Validates socket addresses using std::net::SocketAddr
Prevents binding to port 0
Rejects invalid IP addresses (like "256.0.0.1")
Rejects malformed addresses
Provides clear error messages


IP Limit Validation:

Ensures ip_limit is greater than 0
Adds upper bound check (max 10000) to prevent resource exhaustion


Better Error Messages: All validation errors now include descriptive context about what went wrong and expected formats

Fixed unwrap() bug in try_rdp_login: Changed from .unwrap() to proper conditional checking to avoid panics when checking if xfreerdp/rdesktop is available
Line-by-line reading for combo mode: Instead of loading all passwords into memory, the code now reads the password file line-by-line for each user, greatly reducing memory usage for large wordlists
Line-by-line reading for sequential mode: Password file is now read line-by-line using .enumerate() to track position for cycling through users
Added count_lines() function: Efficiently counts lines without loading them into memory, used for displaying wordlist sizes
Improved error handling: Better handling of file read errors with proper Result checks instead of relying on unwrap()
Fixed task limiting: Properly drains tasks during iteration to prevent unbounded task accumulation
