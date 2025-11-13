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


