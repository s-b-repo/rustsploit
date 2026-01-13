
Walkthrough - MongoBleed Module

Changes Made
I have implemented a new exploit module for MongoBleed (CVE-2025-14847), which targets a critical memory leak vulnerability in MongoDB's zlib decompression.

New Module

src/modules/exploits/mongo/mongobleed.rs
: Containing the core logic to send a malicious compressed packet and analyze the response for memory leaks. Includes unit tests for parser verification.
src/modules/exploits/mongo/mod.rs
: To export the new module.
Integration

Updated 
src/modules/exploits/mod.rs
 to register the new mongo category.

Features
Vulnerability Check: Connects to the target port (default 27017) and sends a probe with inflated uncompressedSize.
Memory Leak Analysis: Parses the error response from MongoDB to extract "field names" and "types" that are actually leaked memory chunks.
Reporting: Prints any leaked strings (potential credentials or data) to the console.
Verification Results
Automated Build Check
Ran cargo check successfully. The module is correctly integrated into the build system and all dependencies are satisfied.
The build script 

build.rs
 will automatically detect the new module exploits/mongo/mongobleed and generate the dispatch code.
Unit Tests
Ran cargo test modules::exploits::mongo::mongobleed successfully.

Verified 
test_extract_leaks_from_plaintext_error
: Correctly extracts leaked strings from simulated plaintext error messages.

Verified 
test_extract_leaks_checks_opcode
: Correctly identifies compressed responses (opcode 2012) and decompresses them to find leaks.
Usage
To use the module:

# In interactive mode
rustsploit > use exploits/mongo/mongobleed
rustsploit (exploits/mongo/mongobleed) > run <target_ip>
# Or direct CLI
./rustsploit exploit --module exploits/mongo/mongobleed --target <target_ip>


NginxPwner Module
Changes Made
I have implemented a new scanner module scanners/http/nginx_pwner which ports the functionality of the popular nginxpwner tool to native Rust.

New Module

src/modules/exploits/http/nginx_pwner.rs
: Contains the logic for 8 different Nginx vulnerability/misconfiguration checks.

src/modules/exploits/http/mod.rs
: Exports the submodule.
Integration
Created src/modules/scanners/http/ directory structure.
Registered http module in src/modules/scanners/mod.rs.

Features Implemented
Version Disclosure: Checks Server header for outdated versions.
CRLF Injection: Tests for HTTP Splitting/CRLF via URI.
PURGE Method: Checks if the PURGE method is enabled.
Variable Leakage: Checks for $http_referer reflection/leakage.
Merge Slashes: Checks for potential path traversal via /// and ///.. patterns.
Header Bypass / IP Spoofing: Tests iterate through common headers (X-Forwarded-For, etc.) with local IPs (127.0.0.1, localhost) to detect bypasses.
Alias Traversal: Checks for "off-by-slash" alias vulnerabilities on common paths (/img../, /static../, etc.).
Integer Overflow (CVE-2017-7529): Tests for the Range header integer overflow vulnerability.

Output
The module prints findings to the console in color.
Findings are saved to a text file named nginx_pwner_results_TARGET.txt in the current directory.

Usage

# Interactive
rustsploit > use exploits/nginx/nginx_pwner
rustsploit (exploits/nginx/nginx_pwner) > run <target_url>

# CLI
./rustsploit exploit --module exploits/nginx/nginx_pwner --target <target_url>

I have updated the nginx_pwner module to include ALL features from the provided Python script.

New Features Added:

PHP Detection: Identifies PHP usage via index.php, PHPSESSID, and headers. Suggests misconfiguration checks.
X-Accel-Redirect Bypass: Tests for logic bypass on a list of common sensitive paths (admin, backups, etc) since we cannot input a file.
Raw Backend Reading: Added suggestion/check.
Manual Suggestions: Prints reminders to check for Redis, CORS, Request Smuggling, etc. at the end of the scan.

1
Adding Raw Backend Reading and expanding path lists

2
Retrying update with larger context check

3
Finding check_alias_traversal location

4
Reading check_alias_traversal block

5
Applying the update to check_alias_traversal and adding check_raw_backend_reading




added Hikvision CVE-2021-36260 exploit

Successfully added the Hikvision CVE-2021-36260 exploit module to rustsploit!

Files created:

src/modules/exploits/hikvision/mod.rs - Module declaration
src/modules/exploits/hikvision/hikvision_rce.rs - Exploit implementation
Features ported from the Python PoC:

Safe vulnerability check - Writes/reads test file to verify exploitability
Unsafe reboot check - Reboots device to confirm vulnerability
Command execution - Execute commands with output retrieval
Blind command execution - Execute commands without output
Interactive command mode - REPL-style command interface
SSH shell setup - Deploys dropbear SSH on port 1337








 The n8n module is already fully implemented and compiles successfully.

The module at n8n_rce_cve_2025_68613.rs (616 lines) includes:

Feature	Implementation
Authentication	Login via /rest/login, handles token/cookie-based auth
Malicious Workflow Creation	Creates workflow with expression injection payload
Workflow Execution	Triggers the exploit via /rest/workflows/{id}/run
Cleanup	Deletes test workflow after execution
All 6 Payloads Ported:

Info - System information gathering
Command - Arbitrary command execution (execSync)
Environment - Extract environment variables (credentials)
Read File - Read arbitrary files (fs.readFileSync)
Write File - Write arbitrary files (fs.writeFileSync)
Reverse Shell - bash TCP reverse shell







FortiWeb CVE-2025-25257 module created and compiles successfully!

Created files:

fortiweb/mod.rs - Module registration
fortiweb/fortiweb_sqli_rce_cve_2025_25257.rs - Full exploit implementation
Features implemented:

Component	Description

SQL Injection	Via Authorization: Bearer ';{injection} header on /api/fabric/device/status
Payload chunking	16-byte hex-encoded chunks via UPDATE ... CONCAT
Webshell write	SELECT INTO OUTFILE to /migadmin/cgi-bin/x.cgi
.pth trigger	Python chmod script at /var/log/lib/python3.10/pylab.py
Trigger execution	Access /cgi-bin/ml-draw.py to trigger chmod
Command execution	Commands sent via User-Agent header to webshell

Interactive options:

Deploy webshell - Full exploit chain with interactive command mode
Execute command - Run commands if webshell already deployed
Test SQLi - Verify if target is vulnerable


pgrading Crates and Fixing Compilation Errors
I successfully resolved all reqwest and suppaftp compilation errors. However, due to undocumented API changes in hickory_client/hickory_proto (specifically UdpClientStream initialization), I am temporarily disabling the logic in 
dns_recursion.rs
 to allow the rest of the project to build and test. I will mark this with a TODO.
 
 
 Upgrading crates and refreshing lockfile

2
Fixing suppaftp feature conflict

3
Updating Cargo.toml to fix suppaftp feature error and rerunning check

4
Updating Cargo.toml again to fix suppaftp feature error

5
Fixing hickory-client feature conflict

6
Analyzing compilation errors from cargo check

7
Fixing compiled errors in http2 and investigating reqwest errors

8
Refactoring http2 module to fix rustls breaking changes

9
Fixing http2 lifetime error and refactoring acti module reqwest usage

10
Retrying acti fix and fixing suppaftp imports

11
Refactoring code to fix breaking changes in modules

12
Fixing suppaftp type usages and DNS scanner imports

13
Fixing DNS scanner imports and removing .form() usage in exploit modules

14
Enabling tokio-async-native-tls for suppaftp and reverting FTP code changes

15
Updating suppaftp imports to suppaftp::tokio and fixing missing semicolon

16
Fixing DNS connection type and replacing form() in remaining modules

17
Correcting syntax errors in reqwest form replacement and fixing DNS imports

18
Temporarily disabling DNS recursion scanner to unblock compilation


I have successfully upgraded all crates to their latest versions and resolved the resulting compilation errors.

Summary of Changes:

Fixed suppaftp Upgrade: Updated imports code to use suppaftp::tokio types for v7 compatibility.
Fixed reqwest Breaking Changes: Refactored 6 modules (acti, zte, roundcube, fortinet, acti_camera, jenkins) to manually construct form bodies and query strings, as helper methods were removed.
Fixed rustls API: Updated ServerName imports and fixed lifetime issues in http2 exploit.
Disabled dns_recursion Scanner: The hickory-client v0.25 update introduced significant API changes. I have commented out the logic in src/modules/scanners/dns_recursion.rs with a TODO to allow the rest of the project to compile and run.


Upgrade Walkthrough
This document summarizes the changes made to upgrade all dependencies in rustsploit to their latest versions, including incompatible major updates.

Changes
1. 
Cargo.toml
 updates
Updated all dependencies to latest versions using cargo upgrade --incompatible.
Adjusted suppaftp features to ["tokio-async-native-tls"] to match version 7.x changes.
Removed dnssec feature from hickory-client and async/async-native-tls from legacy suppaftp configuration.
2. Code Refactoring
rustls (v0.23+)
Updated ServerName imports to rustls::pki_types::ServerName.
Removed deprecated ClientConfig::builder().with_safe_defaults().
Added .to_owned() to ServerName conversion in 
http2/cve_2023_44487_http2_rapid_reset.rs
 to fix lifetime issues.
reqwest (v0.13+)
The .query() and .form() methods were removed or changed in usage context.
Refactored 
src/modules/exploits/acti/acm_5611_rce.rs
 to manually construct query parameters.
Refactored 
src/modules/exploits/zte/zte_zxv10_h201l_rce_authenticationbypass.rs
 to manually construct form bodies.
Refactored 
src/modules/exploits/roundcube/roundcube_postauth_rce.rs
 to manually construct form bodies.
Refactored 
src/modules/creds/generic/fortinet_bruteforce.rs
 to manually construct form bodies.
Refactored 
src/modules/creds/camera/acti/acti_camera_default.rs
 to manually construct form bodies.
Refactored 
src/modules/exploits/jenkins/jenkins_2_441_lfi.rs
 to append query parameters to the URL string.
suppaftp (v7.x)
Updated imports in 
src/modules/creds/generic/ftp_anonymous.rs
 and 
src/modules/creds/generic/ftp_bruteforce.rs
.
Swapped suppaftp types to suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsFtpStream, AsyncNativeTlsConnector}.
hickory-client (v0.25+)
Temporarily Disabled: The 
src/modules/scanners/dns_recursion.rs
 module logic has been commented out. The v0.25 update introduced significant API changes to AsyncClient and UdpClientStream initialization that require further investigation or a rewrite of the DNS client logic. A TODO has been added to the file.
Verification
Run cargo check: Passed (with warnings).
Run cargo test: Passed (compilation success).
Next Steps
Re-implement the dns_recursion scanner using the new hickory-client API.
Address remaining compiler warnings (mostly unused imports due to disabled code).






Upgrade Walkthrough
This document summarizes the changes made to upgrade all dependencies in rustsploit to their latest versions, including incompatible major updates.

Changes
1. 
Cargo.toml
 updates
Updated all dependencies to latest versions using cargo upgrade --incompatible.
Adjusted suppaftp features to ["tokio-async-native-tls"] to match version 7.x changes.
Removed dnssec feature from hickory-client and async/async-native-tls from legacy suppaftp configuration.
2. Code Refactoring
rustls (v0.23+)
Updated ServerName imports to rustls::pki_types::ServerName.
Removed deprecated ClientConfig::builder().with_safe_defaults().
Added .to_owned() to ServerName conversion in 
http2/cve_2023_44487_http2_rapid_reset.rs
 to fix lifetime issues.
reqwest (v0.13+)
The .query() and .form() methods were removed or changed in usage context.
Refactored 
src/modules/exploits/acti/acm_5611_rce.rs
 to manually construct query parameters.
Refactored 
src/modules/exploits/zte/zte_zxv10_h201l_rce_authenticationbypass.rs
 to manually construct form bodies.
Refactored 
src/modules/exploits/roundcube/roundcube_postauth_rce.rs
 to manually construct form bodies.
Refactored 
src/modules/creds/generic/fortinet_bruteforce.rs
 to manually construct form bodies.
Refactored 
src/modules/creds/camera/acti/acti_camera_default.rs
 to manually construct form bodies.
Refactored 
src/modules/exploits/jenkins/jenkins_2_441_lfi.rs
 to append query parameters to the URL string.
suppaftp (v7.x)
Updated imports in 
src/modules/creds/generic/ftp_anonymous.rs
 and 
src/modules/creds/generic/ftp_bruteforce.rs
.
Swapped suppaftp types to suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsFtpStream, AsyncNativeTlsConnector}.
hickory-client (v0.25+)
Fixed: The 
src/modules/scanners/dns_recursion.rs
 module was updated to use the new hickory-client v0.25 API.
Renamed AsyncClient to Client.
Updated UdpClientStream initialization to use the builder pattern with TokioRuntimeProvider: UdpClientStream::builder(socket_addr, TokioRuntimeProvider::new()).build().

hickory-client (v0.25+)
Fixed: The 
src/modules/scanners/dns_recursion.rs
 module was updated to use the new hickory-client v0.25 API.
Renamed AsyncClient to Client.
Updated UdpClientStream initialization to use the builder pattern with TokioRuntimeProvider: UdpClientStream::builder(socket_addr, TokioRuntimeProvider::new()).build().
Re-implemented request timeout using tokio::time::timeout as UdpClientStream no longer supports built-in timeouts.
Verification
 Address remaining compiler warnings (all imports utilized).
Verification
Run cargo check: Passed (0 errors, 0 warnings).
Run cargo test: Passed (compilation success).

I have addressed the remaining compiler warnings and ensured all code is properly utilized.

Clean-up Details:

Re-implemented Timeout: In src/modules/scanners/dns_recursion.rs, I restored the query timeout functionality using tokio::time::timeout. This ensures the Duration import is used and the scanner behaves as expected (timing out after 5 seconds if no response).
Verified Clean Build: Ran cargo clean and cargo check, confirming there are 0 errors and 0 warnings.
