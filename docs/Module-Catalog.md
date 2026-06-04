# Module Catalog

> Auto-generated from the inventory registry by `rustsploit --gen-module-catalog`. Do not edit by hand.

**Total registered modules: 363**

All modules support mass scan universally — `random` / CIDR / file targets / comma-separated lists fan out through `crate::scheduler::run` regardless of the module.

## scanners (45)

- 45 modules, 8 with `check()`

| Module | Description | Rank | Check |
|---|---|---|---|
| `scanners/api_endpoint_scanner` | Comprehensive REST API endpoint discovery and vulnerability scanner with fuzzing, authentication bypass, and injection detection. | Normal |  |
| `scanners/asterisk_fingerprint` | Connects to the Asterisk built-in HTTPS interface (default 8089/tcp), reads the Server header, and flags EOL major branches (1.x through 16.x). Detection only — no exploit traffic, no DoS vectors. | Excellent | ✓ |
| `scanners/cors_reflection_scanner` | Sends a battery of Origin headers (attacker, null, suffix/prefix confusion, scheme downgrade) plus an OPTIONS preflight, and reports any reflected or wildcard ACAO, especially when paired with Access-Control-Allow-Credentials: true. | Excellent |  |
| `scanners/cpanel_exposure` | Probes the cPanel control-plane ports (2082/2083, 2086/2087, 2095/2096) plus 8888/8889 for reachable HTTP(S) endpoints. Reports each panel that responds, its Server header, and any redirect chain — useful for finding management interfaces exposed to the internet without IP allow-lists. | Excellent | ✓ |
| `scanners/csp_audit_scanner` | Extracts Content-Security-Policy from headers or <meta> tags and flags unfilled placeholders, unsafe-inline/unsafe-eval, wildcard sources, missing frame-ancestors, mixed content, and overly broad CDN whitelists. | Excellent |  |
| `scanners/dir_brute` | HTTP directory and file enumeration via wordlist with multiple scan modes, evasion techniques, and concurrent requests. | Normal |  |
| `scanners/dmarc_check` | Queries _dmarc.<domain> TXT records to determine whether DMARC is missing, set to p=none (monitoring only), or enforced (p=quarantine / p=reject). Missing or non-enforcing DMARC enables email spoofing and phishing. | Excellent | ✓ |
| `scanners/dns_recursion` | Detects open DNS resolvers vulnerable to recursion and amplification attacks. | Normal |  |
| `scanners/honeypot_scanner` | Scans targets for honeypot indicators by probing 50 common TCP ports in parallel. Classifies hosts as Clean (0-5 open), Suspicious (6-10), Likely Honeypot (11-20), or Definite Honeypot (21+). Supports single IP, CIDR subnets, file-based target lists, and random/mass scanning. Results are stored to the workspace with honeypot notes. | Normal |  |
| `scanners/http_method_scanner` | Enumerates allowed HTTP methods on a target to identify dangerous or misconfigured endpoints. | Normal |  |
| `scanners/http_title_scanner` | Enumerates HTML page titles across HTTP and HTTPS endpoints for target fingerprinting. | Normal |  |
| `scanners/ipmi_enum_exploit` | Comprehensive IPMI scanner with version detection, cipher 0 bypass, default credential brute force, and RAKP hash dumping. | Normal |  |
| `scanners/iusb_virtualmedia_probe` | Probes a BMC for a reachable IUSB virtual-media service by sending the 12-byte protocol handshake (ASCII 'IUSB' + 4 spaces + 4 NUL) to ports 5120/5123/5124/5126/5127 in plaintext, then over TLS. Reports each port whose reply echoes the IUSB magic — those ports accept remote ISO mounts with valid BMC credentials, which paired with credential-leak or default-password issues is a full host-OS compromise vector. | Great | ✓ |
| `scanners/m365_userenum_scanner` | Confirms Azure AD / M365 tenant existence via OIDC .well-known, then enumerates user existence by POSTing GetCredentialType. Returns IfExistsResult (0=exists, 1=missing, 5=federated, 6=throttled). | Excellent |  |
| `scanners/mysql_exposure` | Connects to TCP/3306 (configurable), reads the server greeting handshake, and reports the protocol byte + advertised version. If the server replies with an ERR packet (host not allowed) the banner still confirms exposure. Detection only — no authentication is attempted. | Excellent | ✓ |
| `scanners/nbns_scanner` | Sends NBNS name queries to UDP port 137 to discover Windows hosts on a network. Extracts NetBIOS computer names, domain/workgroup memberships, MAC addresses, and service type flags. Useful for Windows network reconnaissance. | Excellent |  |
| `scanners/php_version_eol` | Reads the X-Powered-By header from /, then probes a small list of common Vicidial paths. Flags PHP major branches that have reached EOL (4.x, 5.x, 7.x — all unsupported as of 2026). Detection only — no exploitation. | Excellent | ✓ |
| `scanners/ping_sweep` | Single-host liveness probe — ICMP echo, then a small TCP connect pre-check on common ports. Used as a per-host probe inside the scheduler's CIDR / random / file fan-out, so the operator gets the same `up?` answer for one host or a /16 with no extra plumbing. | Excellent |  |
| `scanners/port_scanner` | Concurrent TCP and UDP port scanner with service detection, banner grabbing, and configurable scan ranges. | Normal |  |
| `scanners/proxy_scanner` | Scans for open proxy servers: HTTP CONNECT, SOCKS4, SOCKS5, and HTTP transparent. Identifies proxies that can be used for traffic relay without authentication. | Normal |  |
| `scanners/redfish_unauth_enum` | Walks the standard Redfish tree (Systems, Managers, Chassis, AccountService, SecurityService, UpdateService) against a BMC target and reports any endpoint that returns sensitive identity/firmware/policy data without authentication. Also probes vendor-aux endpoints like /cc/bmc_cc.xml that commonly leak capability catalogs and error-string enums. | Great | ✓ |
| `scanners/redis_scanner` | Scans for Redis instances with no authentication. Extracts server version, configuration, key count, and identifies potential exploitation vectors such as writable directories and empty requirepass. | Excellent |  |
| `scanners/reflect_scanner` | Scans for UDP amplification vulnerabilities (DNS open resolver, NTP monlist, SSDP M-SEARCH, Memcached stats). Identifies reflectors that could be abused for volumetric DDoS attacks. | Excellent |  |
| `scanners/s3_bucket_scanner` | Probes an S3 bucket via virtual-hosted and path-style URLs for public listing, ACL/policy disclosure, and bucket-existence (NoSuchBucket → registration takeover candidate). | Excellent |  |
| `scanners/sample_scanner` | Checks HTTP and HTTPS reachability and response codes for target hosts. | Normal |  |
| `scanners/security_headers_scanner` | Fetches a target URL, audits the security-relevant response headers, and reports missing/weak HSTS, CSP, X-Frame-Options, COOP/COEP/CORP, server banners, and insecure cookie attributes. | Excellent |  |
| `scanners/sequential_fuzzer` | Sequential character-based HTTP fuzzer with multiple encoding types, injection charsets, and concurrent request support. | Normal |  |
| `scanners/service_scanner` | Connects to common service ports and grabs banners/version strings using protocol-specific probes. Detects FTP, SSH, Telnet, SMTP, POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, Memcached, RDP, VNC, and Elasticsearch. | Excellent |  |
| `scanners/sgbox_siem_recon` | Non-destructive recon of Securegate SGBox NG-SIEM consoles. | Excellent | ✓ |
| `scanners/smtp_user_enum` | Enumerates valid usernames on SMTP servers using VRFY commands with wordlist-based concurrent scanning. | Normal |  |
| `scanners/snmp_scanner` | Tests SNMP v1/v2c community strings against target devices. Builds raw SNMP GET packets using BER/ASN.1 encoding to extract sysDescr, sysName, and sysLocation from responding devices. | Excellent |  |
| `scanners/source_map_scanner` | Crawls the target HTML for <script src> URLs, then probes each .map companion to detect exposed JavaScript source-maps that leak original source code, internal API paths, and embedded secrets. | Excellent |  |
| `scanners/source_port_scanner` | Firewall bypass scanner that discovers which source ports are allowed to connect to a target IP and destination port. Useful for identifying firewall rules that permit traffic from specific source ports (e.g., DNS/53, HTTP/80). Supports parallel scanning with configurable concurrency. | Excellent |  |
| `scanners/ssdp_msearch` | Discovers UPnP devices on a network via SSDP M-SEARCH multicast and unicast probes. | Normal |  |
| `scanners/ssh_scanner` | Scans networks for SSH services with banner grabbing, CIDR range support, and concurrent scanning. | Normal |  |
| `scanners/ssl_scanner` | Analyzes SSL/TLS certificates and configuration. Detects expired certificates, self-signed certs, weak ciphers, and misconfigurations. | Excellent |  |
| `scanners/stalkroute_full_traceroute` | Advanced traceroute with ICMP, TCP, and UDP probes, OS fingerprint spoofing, and decoy packet generation. | Normal |  |
| `scanners/subdomain_scanner` | Brute-forces subdomains of a target domain using DNS resolution. Supports built-in wordlist or custom wordlist file. Uses concurrent asynchronous DNS lookups for fast enumeration. | Excellent |  |
| `scanners/subdomain_takeover_scanner` | Resolves the CNAME chain for a host, identifies the cloud provider, and probes the live URL for the provider-specific 'unclaimed' fingerprint. Covers CloudFront, Heroku, GitHub Pages, Azure, Netlify, WPEngine, Surge, Pantheon, Fastly, Vercel, Shopify, Statuspage, Zendesk, and 18 more. | Excellent |  |
| `scanners/vnc_scanner` | Scans VNC servers for protocol version and security type enumeration. Identifies servers with 'None' authentication (no password required) and reports all supported security mechanisms. | Excellent |  |
| `scanners/vuln_checker` | Runs fingerprint probes against a target to identify vulnerable products/services. | Excellent |  |
| `scanners/waf_detector` | Detects Web Application Firewalls and CDN providers by analyzing HTTP response headers, cookies, and body content. Sends benign and malicious payloads to trigger WAF signatures for higher-confidence detection. Identifies Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP, ModSecurity, Sucuri, Barracuda, Fortinet, and Citrix NetScaler. | Excellent |  |
| `scanners/wellknown_scanner` | Probes ~50 common discovery endpoints (security.txt, OIDC config, autodiscover, swagger, .env, .git, actuator, healthz) and reports reachable resources with status, content-type, length, and snippet. | Excellent |  |
| `scanners/wp_user_enum` | Three-vector WordPress user enumeration: /wp-json/wp/v2/users, ?author=N slug-leak via redirect, and /wp-json/oembed/1.0/embed author disclosure. | Excellent |  |
| `scanners/wp_xmlrpc_scanner` | Detects /xmlrpc.php exposure on WordPress sites, enumerates allowed methods via system.listMethods, and flags system.multicall (password-spray amplifier) and pingback.ping (SSRF / DDoS primitive). | Excellent |  |

## exploits (284)

- 284 modules, 137 with `check()`

| Module | Description | Rank | Check |
|---|---|---|---|
| `exploits/bluetooth/wpair` | Google Fast Pair pairing-mode-bypass exploitation (WhisperPair, CVE-2025-36911). Discovers Fast Pair accessories (service 0xfe2c), then performs the secp256r1 ECDH Key-Based Pairing handshake against the target's Anti-Spoofing key to force-pair out of pairing mode. Interactive sub-shell: scan/info/exploit/testall/exploitall/nonce/curve/pair/rename/switch/harvest, with nonce-replay (§4.3) and invalid-curve (§4.5) conformance tests. Requires `bluetooth` feature + a local BLE adapter. See the [Fast Pair / WhisperPair Guide](Fast-Pair-WhisperPair-Guide.md). | Excellent |  |
| `exploits/cameras/abus/abussecurity_camera_cve202326609variant1` | Probes ABUS security cameras for the path-traversal vulnerability in /webparam.cgi that allows reading /etc/passwd and similar local files. | Excellent |  |
| `exploits/cameras/acti/acm_5611_rce` | Probes ACTi ACM-5611 IP cameras for command injection in the iperf parameter on /cgi-bin/test. Sends a benign echo-marker payload. | Excellent |  |
| `exploits/cameras/avtech/cve_2024_7029_avtech_camera` | Exploits CVE-2024-7029 in AVTECH IP cameras for remote code execution. | Excellent |  |
| `exploits/cameras/galayou_g2_rtsp_bypass_cve_2025_9983` | Sends an unauthenticated RTSP DESCRIBE to the camera and detects | Great | ✓ |
| `exploits/cameras/hikvision/hikvision_rce_cve_2021_36260` | Sends a benign `echo $marker` payload to PUT /SDK/webLanguage with the XML command-injection vector from CVE-2021-36260. Vulnerable devices echo the marker. No destructive operations performed. | Excellent |  |
| `exploits/cameras/reolink/reolink_rce_cve_2019_11001` | Exploits CVE-2019-11001 authenticated OS command injection in Reolink cameras via TestEmail functionality. | Excellent |  |
| `exploits/cameras/uniview/uniview_nvr_pwd_disclosure` | Extracts and decodes user credentials from Uniview NVR devices via remote password disclosure vulnerability. | Good |  |
| `exploits/cameras/xiongmai_xm530` | Probes the proprietary Xiongmai XM530 control protocol on TCP/34567 for | Normal | ✓ |
| `exploits/cowrie/ansi_log_injection` | Injects ANSI/OSC escape sequences into cowrie's session log via unsanitized crontab command arguments. When an operator views the replay log on a real terminal, embedded escapes execute: title bar hijack, bell spam, cursor repositioning. | Normal |  |
| `exploits/cowrie/llm_prompt_injection` | Exploits cowrie's LLM mode where unsanitized attacker commands are concatenated into the same prompt context as the confidential system prompt containing real hostname and username. Injection can coerce the LLM to echo real configuration data. | Normal |  |
| `exploits/cowrie/ssrf_ipv6` | Demonstrates that cowrie's SSRF blocklist omits fc00::/7, fe80::/10, and ::ffff:0:0/96, allowing IPv6 SSRF to internal addresses. Also demonstrates the DNS-rebinding TOCTOU where check→re-resolve allows SSRF bypass via fast-flux DNS. | Normal |  |
| `exploits/crypto/geth_dos_cve_2026_22862` | Detects Go-Ethereum nodes vulnerable to CVE-2026-22862 by querying the JSON-RPC web3_clientVersion endpoint and parsing the version string. Does NOT send the destructive ECIES crash payload. | Normal |  |
| `exploits/crypto/heartbleed` | Tests for and exploits the OpenSSL Heartbleed vulnerability (CVE-2014-0160) to leak server memory contents. | Good |  |
| `exploits/dionaea/mqtt_underflow` | Sends a malformed MQTT PUBLISH packet to dionaea where TopicLength (255) exceeds MessageLength-2 (3), causing a negative length_from in scapy's MQTT_Publish parser. Triggers parser desync / UnicodeDecodeError exception. | Normal |  |
| `exploits/dionaea/mssql_dos` | Sends a crafted TDS7 LOGIN7 packet to dionaea's MSSQL honeypot where ibPassword=85 and cchPassword=2, causing the password slice to be 1 byte. Decoding 1 byte as UTF-16 raises UnicodeDecodeError outside the try block → unhandled exception → connection handler crash. | Normal |  |
| `exploits/dionaea/mysql_sqli` | Sends a MySQL COM_FIELD_LIST command to dionaea where the table name contains SQLite injection. Table 'sqlite_master)--' changes the PRAGMA query to return the honeypot's internal DB schema. Demonstrates the developer's comment 'I'm not afraid of SQLi here though.' | Normal |  |
| `exploits/dionaea/tftp_crash` | Sends a malformed TFTP RRQ to dionaea where the option name 'blksize' lacks a trailing NUL byte. dionaea's options parser builds a malformed struct format string → struct.error or UnicodeDecodeError in tftp.py:178-216. | Normal |  |
| `exploits/dos/apachebrpc_overflow_cve_2025_59789` | Detects Apache bRPC ports; deeply recursive JSON crashes the server. | Normal | ✓ |
| `exploits/dos/connection_exhaustion_flood` | Ultra-fast TCP connection flood that exhausts server connection tables and TIME_WAIT slots. | Normal |  |
| `exploits/dos/dns_amplification` | Sends spoofed DNS ANY queries to open resolvers, causing amplified responses (~100x) directed at the victim via raw UDP with IP_HDRINCL. | Normal |  |
| `exploits/dos/http2_rapidreset_cve_2023_44487` | Probes the target for HTTP/2 Rapid Reset DoS exposure by detecting | Normal | ✓ |
| `exploits/dos/http_flood` | High-speed HTTP GET/POST flood targeting web servers at the application layer with User-Agent rotation and cache-busting random parameters. | Normal |  |
| `exploits/dos/icmp_flood` | Raw ICMP echo request flood with proper checksums. Supports optional source IP spoofing via IP_HDRINCL or non-spoofed ICMP raw sockets. | Normal |  |
| `exploits/dos/memcached_amplification` | Sends spoofed memcached UDP stats requests to open servers, causing massively amplified responses (~51,000x) directed at the victim via raw UDP with IP_HDRINCL. | Normal |  |
| `exploits/dos/ntp_amplification` | Sends spoofed NTP MON_GETLIST_1 requests to NTP servers, causing amplified responses (~556x) directed at the victim via raw UDP with IP_HDRINCL. | Normal |  |
| `exploits/dos/null_syn_exhaustion` | High-performance SYN flood with null-byte payloads for resource exhaustion testing using native OS threads and sendmmsg batching. | Normal |  |
| `exploits/dos/px4_uav_dos` | Sends a benign MAVLink heartbeat to UDP/14550 to fingerprint PX4 autopilot exposure. | Normal | ✓ |
| `exploits/dos/rudy` | Opens HTTP POST connections with large Content-Length then drips the body one byte at a time, exhausting server connection pools. Supports optional TLS. | Normal |  |
| `exploits/dos/slowloris` | Keeps HTTP connections open by sending partial headers slowly, exhausting the server's connection pool. Supports optional TLS. | Normal |  |
| `exploits/dos/ssdp_amplification` | Sends spoofed SSDP M-SEARCH requests to UPnP/SSDP targets, causing amplified responses (~30x) directed at the victim via raw UDP with IP_HDRINCL. | Normal |  |
| `exploits/dos/syn_ack_flood` | Sends SYN packets to reflector servers with spoofed victim source IP, causing SYN-ACK responses directed at the victim for amplification. | Normal |  |
| `exploits/dos/tcp_connection_flood` | TCP connection flood with optional RST close and HTTP payload delivery for denial of service testing. | Normal |  |
| `exploits/dos/telnet_iac_flood` | Exploits unbounded IAC subnegotiation (SB without SE) and rapid WILL/DO option cycling to exhaust CPU and memory on telnet daemons, bruteforce tools, and honeypots. Four modes: WILL/DO storm, SB decompression bomb, NOP interleave, and combined. | Normal |  |
| `exploits/dos/udp_flood` | High-speed UDP flood with optional source IP spoofing via raw sockets. Supports random, null, and pattern payload modes. | Normal |  |
| `exploits/frameworks/apache_camel/cve_2025_27636_camel_header_injection` | Code injection via HTTP headers in Apache Camel routes that use the | Great |  |
| `exploits/frameworks/apache_tomcat/catkiller_cve_2025_31650` | Exploits CVE-2025-31650 memory leak in Apache Tomcat 10.1.10-10.1.39 via invalid HTTP/2 priority headers. | Normal |  |
| `exploits/frameworks/apache_tomcat/cve_2025_24813_apache_tomcat_rce` | Exploits CVE-2025-24813 deserialization vulnerability in Apache Tomcat for remote code execution. | Excellent |  |
| `exploits/frameworks/apache_tomcat/cve_2025_24813_tomcat_put_rce` | Unauthenticated RCE via partial PUT upload and Java deserialization. | Excellent | ✓ |
| `exploits/frameworks/exim/exim_etrn_sqli_cve_2025_26794` | Exploits CVE-2025-26794 time-based SQL injection in Exim ETRN command when using SQLite backend. | Good |  |
| `exploits/frameworks/h3c_bmc/h3c_websocket_dump` | H3C iBMC firmware accepts an unauthenticated WebSocket upgrade on TCP/8090 that immediately dumps a JSON chassis status block and proxies arbitrary Redfish GETs into the management plane — bypassing the auth gate on the :443 Redfish HTTPS API. Also supports a pipelined-frame race condition where a JSON command sent in the same TCP segment as the HTTP upgrade is processed before the WebSocket dispatcher attaches an auth context. | Excellent | ✓ |
| `exploits/frameworks/http2/cve_2023_44487_http2_rapid_reset` | Exploits CVE-2023-44487 HTTP/2 Rapid Reset vulnerability to cause denial of service via rapid stream creation and reset. | Normal |  |
| `exploits/frameworks/jenkins/jenkins_2_441_lfi` | Exploits CVE-2024-23897 CLI argument injection in Jenkins 2.441 and earlier for arbitrary file read. | Good |  |
| `exploits/frameworks/jenkins/jenkins_args4j_rce_cve_2024_24549` | Exploits the args4j parser via the connect-node CLI command with @-prefixed file paths to leak arbitrary file contents through error messages. | Great |  |
| `exploits/frameworks/jenkins/jenkins_cli_rce_cve_2024_23897` | Exploits the args4j argument parser in Jenkins CLI to read arbitrary files from the server via @-expansion in command arguments. Sends POST to /cli?remoting=false. | Great |  |
| `exploits/frameworks/mongo/mongobleed` | Exploits CVE-2025-14847 zlib decompression bug in MongoDB Server to leak uninitialized heap memory via BSON field names. | Good |  |
| `exploits/frameworks/nginx/nginx_pwner` | Checks for common Nginx misconfigurations and vulnerabilities including alias traversal, CRLF injection, and more. | Good |  |
| `exploits/frameworks/php/cve_2024_4577` | Exploits CVE-2024-4577 PHP CGI argument injection on Windows (XAMPP) for remote code execution. | Excellent |  |
| `exploits/frameworks/php/cve_2025_51373_php_rce` | PHP CGI argument injection on Windows via soft hyphen (0xAD) code-page | Excellent |  |
| `exploits/frameworks/wsus/cve_2025_59287_wsus_rce` | Unauthenticated RCE in Windows Server Update Services (WSUS). | Great | ✓ |
| `exploits/ftp/ftp_bounce_test` | Tests FTP servers for bounce attack vulnerability by attempting PORT commands to third-party hosts. | Good |  |
| `exploits/ftp/ftp_default_creds` | Tries a built-in (or user-supplied) list of common user:password pairs against an FTP service. On success it issues PWD then disconnects — no directory listing, transfer or write is performed. Designed for credential-hygiene checks during sanctioned engagements. | Good | ✓ |
| `exploits/ftp/pachev_ftp_path_traversal_1_0` | Exploits directory traversal vulnerability in Pachev FTP Server 1.0 to read files outside the FTP root. | Good |  |
| `exploits/honeytrap/docker_panic` | Sends POST /v1.40/images/create without a fromImage query parameter to honeytrap's Docker emulation. The handler indexes a nil map value → 'index out of range' panic. No recover() in the chain → daemon exit. | Good |  |
| `exploits/honeytrap/ftp_panic` | Sends a malformed FTP PORT command (`PORT 1,2,3` — only 4 fields) to honeytrap's FTP honeypot. The handler calls nums[4] without a length check → slice out of range panic → no recover() → daemon exits. | Good |  |
| `exploits/ipmi/ipmi_enum_exploit` | Comprehensive IPMI scanner with version detection, cipher 0 bypass, default credential brute force, and RAKP hash dumping. | Good |  |
| `exploits/network_infra/apache_modssl_bypass_cve_2025_23048` | Detects Apache HTTPD with mod_ssl by Server header; client-cert auth | Good | ✓ |
| `exploits/network_infra/arista_ngfw_disclose` | Probes Arista NGFW for the unauthenticated internal RPC endpoint. | Good | ✓ |
| `exploits/network_infra/checkpoint_fileread_cve_2024_24919` | Probes Check Point Security Gateway portals for the unauthenticated | Great | ✓ |
| `exploits/network_infra/cisco/cisco_ise_api_inject_cve_2025_20281` | Detects Cisco ISE 3.1/3.2 ERS API and probes the unauthenticated | Great | ✓ |
| `exploits/network_infra/citrix/cve_2025_5777_citrixbleed2` | Out-of-bounds read in Citrix NetScaler ADC/Gateway authentication endpoint. | Good | ✓ |
| `exploits/network_infra/commvault/cve_2025_34028_commvault_rce` | Pre-authentication remote code execution in Commvault Command Center | Excellent |  |
| `exploits/network_infra/f5/cve_2025_53521_f5_bigip_rce` | Unauthenticated remote code execution in F5 BIG-IP Access Policy Manager. | Great | ✓ |
| `exploits/network_infra/fortinet/forticloud_sso_auth_bypass_cve_2026_24858` | Authentication bypass via alternate path in Fortinet products with FortiCloud SSO enabled. Allows reusing SSO tokens to access other customers' appliances. | Normal |  |
| `exploits/network_infra/fortinet/fortigate_rce_cve_2024_21762` | Critical out-of-bounds write vulnerability in FortiOS SSL VPN allowing unauthenticated remote code execution via crafted HTTP requests to /remote/hostcheck_validate. | Normal |  |
| `exploits/network_infra/fortinet/fortimanager_rce_cve_2024_47575` | Critical missing authentication vulnerability in FortiManager fgfmd daemon allowing unauthenticated remote code execution via crafted FGFM registration requests on port 541. | Good |  |
| `exploits/network_infra/fortinet/fortios_auth_bypass_cve_2022_40684` | Authentication bypass on FortiOS/FortiProxy/FortiSwitchManager administrative interface via crafted HTTP headers, allowing unauthenticated API access. | Great |  |
| `exploits/network_infra/fortinet/fortios_heap_overflow_cve_2023_27997` | Pre-authentication heap-based buffer overflow in FortiOS SSL VPN allowing remote code execution via crafted requests to /remote/logincheck with oversized payload. | Normal |  |
| `exploits/network_infra/fortinet/fortios_ssl_vpn_cve_2018_13379` | Path traversal in FortiOS SSL VPN web portal to leak session files containing cleartext credentials. | Great |  |
| `exploits/network_infra/fortinet/fortisiem_rce_cve_2025_64155` | Unauthenticated remote code execution in FortiSIEM phMonitor service via argument injection in XML payload over SSL binary protocol. | Great |  |
| `exploits/network_infra/fortinet/fortiweb_rce_cve_2021_22123` | Authenticated command injection in FortiWeb SAML Server configuration via server-name parameter. Requires valid credentials. | Normal |  |
| `exploits/network_infra/fortinet/fortiweb_sqli_rce_cve_2025_25257` | Probes FortiWeb (≤ 7.0.10 / 7.2.10 / 7.4.7 / 7.6.3) for the unauthenticated SQLi that escalates to RCE via webshell deployment. Sends a benign UNION SELECT marker — no webshell write. | Great |  |
| `exploits/network_infra/hpe/cve_2025_37164_hpe_oneview_rce` | Unauthenticated RCE via REST API command injection in HPE OneView. | Excellent | ✓ |
| `exploits/network_infra/hpprocurve_disclose` | Detects HP ProCurve 4.00 admin web; reads /config/credentials disclosure. | Normal | ✓ |
| `exploits/network_infra/hpprocurve_snac_inject` | Detects HP ProCurve SNAC controller endpoints; PHP injection via management form. | Normal | ✓ |
| `exploits/network_infra/ivanti/cve_2025_0282_ivanti_preauth_rce` | Detects Ivanti Connect Secure gateways running pre-22.7R2.5 firmware vulnerable to CVE-2025-0282. Probe only — no payload sent. | Great | ✓ |
| `exploits/network_infra/ivanti/cve_2025_22457_ivanti_ics_rce` | Probes for the X-Forwarded-For stack overflow in Ivanti Connect Secure / Policy Secure / ZTA Gateway pre-22.7R2.6. Sends an oversized header and inspects the response banner. Probe only — no shellcode. | Great | ✓ |
| `exploits/network_infra/ivanti/ivanti_connect_secure_stack_based_buffer_overflow` | Critical stack-based buffer overflow in Ivanti Connect Secure, Policy Secure, and ZTA Gateways via crafted X-Forwarded-For header. CVSS 9.0. | Normal |  |
| `exploits/network_infra/ivanti/ivanti_epmm_cve_2023_35082` | Authentication bypass in Ivanti Endpoint Manager Mobile allowing unauthenticated access to user information via API endpoints. | Great |  |
| `exploits/network_infra/ivanti/ivanti_ics_auth_bypass_cve_2024_46352` | Authentication bypass in Ivanti Connect Secure via path traversal in the /api/v1/totp/user-backup-code endpoint, allowing unauthenticated access to protected resources. | Great |  |
| `exploits/network_infra/ivanti/ivanti_neurons_rce_cve_2025_22460` | Deserialization vulnerability in Ivanti Neurons for ITSM allowing unauthenticated remote code execution via crafted requests to the /api/now/ endpoint. | Normal |  |
| `exploits/network_infra/juniper_screenos_scanner` | Probes Juniper ScreenOS for the historical hard-coded backdoor. | Normal | ✓ |
| `exploits/network_infra/kubernetes/cve_2025_1974_ingress_nginx_rce` | The ingress-nginx admission webhook does not validate NGINX | Excellent |  |
| `exploits/network_infra/qnap/qnap_qts_rce_cve_2024_27130` | Stack buffer overflow in QNAP QTS No_Support_ACL function via share.cgi, allowing remote code execution. Affects QNAP QTS, QuTScloud, and QTS hero. | Normal |  |
| `exploits/network_infra/sonicwall/cve_2025_40602_sonicwall_sma_rce` | Detects SonicWall SMA1000 series management/auth surfaces vulnerable to CVE-2025-40602. Probe only — banner / endpoint check, no payload. | Great | ✓ |
| `exploits/network_infra/trend_micro/cve_2025_5777` | Unauthenticated command injection in Trend Micro Apex Central via Login.aspx endpoint. | Great |  |
| `exploits/network_infra/trend_micro/cve_2025_69258` | Unauthenticated DLL loading via Trend Micro MsgReceiver service on port 20001, allowing remote code execution. | Great |  |
| `exploits/network_infra/trend_micro/cve_2025_69259` | Denial of service via unchecked NULL return value in Trend Micro MsgReceiver service, causing service crash. | Normal |  |
| `exploits/network_infra/trend_micro/cve_2025_69260` | Denial of service via out-of-bounds read in Trend Micro MsgReceiver service, causing service crash. | Normal |  |
| `exploits/network_infra/vmware/esxi_auth_bypass_cve_2024_37085` | VMware ESXi authentication bypass via Active Directory group manipulation. Attackers with AD access can create the 'ESX Admins' group to gain full admin access to ESXi hosts. | Normal |  |
| `exploits/network_infra/vmware/esxi_vm_escape_check` | Checks ESXi hosts for vulnerability to VM escape chain (CVE-2025-22224, CVE-2025-22225, CVE-2025-22226) and detects indicators of compromise. | Good |  |
| `exploits/network_infra/vmware/esxi_vsock_client` | VSOCK client for communicating with VSOCKpuppet backdoor on compromised ESXi hosts after successful VM escape exploitation. | Manual | ✓ |
| `exploits/network_infra/vmware/vcenter_backup_rce` | Authenticated remote code execution in VMware vCenter Server via flag injection in backup.validate API locationUser parameter. CVSS 7.2. | Great |  |
| `exploits/network_infra/vmware/vcenter_file_read` | Authenticated partial arbitrary file read in VMware vCenter Server via RVC command. CVSS 4.9. | Good |  |
| `exploits/network_infra/vmware/vcenter_rce_cve_2024_37079` | Critical heap-overflow vulnerability in VMware vCenter Server DCERPC protocol implementation allowing unauthenticated remote code execution via crafted packets to port 443. | Normal |  |
| `exploits/payloadgens/obfuscator` | Multi-layer payload obfuscator. Twenty-four methods (XOR / RC4 / base16/32/32hex/64/64url/85/91 / ROT13 / ROT47 / reverse / gzip / URL / Caesar / bit-rotate / Vigenère / zero-width / hex-split / UTF-16LE / char-substitution / ANSI-escape / chunk-permute) and seven output formats (raw, recipe, Python / PowerShell / Bash / JavaScript self-decoder, C array). Three modes: chain (explicit order), random (auto N rounds), same (one method N times). Default 4 rounds, user-overridable up to 32. All randomness from OS RNG; chains are reproducible via the recipe. Engine lives in native::obfuscator_engine; this module is the prompt-driven UI. | Normal | ✓ |
| `exploits/payloadgens/payloadgen` | Unified payload generator. Modes: bat (BAT chain dropper), lnk (malicious LNK for NTLMv2-SSP hash disclosure CVE-2025-50154 / CVE-2025-59214), narutto (polymorphic 3-stage LOLBAS dropper), polymorph (3-stage Task-Scheduler dropper), encode (multi-stage payload encoder — base16/32/64/url/shell/html/zero-width), or menu for an interactive selector. Same prompt keys as the previous individual modules so existing automation migrates with `mode=<bat\|lnk\|narutto\|polymorph\|encode>`. | Normal | ✓ |
| `exploits/routers/dlink/dlink_dcs_930l_auth_bypass` | Authentication bypass via unauthenticated configuration disclosure on D-Link DCS-930L/932L cameras. Retrieves and deobfuscates credentials from /frame/GetConfig. | Great |  |
| `exploits/routers/netgear/netgear_r6700v3_rce_cve_2022_27646` | Pre-authentication buffer overflow in Netgear R6700v3 circled daemon allowing remote code execution. Based on Pwn2Own Austin 2021 exploit. | Normal |  |
| `exploits/routers/palo_alto/panos_authbypass_cve_2025_0108` | Authentication bypass in Palo Alto Networks PanOS via path traversal in the authentication mechanism, allowing unauthenticated access to administrative functions. | Great |  |
| `exploits/routers/palo_alto/panos_expedition_rce_cve_2024_9463` | Unauthenticated OS command injection in Palo Alto Expedition | Excellent |  |
| `exploits/routers/palo_alto/panos_globalprotect_rce_cve_2024_3400` | Unauthenticated OS command injection in PAN-OS GlobalProtect gateway. | Excellent |  |
| `exploits/routers/ruijie/ruijie_auth_bypass_rce_cve_2023_34644` | Authentication bypass leading to remote code execution on Ruijie RG-EW routers, RG-NBS/RG-S1930 switches, RG-EG VPN routers, and EAP/RAP access points. CVSS 9.8. | Excellent |  |
| `exploits/routers/ruijie/ruijie_reyee_ssrf_cve_2024_48874` | Server-Side Request Forgery in Ruijie Reyee cloud-connected devices. Part of the Open Sesame vulnerability chain discovered by Claroty Team82. CVSS 8.6. | Good |  |
| `exploits/routers/ruijie/ruijie_rg_ew_login_bypass_cve_2023_4415` | Authentication bypass on Ruijie RG-EW1200G routers via crafted JSON login request to /api/sys/login. CVSS 9.8. | Great |  |
| `exploits/routers/ruijie/ruijie_rg_ew_password_reset_cve_2023_4169` | Unauthenticated admin password reset on Ruijie RG-EW1200G routers via /api/sys/set_passwd endpoint. CVSS 9.8. | Great |  |
| `exploits/routers/ruijie/ruijie_rg_ew_update_version_rce_cve_2021_43164` | Remote code execution via command injection in firmware update function on Ruijie RG-EW Series routers up to ReyeeOS 1.55.1915. CVSS 9.8. | Excellent |  |
| `exploits/routers/ruijie/ruijie_rg_uac_ci_cve_2024_4508` | Critical unauthenticated command injection in Ruijie RG-UAC via static_route_edit_ipv6.php route parameters. CVSS 9.8. | Great |  |
| `exploits/routers/ruijie/ruijie_rsr_router_ci_cve_2024_31616` | Authenticated command injection via backtick in Ruijie RSR10-01G-T-S router diagnostic endpoints. CVSS 8.8. | Great |  |
| `exploits/routers/tenda/tenda_cp3_rce_cve_2023_30353` | Command injection in Tenda CP3 IP Camera via YGMP_CMD message on UDP port 5012, allowing unauthenticated remote code execution. | Excellent |  |
| `exploits/routers/tplink/tapo_c200_vulns` | Multiple vulnerabilities in TP-Link Tapo C200 including pre-auth WiFi network scanning info leak (CVE-2025-14300), WiFi hijacking, ONVIF SOAP XML parser memory overflow (CVE-2025-8065), and HTTPS Content-Length integer overflow (CVE-2025-14299). | Good |  |
| `exploits/routers/tplink/tp_link_vn020_dos` | Denial of service via malformed AddPortMapping SOAP request on TP-Link VN020 F3v(T) UPnP service. | Normal |  |
| `exploits/routers/tplink/tplink_archer_c2_c20i_rce` | Authenticated command injection via host parameter in diagnostic POST request on TP-Link Archer C2 and C20i routers. | Great |  |
| `exploits/routers/tplink/tplink_archer_c9_password_reset` | Exploits predictable PRNG for password reset code on TP-Link Archer C9/C60 routers, allowing unauthenticated admin password reset. | Great |  |
| `exploits/routers/tplink/tplink_archer_rce_cve_2024_53375` | Authenticated command injection in TP-Link Archer, Deco, and Tapo series routers via OwnerId parameter in /admin/smart_network endpoint. | Great |  |
| `exploits/routers/tplink/tplink_ax1800_rce_cve_2024_53375` | Authenticated command injection in TP-Link Archer AX1800 via the NTP server configuration field. The NTP server value is passed to os.execute() without sanitization. | Great |  |
| `exploits/routers/tplink/tplink_deco_m4_rce` | Tests default admin:admin credentials on TP-Link Deco M4, then exploits the diagnostic ping field for command injection via /cgi-bin/luci/admin/network/diagnostics. | Great |  |
| `exploits/routers/tplink/tplink_tapo_c200` | Probes TP-Link Tapo C200 IP cameras for command injection via the setLanguage JSON-RPC method on TCP/8800. Probe-only echo-marker. | Excellent |  |
| `exploits/routers/tplink/tplink_vigi_c385_rce_cve_2026_1457` | Detects TP-Link VIGI C385 V1 web UI vulnerable to the authenticated set_resolution buffer overflow. Probe only — requires creds, sourced separately. | Great |  |
| `exploits/routers/tplink/tplink_wdr740n_backdoor` | Exploits a debug page on TP-Link WDR740ND/WDR740N routers that allows command execution with hardcoded credentials (osteam/5up). | Great |  |
| `exploits/routers/tplink/tplink_wdr740n_path_traversal` | Path traversal on TP-Link WDR740ND/WDR740N routers allowing arbitrary file read from the filesystem via /help/ endpoint. | Good |  |
| `exploits/routers/tplink/tplink_wdr842n_configure_disclosure` | Downloads and decrypts configuration from TP-Link WDR842ND/WDR842N routers via /config.bin, extracting credentials using DES decryption. | Good |  |
| `exploits/routers/tplink/tplink_wr740n_dos` | Buffer overflow denial of service in TP-Link TL-WR740N router web server, crashing the HTTP service and requiring physical reboot. | Normal |  |
| `exploits/routers/ubiquiti/ubiquiti_edgerouter_ci_cve_2023_2376` | Command injection in Ubiquiti EdgeRouter X Web Management Interface affecting versions up to 2.0.9-hotfix.6. | Great |  |
| `exploits/routers/zte/zte_zxv10_h201l_rce_authenticationbypass` | Authentication bypass and remote code execution on ZTE ZXV10 H201L routers via configuration leak, credential extraction, and DDNS command injection. | Great |  |
| `exploits/routers/zyxel/zyxel_cpe_ci_cve_2024_40890` | Probes legacy Zyxel CPE devices for HTTP-based unauthenticated command injection. EOL hardware — no patches. Probe sends a benign echo-marker. | Great |  |
| `exploits/safeline/cookie_attributes` | Sends one POST /api/Login with an invalid passcode to observe the Set-Cookie header. The session cookie lacks HttpOnly, Secure, and SameSite attributes — enabling XSS-based session theft, CSRF, and plaintext transmission when TLS is upstream-terminated. | Normal |  |
| `exploits/safeline/nginx_injection` | Sends an authenticated POST /api/Website to SafeLine with a malicious Ports field. The tcontrollerd process inserts the value verbatim into an nginx config template via fmt.Sprintf → arbitrary directive injection. On nginx reload the injected config takes effect on the WAF host. | Great |  |
| `exploits/safeline/no_auth_probe` | Sends unauthenticated GET requests to protected SafeLine endpoints. If the operator has set the NO_AUTH env var, main.go:162 uses `len(noAuth) >= 0` (always true), disabling the auth middleware. A 200 response with data confirms the bypass. | Good |  |
| `exploits/safeline/pre_auth_tfa` | On fresh SafeLine installs (LastLoginTime == 0), GET /api/OTPUrl is unauthenticated and rotates the TFA secret, returning the new otpauth:// URL. This module fetches the secret, computes the current TOTP code, and logs in as super-user — account takeover without credentials. | Excellent |  |
| `exploits/safeline/session_secret_entropy` | SafeLine generates its JWT/session signing secret with math/rand seeded by time.Now().UnixNano(). Effective entropy is log2(install_window_ns) — as low as 39 bits for a known 10-minute window. This module prints the entropy analysis and optionally probes the Set-Cookie header to confirm the signed cookie mechanism is in use. | Normal |  |
| `exploits/safeline/unauth_writes` | POST /api/Behaviour and POST /api/FalsePositives are in SafeLine's publicRouters (no auth required). Any client can write arbitrary data to the behaviour analytics DB and trigger per-request outbound HTTPS calls via /api/FalsePositives — analytics pollution, storage DoS, and request amplification. | Good |  |
| `exploits/sample_exploit` | A demonstration exploit that checks if a target endpoint is vulnerable. | Normal | ✓ |
| `exploits/snare/cookie_dos` | Sends an HTTP GET with a Cookie header that has no '=' separator to snare. The tanner_handler.py dict comprehension calls `cookie.split('=')[1]` unconditionally → IndexError → worker crash. | Normal |  |
| `exploits/snare/tanner_version_mitm` | Binds a rogue HTTP server on port 8090 that returns a forged {"version": "X.Y.Z"} response to GET /version. When snare is launched with --tanner pointing to this host, it accepts the forged version and starts up — demonstrating that the version check has no cryptographic authenticity guarantee. | Normal |  |
| `exploits/ssh/asyncssh_beginauthpass` | Exploits AsyncSSH servers whose SSHServer.begin_auth() returns False, causing USERAUTH_SUCCESS to be sent immediately. Opens a session after bypass and runs an arbitrary command. | Great |  |
| `exploits/ssh/erlang_otp_ssh_rce_cve_2025_32433` | Unauthenticated RCE in Erlang/OTP SSH server. | Great | ✓ |
| `exploits/ssh/libssh2_rogue_server` | Starts a rogue SSH server that accepts ALL authentication attempts regardless of credentials. Exploits libssh2 clients that accept USERAUTH_SUCCESS without verifying KEX state (userauth.c:201,396,1714). Captures username, password, and public key fingerprints. | Excellent |  |
| `exploits/ssh/libssh_auth_bypass_cve_2018_10933` | Authentication bypass in libSSH server. | Excellent | ✓ |
| `exploits/ssh/openssh_regresshion_cve_2024_6387` | Signal handler race condition in OpenSSH sshd allows unauthenticated | Normal | ✓ |
| `exploits/ssh/opensshserver_9_8p1race_condition` | Exploits a race condition in OpenSSH server 9.8p1 for remote code execution via heap-based glibc exploitation. | Normal |  |
| `exploits/ssh/paramiko_authnonepass` | Exploits Paramiko-based SSH servers that mistakenly return AUTH_SUCCESSFUL from check_auth_none(). Sends an SSH2 'none' userauth request and, if the server accepts it, opens a session channel and runs an arbitrary command. Tested against paramiko 4.0.0. | Great |  |
| `exploits/ssh/paramiko_unknown_method` | Exploits Paramiko-based SSH servers where an unrecognized auth method falls through to check_auth_none() (auth_handler.py:721-724). If check_auth_none() returns AUTH_SUCCESSFUL, any bogus method name authenticates the client. Tested against paramiko 4.0.0. | Great |  |
| `exploits/ssh/sshpwn_auth_passwd` | Exploits OpenSSH auth2-passwd.c vulnerabilities including password length DoS, password change info leak, and timing-based user enumeration. | Normal |  |
| `exploits/ssh/sshpwn_pam` | Exploits OpenSSH auth-pam.c vulnerabilities including environment variable injection, memory leak DoS, and username length validation bypass. | Normal |  |
| `exploits/ssh/sshpwn_scp_attacks` | Exploits OpenSSH SCP vulnerabilities including path traversal via filename manipulation, command injection, and brace expansion DoS. | Normal |  |
| `exploits/ssh/sshpwn_session` | Exploits OpenSSH session.c and sshd-session.c vulnerabilities including forced command bypass, environment variable injection, and privilege separation issues. | Good |  |
| `exploits/ssh/sshpwn_sftp_attacks` | Exploits OpenSSH SFTP server vulnerabilities including symlink injection, chmod setuid abuse, path traversal, and partial write issues. | Normal |  |
| `exploits/telnet/telnet_auth_bypass_cve_2026_24061` | Exploits CVE-2026-24061 to bypass telnet authentication on vulnerable devices. | Excellent |  |
| `exploits/vnc/libvnc_checkrect_overflow` | LibVNCClient vncviewer.c:115-117 uses signed 32-bit bounds checks (x+w > fb_width). At x=0x7FFFFFFF, w=1: x+w wraps to INT_MIN — negative, bypasses check. Raw pixel data is then written past the allocated framebuffer → heap overflow → RCE. This module acts as a malicious VNC server. | Normal | ✓ |
| `exploits/vnc/libvnc_tight_filtergradient` | LibVNCClient tight.c:468-522 reads numRows from the decompressed Tight stream and drives the gradient filter loop without clamping to the rect height. A crafted stream claiming numRows=10000 for a 20-row rect writes far past the allocated heap buffer → OOB write → RCE. Malicious server module. | Normal | ✓ |
| `exploits/vnc/libvnc_ultrazip` | LibVNCClient ultra.c:100-150 (CVE-2018-20750) reads numCacheRects from the UltraZip wire stream and loops that many times memcpy-ing into a fixed-size rect cache (~200 entries) without bounds-checking. numCacheRects=0xFFFF with 1 real entry → heap overflow → RCE. Malicious server module. | Normal | ✓ |
| `exploits/vnc/libvnc_websocket_overflow` | LibVNCServer ws_decode.c:219-254 reads a 64-bit WebSocket frame payloadLen and uses it without bounding against the receive buffer size. Sending a binary frame with payloadLen=0xFFFFFFFFFFFF and 0 bytes of actual data triggers a heap overflow → server crash / RCE. | Good |  |
| `exploits/vnc/libvnc_zrle_tile` | LibVNCClient zrle.c:201-209 does not track bytes consumed per tile during decompression. A truncated RLE tile provides only 1 pixel run but the tile covers 64×64 pixels; the client reads ~4095 extra runs from beyond the decompressed buffer → heap over-read → potential info-leak or RCE. Malicious server module. | Normal | ✓ |
| `exploits/vnc/tigervnc_rre_overflow` | TigerVNC's RRE decoder reads numSubrects from the wire as u32 and loops that many times, reading 4+bpp bytes per subrect without bounds-checking the received buffer. numSubrects=0xFFFFFFFF with a minimal body forces the client to read past the heap buffer → RCE. Malicious server module. | Normal | ✓ |
| `exploits/vnc/tigervnc_timing_oracle` | TigerVNC's VNC auth handler may exhibit measurable timing differences between a correct and incorrect first-block DES response. Repeated auth attempts with crafted 16-byte responses and RTT measurement can leak partial key information. Highly noisy — requires low-latency controlled network. Rank: Low. | Low |  |
| `exploits/vnc/tightvnc_decompression_bomb` | TightVNC's FileUploadData handler (FileTransferRequestHandler.cpp:582-590) uses the wire `uncompressedSize` field without any cap. Sending a tiny zlib payload (~13 bytes) claiming 2 GiB uncompressed forces the server to allocate gigabytes → heap exhaustion → process crash / OOM-kill. DESTRUCTIVE. | Normal |  |
| `exploits/vnc/tightvnc_des_hardcoded_key` | TightVNC stores the VNC password encrypted with a hardcoded 8-byte DES key (VncPassCrypt.cpp:29-44). The 8-byte ciphertext lives in the Windows registry at HKLM\SOFTWARE\TightVNC\Server\Password. Any user who can read that value can recover the plaintext offline in microseconds. No network interaction required. | Excellent | ✓ |
| `exploits/vnc/tightvnc_ft_path_traversal` | Detects TightVNC servers exposing the file-transfer extension. The full exploit needs an authenticated session; this probe only confirms the surface is reachable. | Excellent |  |
| `exploits/vnc/tightvnc_predictable_challenge` | TightVNC fills the 16-byte RFB challenge with srand(time(0))+rand(). Two connections in the same wall-clock second receive identical challenges, allowing replay attacks or offline PRNG reconstruction. Bug: RfbInitializer.cpp:173-175. | Good |  |
| `exploits/vnc/tightvnc_rect_overflow` | TightVNC Rect::area() uses signed int32 multiplication (Rect.h:172). At 0x8001×0x8001 the product wraps, causing TightEncoder to allow a 300-entry palette write past the 256-entry heap buffer → RCE. This module acts as a malicious VNC server; point a TightVNC/LibVNCClient viewer at the listen address. | Normal | ✓ |
| `exploits/vnc/x11vnc_dns_injection` | x11vnc connections.c:1665-1670 calls gethostbyaddr() on the connecting client IP and passes the result UNSANITISED to system() when -accept xmessage is set. A crafted PTR record containing shell metacharacters achieves RCE as the x11vnc user. Requires a rogue DNS server — this module prints the setup recipe. Rank: Manual. | Manual |  |
| `exploits/vnc/x11vnc_env_injection` | x11vnc populates the RFB_CLIENT_IP environment variable from the connecting client's source IP address and passes it to hook scripts. If hook scripts interpolate this variable unsafely (e.g. in shell `exec $RFB_CLIENT_IP`), and the attacker controls the source IP routing, shell injection achieves RCE. This module prints the setup recipe. Rank: Manual. | Manual |  |
| `exploits/vnc/x11vnc_unixpw_inject` | x11vnc -unixpw mode sends a plaintext username+password challenge over the VNC channel without stripping newlines from the username field. Injecting \n in the username can confuse the PAM interaction, potentially bypassing authentication or creating unexpected auth state. | Normal |  |
| `exploits/voip/cve_2025_64328_freepbx_cmdi` | Post-authentication command injection in FreePBX filestore module. | Great | ✓ |
| `exploits/voip/magnusbilling_ssrf_cve_2023_30258` | Detects MagnusBilling 6 panel; multiple unauth weaknesses including SSRF and traversal. | Good | ✓ |
| `exploits/voip/xorcompbx_rce` | Detects Xorcom CompletePBX login portal; auth-required RCE via shell injection in admin endpoints. | Normal | ✓ |
| `exploits/webapps/aiplugins_rce_cve_2025_23968` | Detects unauthenticated arbitrary file upload in Cibeles AI, | Great | ✓ |
| `exploits/webapps/api_attack_suite` | Active offensive sweep covering every API attack category in PortSwigger's Web Security Academy. Accepts either a target URL OR a raw captured HTTP request (Burp 'Copy as raw request'); when a captured request is provided, fingerprints the stack, walks every fuzzable parameter (query, JSON body recursive, headers, cookies), auto-detects already-privileged fields (`admin: true`, `role: ...`) and flips them, then runs verb tampering, auth bypass, HPP, mass-assign, BOLA, content-type confusion, GraphQL attacks, JWT none-alg, rate-limit, and sensitive-field exposure. Two interaction modes (interactive / auto) — same surface across shell / CLI / API / MCP. | Normal | ✓ |
| `exploits/webapps/azureapim_checker` | Probes Azure APIM developer portal endpoints for cross-tenant signup | Normal | ✓ |
| `exploits/webapps/azuriom_csti_cve_2025_65271` | Detects Azuriom admin dashboard; client-side template injection enables | Normal | ✓ |
| `exploits/webapps/beego_traversal_lfi` | Detects Beego applications vulnerable to %5c-encoded path traversal. | Good | ✓ |
| `exploits/webapps/cacti_graph_rce_cve_2025_24367` | Detects Cacti ≤ 1.2.29 and verifies authenticated access | Good | ✓ |
| `exploits/webapps/casdoor_traversal_cve_2023_34927` | Detects Casdoor 2.95.0 vulnerable to %5c-encoded path traversal. | Good | ✓ |
| `exploits/webapps/cbitrix_translate_upload_cve_2025_67887` | Detects 1C-Bitrix CMS ≤ 25.100.500 exposing the Translate module | Good | ✓ |
| `exploits/webapps/cinnamon_kotaemon_zip_dos_cve_2025_63914` | Detects Cinnamon kotaemon ≤ 0.11.0 by Gradio fingerprint. | Normal | ✓ |
| `exploits/webapps/cleo_harmony_filewrite_cve_2024_55956` | Detects Cleo Harmony / VLTrader / LexiCom MFT 5.8.0.23 by web banner. | Great | ✓ |
| `exploits/webapps/clipbucket_rce_cve_2025_55911` | Detects ClipBucket 5.5.2 build 90 video platform. | Good | ✓ |
| `exploits/webapps/cloudbleed_scanner` | Sends malformed HTML probes and inspects responses for | Normal | ✓ |
| `exploits/webapps/commvault_cli_rce_cve_2025_57788` | Probes Commvault Command Center for the unauth RCE chain | Great | ✓ |
| `exploits/webapps/convio_sqli` | Probes Convio CMS endpoints for SQL error markers in `id` parameter. | Normal | ✓ |
| `exploits/webapps/coohom_xss` | Detects Coohom application; reflected XSS via input parameters. | Normal | ✓ |
| `exploits/webapps/cpms_authbypass` | Detects CPMS 2.0 admin login; SQLi or hardcoded credentials enable unauth admin access. | Normal | ✓ |
| `exploits/webapps/craftcms_key_rce_cve_2025_23209` | RCE in Craft CMS when the application security key is known or leaked. | Normal | ✓ |
| `exploits/webapps/craftcms_logicflaw` | Detects Craft CMS 5.0; image-transform endpoint authenticates via | Normal | ✓ |
| `exploits/webapps/craftcms_rce_cve_2025_47726` | Remote Code Execution via Server-Side Template Injection in Craft CMS. | Great | ✓ |
| `exploits/webapps/craftcms_ssti_scanner` | Submits {{7*7}} via search/path parameters and looks for "49" reflection. | Normal | ✓ |
| `exploits/webapps/crafty_controller_rce_cve_2025_14700` | Detects Crafty Controller; auth-required SSTI in template configuration enables RCE. | Good | ✓ |
| `exploits/webapps/dify/cve_2025_56157_dify_default_creds` | Checks for default PostgreSQL credentials in Dify deployments. | Great | ✓ |
| `exploits/webapps/django_sqli_cve_2025_64459` | Probes Django apps for the QuerySet/Lookup SQLi affecting 5.1.x ≤ 5.1.13. | Good | ✓ |
| `exploits/webapps/dnnplatform_upload_cve_2025_64095` | Detects DNN (DotNetNuke) <10.1.1 with the HTML editor upload endpoint | Great | ✓ |
| `exploits/webapps/dotcms_blind_sqli_cve_2025_8311` | Authenticated time-based blind SQL injection in dotCMS 25.07.02-1 | Good | ✓ |
| `exploits/webapps/dotcms_scanner` | Detects dotCMS instances and reads /api/v1/system/version disclosure. | Normal | ✓ |
| `exploits/webapps/drupal11_pathdisclose_cve_2024_45440` | Triggers Drupal error responses that disclose the absolute filesystem path. | Normal | ✓ |
| `exploits/webapps/eduplus_idor` | Detects EduplusCampus student portal IDOR by enumerating | Normal | ✓ |
| `exploits/webapps/elementor_wb_sqli_cve_2023_0329` | Detects Elementor WP plugin <3.12.2; admin SQL injection in template endpoint. | Good | ✓ |
| `exploits/webapps/eramba_grc_rce_cve_2023_36255` | Detects Eramba GRC by login fingerprint; download-test-pdf is | Good | ✓ |
| `exploits/webapps/ffcw_inject` | Detects FileCatalyst Workflow login; PHP injection via workflow params. | Normal | ✓ |
| `exploits/webapps/flask_command_injection` | Probes a Flask app for SSTI and command-injection markers in | Normal | ✓ |
| `exploits/webapps/flatcore_upload_cve_2019_13961` | Detects flatCore 1.5 by login fingerprint; chained file upload to PHP RCE. | Good | ✓ |
| `exploits/webapps/flatpress_xsrf_shell` | Detects FlatPress 1.3 admin endpoints; CSRF + auth shell upload. | Good | ✓ |
| `exploits/webapps/flowise/cve_2024_31621` | Unauthenticated access to Flowise /API/V1/credentials endpoint, bypassing authentication in Flowise <= 1.6.5. | Great |  |
| `exploits/webapps/flowise/cve_2025_59528_flowise_rce` | Authenticated RCE in Flowise < 3.0.5 via customMCP endpoint expression injection. | Great |  |
| `exploits/webapps/flowise_js_inject_cve_2025_59528` | Detects Flowise UI/API; JS parsing injection allows code | Good | ✓ |
| `exploits/webapps/foxcms_inject_cve_2025_29306` | Detects FoxCMS 1.0 by admin fingerprint; PHP code injection in admin actions. | Good | ✓ |
| `exploits/webapps/fuguhub_rsakey_disclose_cve_2025_65790` | Probes FuguHub web-accessible documentation for an embedded RSA | Good | ✓ |
| `exploits/webapps/getsimple_csrf_cve_2021_28976` | Detects GetSimple CMS 3.3.16; missing anti-CSRF tokens on backup | Normal | ✓ |
| `exploits/webapps/gnuboard5_install` | Detects exposed /install/ endpoint of Gnuboard 5; if reachable, attacker can compromise installation parameters. | Good | ✓ |
| `exploits/webapps/gravcms_sandbox_bypass_cve_2025_66294` | Detects Grav CMS by the X-Generator header / login page; Twig sandbox bypass | Good | ✓ |
| `exploits/webapps/guppycms_shell` | Detects GuppY CMS via /admin login and probes for PHP injection in admin endpoints. | Normal | ✓ |
| `exploits/webapps/headlamp_unauth_disclose_cve_2025_14269` | Probes the Headlamp Kubernetes dashboard for unauthenticated | Good | ✓ |
| `exploits/webapps/hestia_inject` | Detects Hestia CP login portal; auth-required PHP code injection in admin scripts. | Normal | ✓ |
| `exploits/webapps/highcms_sqli` | Probes legacy HighCMS / HighPortal endpoints for blind SQL injection markers. | Normal | ✓ |
| `exploits/webapps/hpe_oneview_rce` | Probes HPE OneView REST API; authenticated Java deserialization | Normal | ✓ |
| `exploits/webapps/ias25_idor` | Detects IAS 2.5 admin panel; enumerates student record IDs via IDOR. | Normal | ✓ |
| `exploits/webapps/ias25_sqli` | Detects IAS 2.5 SQL injection via the login form parameters. | Normal | ✓ |
| `exploits/webapps/ias25_upload` | Detects IAS 2.5 admin upload form; chained with default creds → PHP RCE. | Normal | ✓ |
| `exploits/webapps/ibmbigfix_disclose` | Detects IBM BigFix Platform port and probes for unauth disclosure paths. | Normal | ✓ |
| `exploits/webapps/ictbroadcast_rce` | Detects ICTBroadcast 7.0 admin endpoint; auth RCE via DBC (Dynamic Broadcast Configuration). | Normal | ✓ |
| `exploits/webapps/iemm_eli_inject_cve_2025_4427` | Probes Ivanti EPM Mobile (formerly MobileIron Core) for the | Great | ✓ |
| `exploits/webapps/invision_csti_cve_2025_ic506` | Detects Invision Community 5.0.6; auth-required Expression Injection (SSTI) in customCss. | Normal | ✓ |
| `exploits/webapps/invoiceninja_inject` | Detects Invoice Ninja by the api/v1/ping endpoint; PHP code injection via auth-required template editor. | Normal | ✓ |
| `exploits/webapps/ioncube_loader_scanner` | Detects exposed ionCube wizard helper files (loader-wizard.php). | Normal | ✓ |
| `exploits/webapps/jenkins_fileread` | Detects Jenkins ≤ 2.441 vulnerable to arbitrary file read via the | Great | ✓ |
| `exploits/webapps/jsonpath_plus_rce_cve_2025_1302` | Submits a JSONPath expression that triggers JS evaluation; reflection | Normal | ✓ |
| `exploits/webapps/kalmia_user_enum_cve_2025_65899` | JWT auth endpoint leaks user existence based on returned message. | Normal | ✓ |
| `exploits/webapps/langflow/cve_2026_33017_build_public_tmp_rce` | Pre-auth RCE on Langflow ≤ 1.8.2 via `/api/v1/build_public_tmp/{flow_id}/flow`. The endpoint executes attacker-controlled Python code embedded in flow nodes during graph preparation. Default-deployed Langflow has `AUTO_LOGIN=true`, which the chain leverages to mint the required public-flow id without creds. | Excellent | ✓ |
| `exploits/webapps/langflow_rce_cve_2025_3248` | Unauthenticated RCE via Python exec() in Langflow code validation. | Excellent | ✓ |
| `exploits/webapps/laravel_livewire_rce_cve_2025_47949` | Remote Code Execution via unsafe deserialization in Laravel Livewire. | Great | ✓ |
| `exploits/webapps/laravel_pulse_inject_cve_2024_55661` | Detects Laravel Pulse dashboard at /pulse; remote_ip header / route | Normal | ✓ |
| `exploits/webapps/lepton_xss_rce` | Detects LEPTON CMS 7.4.0 admin endpoints; chained Stored XSS into | Normal | ✓ |
| `exploits/webapps/lgsimpleeditor_inject` | Detects LG Simple Editor by /login fingerprint; PHP code injection in editor endpoints. | Normal | ✓ |
| `exploits/webapps/librenms_inject` | Detects LibreNMS by /login fingerprint; auth-required PHP code injection. | Normal | ✓ |
| `exploits/webapps/limesurvey_filedownload` | Detects LimeSurvey 2.0 export endpoint that exposes uploaded files | Normal | ✓ |
| `exploits/webapps/magento_session_reaper_cve_2025_54236` | Probes Magento 2 / Adobe Commerce REST API for vulnerable build banners | Great | ✓ |
| `exploits/webapps/mangosweb_xss` | Probes mangosweb search/login endpoints for unsanitised reflection. | Normal | ✓ |
| `exploits/webapps/mantisbt_exec` | Detects Mantis Bug Tracker 2.30; auth RCE via filter/admin paths. | Normal | ✓ |
| `exploits/webapps/mcpjam/cve_2026_23744_mcpjam_rce` | Detects MCPJam Inspector ≤ 1.4.2 listening on a non-loopback interface. The Inspector accepts unauthenticated MCP server registrations, which is RCE in practice. Probe only. | Great |  |
| `exploits/webapps/misp_rce_cve_2025_27364` | Authenticated file upload to RCE in MISP < 2.5.3. The /events/upload_sample endpoint accepts arbitrary MIME types, allowing upload of PHP webshells when combined with a permissive server configuration. CVSS 8.8 High. | Normal |  |
| `exploits/webapps/mobiledetect_xss` | Probes endpoints that echo User-Agent for XSS reflection markers. | Normal | ✓ |
| `exploits/webapps/n8n/n8n_form_afr_cve_2026_21858` | POSTs `files.filepath` to a known n8n form-trigger workflow on n8n ≤ 1.65.0. Operator supplies the form path via `setg n8n_form_path /form/...` and the file via `setg n8n_target_file /etc/passwd`. Probe-only — does not chain into RCE. | Good | ✓ |
| `exploits/webapps/n8n/n8n_rce_cve_2025_68613` | Authenticated RCE in n8n 0.211.0-1.120.3/1.121.0 via expression injection in workflow Set nodes. CVSS 10.0 Critical. | Great |  |
| `exploits/webapps/nextjs_middleware_bypass_cve_2025_29927` | Bypasses Next.js middleware (auth, RBAC, redirects) by sending the | Great |  |
| `exploits/webapps/openrepeater_inject` | Detects OpenRepeater web UI; authenticated injection in audio/network configuration endpoints. | Normal | ✓ |
| `exploits/webapps/opensisce_sqli` | Detects openSIS classic; auth-bypass / SQLi via login form. | Normal | ✓ |
| `exploits/webapps/phpipam_sqli` | Detects phpIPAM and probes parameterised endpoints for SQL error markers. | Normal | ✓ |
| `exploits/webapps/phpmyadmin_sqli` | Detects phpMyAdmin and probes for known SQLi via designer endpoints. | Normal | ✓ |
| `exploits/webapps/phpmyfaq_xss` | Detects phpMyFAQ; reflected XSS via search and CSRF on admin endpoints. | Normal | ✓ |
| `exploits/webapps/pihole_redis_rce_cve_2024_34361` | Detects Pi-hole admin UI; authenticated SSRF + Redis abuse for RCE. | Good | ✓ |
| `exploits/webapps/piwigo_sqli` | Detects Piwigo gallery; SQLi via parameter abuse in admin endpoints. | Normal | ✓ |
| `exploits/webapps/pluck_upload` | Detects Pluck CMS; auth admin upload chained to PHP code execution. | Normal | ✓ |
| `exploits/webapps/react/react2shell` | Detects exposed React Server Components Flight endpoints (`?_rsc=` query parameter) that may be vulnerable to deserialization-based RCE on patched-but-misconfigured Next.js installations. Probe only. | Excellent |  |
| `exploits/webapps/react_rsc_rce_cve_2025_55182` | Detects React Server Components fingerprint; server-side serialisation | Good | ✓ |
| `exploits/webapps/redash_rce_hash` | Detects Redash via /api/admin/status; auth-required RCE via SQL data source helper. | Normal | ✓ |
| `exploits/webapps/rosariosis_xss` | Detects RosarioSIS login page; reflected XSS via search parameter. | Normal | ✓ |
| `exploits/webapps/roundcube/roundcube_postauth_rce` | Authenticated RCE in Roundcube webmail via PHP deserialization (Crypt_GPG_Engine gadget) in file upload. Affects versions 1.1.0-1.5.9 and 1.6.0-1.6.10. | Great |  |
| `exploits/webapps/sap_netweaver_rce_cve_2025_31324` | Unauthenticated file upload to RCE in SAP NetWeaver Visual Composer. | Excellent | ✓ |
| `exploits/webapps/sharepoint/cve_2024_38094` | Authenticated remote code execution in SharePoint Server via deserialization of malicious .bdcm file upload. Requires Site Owner privileges. CVSS 7.2. | Great |  |
| `exploits/webapps/sharepoint/cve_2025_53770_sharepoint_toolpane_rce` | Unauthenticated deserialization RCE in SharePoint on-premises. | Great | ✓ |
| `exploits/webapps/sharepoint_toolpane_cve_2025_53770` | Probes SharePoint Server for the ToolPane.aspx endpoint and missing | Excellent | ✓ |
| `exploits/webapps/smartermail/admin_password_reset_cve_2026_23760` | Probes SmarterTools SmarterMail < 9511 for the IsSysAdmin client-trust bypass on /api/v1/auth/force-reset-password. By default, only checks whether the endpoint accepts the unauthenticated payload — does NOT change the live admin password unless `setg smartermail_keep y` is set. | Excellent | ✓ |
| `exploits/webapps/solarwinds/cve_2025_40551_solarwinds_whd_rce` | Detects SolarWinds Web Help Desk ≤ 12.8.8 Hotfix 1 vulnerable to the unauth Java deserialization RCE. Probe only — fingerprints the login page version banner. | Excellent | ✓ |
| `exploits/webapps/spotube/spotube` | Unauthenticated access to Spotube API enabling path traversal via WebSocket and denial of service attacks against the desktop music client. | Good |  |
| `exploits/webapps/termix/termix_xss_cve_2026_22804` | Stored Cross-Site Scripting in Termix File Manager (1.7.0-1.9.0) via malicious SVG file upload. Executes JavaScript in Electron context when previewed. | Normal |  |
| `exploits/webapps/textpattern_xss` | Detects Textpattern admin; auth-required stored XSS in /textpattern/index.php?event=pref. | Normal | ✓ |
| `exploits/webapps/varnish_styx_smuggling` | Detects Varnish-fronted edge cache; TE.CL request smuggling via inconsistent | Normal | ✓ |
| `exploits/webapps/visualstudio_debugger` | Connects to TCP/5858 (Node Inspector / VS Code debugger) and verifies a debug session is exposed. | Good | ✓ |
| `exploits/webapps/vite_path_traversal_cve_2025_30208` | Path traversal in Vite dev server /@fs/ endpoint. Appending ?import&raw bypasses allowed-path checks and returns arbitrary files from the host filesystem. Affects Vite < 6.2.3 / 6.1.2 / 6.0.12 / 5.4.15 / 4.5.10. | Great |  |
| `exploits/webapps/wfentlm_disclose` | Generates a UNC trigger HTML payload that leaks NTLMv2 hashes when | Normal | ✓ |
| `exploits/webapps/wordpress/vitepos_file_upload_cve_2025_13156` | Authenticated arbitrary file upload in Vitepos POS for WooCommerce plugin <= 3.3.0, allowing PHP shell upload via missing file type validation. | Great |  |
| `exploits/webapps/wordpress/wp_bricks_rce_cve_2024_25600` | Exploits the bricks/v1/render_element REST endpoint in Bricks Builder for WordPress to achieve unauthenticated remote code execution via crafted element data with PHP code injection. | Excellent |  |
| `exploits/webapps/wordpress/wp_litespeed_rce_cve_2024_28000` | Exploits weak hash generation in the LiteSpeed Cache crawler feature to brute-force the security hash and escalate to WordPress administrator. | Normal |  |
| `exploits/webapps/wordpress/wp_royal_elementor_rce_cve_2024_32suspended` | Exploits the unauthenticated file upload handler in Royal Elementor Addons for WordPress to upload a PHP webshell via multipart POST to /wp-admin/admin-ajax.php?action=wpr_addons_upload. | Excellent |  |
| `exploits/webapps/wp_storychief_rce_cve_2025_7441` | Detects the StoryChief WP plugin; unauthenticated REST endpoint allows | Good | ✓ |
| `exploits/webapps/wpcpi_upload` | Detects WP for CPI plugin readme; upload endpoint is unauth. | Good | ✓ |
| `exploits/webapps/wpgivewp_inject` | Detects GiveWP plugin via readme; PHP object injection via donation form. | Good | ✓ |
| `exploits/webapps/wpomnipress_xss` | Detects WP OmniPress plugin via readme; auth admin XSS in widget config. | Normal | ✓ |
| `exploits/webapps/xwiki/cve_2025_24893_xwiki_rce` | Unauthenticated RCE via Groovy template injection in XWiki SolrSearch. | Excellent | ✓ |
| `exploits/webapps/yourls_sqli_cve_2022_0088` | Detects YOURLS instance; SQLi in admin/upgrade.php that allows compromise. | Good | ✓ |
| `exploits/webapps/yourls_xsrf_idor` | Probes YOURLS /admin/ajax.php for unauthenticated CSRF/IDOR on link mgmt. | Normal | ✓ |
| `exploits/webapps/zabbix/zabbix_7_0_0_sql_injection` | Time-based SQL injection in Zabbix 7.0.0 API endpoints allowing arbitrary SQL execution and potential remote code execution. | Great |  |
| `exploits/webapps/zimbra_postjournal_rce` | Detects Zimbra ZCS by SMTP banner / 7071 admin port; postjournal | Great | ✓ |
| `exploits/webapps/zimbra_sqli_auth_bypass_cve_2025_25064` | SQL injection in Zimbra ZCS ZimbraSync endpoint allows unauthenticated | Great |  |
| `exploits/windows/windows_dwm_cve_2026_20805` | Exploits CVE-2026-20805 in Windows Desktop Window Manager to leak kernel object pointers for KASLR bypass. | Good |  |

## creds (30)

- 30 modules, 0 with `check()`

| Module | Description | Rank | Check |
|---|---|---|---|
| `creds/camera/acti/acti_camera_default` | Tests default credentials across FTP, SSH, Telnet, and HTTP on ACTi IP cameras. | Normal |  |
| `creds/camxploit/camxploit` | Comprehensive IP camera discovery, fingerprinting, and default credential testing across RTSP, HTTP, and HTTPS. Supports Hikvision, Dahua, Axis, CP Plus, Foscam, Vivotek, and generic cameras. | Great |  |
| `creds/generic/couchdb_bruteforce` | Tests CouchDB authentication via POST /_session. Single-target — scheduler does CIDR / random / file fan-out. | Normal |  |
| `creds/generic/elasticsearch_bruteforce` | Tests Elasticsearch HTTP Basic auth on the cluster root endpoint. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/enablebruteforce` | Raises file descriptor limits (ulimit) for the current process to support high-concurrency brute-force operations. Provides guidance for persistent system configuration. | Normal |  |
| `creds/generic/fortinet_bruteforce` | POSTs `username=&secretkey=` to /remote/logincheck on a FortiGate SSL VPN portal and inspects the response body for the redirect / error markers. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/ftp_anonymous` | Checks for anonymous FTP access on targets. Supports plain FTP and FTPS, IPv4/IPv6, and mass scanning (hose mode). | Normal |  |
| `creds/generic/ftp_bruteforce` | Brute-force FTP authentication with support for FTPS (TLS), combo mode, concurrent connections, and subnet/mass scanning. | Normal |  |
| `creds/generic/h3c_oem_kvm_bruteforce` | Brute-forces the H3C iBMC vendor-specific KVM session login at POST /api/oem_kvm/session, which has no rate limiting on default firmware builds. Tests every (user, password) pair in plaintext, base64, and double-base64 encodings — the endpoint silently accepts all three. A successful hit yields an X-Auth-Token that grants virtual-media + reboot equivalents (full host compromise). | Excellent |  |
| `creds/generic/http_basic_bruteforce` | Brute-force HTTP Basic Authentication using username/password wordlists. Supports HTTPS with invalid certificate acceptance, default credential testing, combo mode, concurrent connections, and subnet/mass scanning. | Normal |  |
| `creds/generic/imap_bruteforce` | Brute-force IMAP authentication using raw TCP protocol with TLS/IMAPS support. Sends IMAP LOGIN commands, handles greeting banners, and supports default credential testing, combo mode, concurrent connections, and subnet/mass scanning. | Normal |  |
| `creds/generic/l2tp_bruteforce` | Sends an L2TPv2 SCCRQ on UDP/1701 and reports whether the gateway responds with SCCRP / StopCCN. Single-target — scheduler does fan-out. NOTE: real L2TP credential brute-force needs a full PPP+CHAP stack, which is out of scope; this module detects reachable gateways only. | Manual |  |
| `creds/generic/memcached_bruteforce` | Probes Memcached SASL PLAIN auth via the binary protocol (cmd 0x21). Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/mqtt_bruteforce` | Tests MQTT v3.1.1 CONNECT authentication. Reads CONNACK return code to classify accepted / bad-credentials / not-authorized. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/mysql_bruteforce` | Tests MySQL/MariaDB authentication via the HandshakeV10 → HandshakeResponse41 (mysql_native_password) flow. Reads the OK/ERR packet to classify the result. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/pop3_bruteforce` | Brute-force POP3 authentication with SSL/TLS support. Tests credentials against POP3 mail servers with combo mode, retry logic, and subnet/mass scanning. | Normal |  |
| `creds/generic/postgres_bruteforce` | Tests PostgreSQL authentication via the protocol v3 startup flow. Cleartext (R 3) and MD5 (R 5) auth methods supported; SASL/GSS/SSPI fall through as unsupported. Tries common defaults first, then operator-supplied wordlists. Single-target — scheduler does CIDR / random / file fan-out. | Normal |  |
| `creds/generic/proxy_bruteforce` | Bruteforces proxy authentication for HTTP CONNECT (Basic auth), SOCKS5 (username/password), and HTTP forward proxies. Supports combo, spray, and credential file modes. | Normal |  |
| `creds/generic/rdp_bruteforce` | Tests RDP authentication via the X.224 → MCS → CredSSP / Standard RDP flows. Negotiates Hybrid (NLA) → TLS → Standard. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/redis_bruteforce` | Brute-force Redis authentication using raw TCP protocol. Supports both legacy password-only AUTH and Redis 6+ ACL mode (AUTH username password). Tests default credentials, gathers server info on success, and supports subnet/mass scanning. | Normal |  |
| `creds/generic/rtsp_bruteforce` | Tests RTSP DESCRIBE auth (HTTP-Basic) on a given path. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/sample_cred_check` | Sample module that tests HTTP Basic Auth with default admin:admin credentials. Serves as a template for building custom credential checking modules — uses the native ModuleCtx/ModuleOutcome shape so credential findings flow into LootStore. | Normal |  |
| `creds/generic/smtp_bruteforce` | Brute-force SMTP authentication supporting PLAIN and LOGIN mechanisms. Tests credentials against mail servers with combo mode and subnet scanning. | Normal |  |
| `creds/generic/snmp_bruteforce` | Tests SNMPv2c community strings via a sysDescr.0 GetRequest. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/ssh_bruteforce` | Brute-force SSH authentication using username/password wordlists. Supports default credential testing, combo mode, concurrent connections, and subnet/mass scanning. | Normal |  |
| `creds/generic/ssh_spray` | Sprays a single password across multiple SSH targets and usernames. Avoids account lockouts by distributing attempts across hosts with configurable concurrency and delays. | Normal |  |
| `creds/generic/ssh_user_enum` | Enumerates valid SSH usernames via timing-based side-channel attack. Measures authentication response time differences to identify valid accounts, inspired by CVE-2018-15473. | Normal |  |
| `creds/generic/telnet_bruteforce` | Wordlist-driven Telnet credential probe with IAC handling. Single-target — scheduler does fan-out. | Normal |  |
| `creds/generic/telnet_hose` | Rapidly tests default credentials against Telnet services across large IP ranges. Supports mass scanning with concurrent connections and multiple default port checks. | Normal |  |
| `creds/generic/vnc_bruteforce` | Tests VNC RFB 3.x security-type 2 (DES challenge-response). Password-only — server silently truncates to 8 bytes. Single-target — scheduler does fan-out. | Normal |  |

## osint (3)

- 3 modules, 1 with `check()`

| Module | Description | Rank | Check |
|---|---|---|---|
| `osint/cert_transparency` | Queries crt.sh for every TLS certificate issued to the target domain or its subdomains, then extracts unique subdomain names from the CN / SAN fields. Pure OSINT — no traffic to the target. | Normal | ✓ |
| `osint/cname_chain` | Recursively follows CNAMEs for a single host (or a newline-separated file of hosts), tags terminal records that match known cloud providers, and flags hosts whose CNAME does not resolve to an A record (dangling). | Excellent |  |
| `osint/jwks_inspector` | Discovers JWKS endpoints under common paths, parses the key set, prints a per-key audit (kid/kty/alg/use/modulus length), and optionally exports each RSA public key as PEM (input for jwt_tool RS256→HS256 alg-confusion). | Excellent |  |

## plugins (1)

- 1 modules, 0 with `check()`

| Module | Description | Rank | Check |
|---|---|---|---|
| `plugins/sample_plugin` | Template plugin demonstrating the RustSploit native plugin API — uses ModuleCtx + ModuleOutcome and emits a Note finding per invocation. | Normal |  |

