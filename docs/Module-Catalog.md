# Module Catalog

All modules live under `src/modules/` and are auto-discovered by `build.rs`. Use the shell's `modules` command or `find <keyword>` for the live list. Use `info <module>` to see metadata (CVE, author, rank) if available.

> **Module categories:** `exploits/`, `scanners/`, `creds/`, `osint/`, `plugins/` -- all auto-discovered at build time. Adding a new subdirectory under `src/modules/` automatically creates a new category.

**Totals (v0.4.10):** 283 exploit modules, 35 scanners, 30 credential modules, 1 OSINT module, 1 plugin.

---

## Exploits

### Bluetooth

| Module Path | Description |
|-------------|-------------|
| `exploits/bluetooth/wpair` | WhisperPair: hijacks Bluetooth accessories via Google Fast Pair protocol flaws — unauthorized bonding, account key injection, audio interception. v0.4.9 adds proper paper-conformant **ECDH key exchange** (secp256r1 + SHA-256, 80-byte payload `E_K(request) \|\| PK_s`) using each device's **Anti-Spoofing public key** when known, with raw-KBP fallback. New REPL commands: `pair`, `rename <name>` (writes the personalized name to the Additional Data characteristic, encrypted with the session key), `switch` (audio-switching attack using the stored account key as MAC key), `testall`, `exploitall`. Conformance tests `nonce` (replay the same KBP write to test nonce freshness) and `curve` (off-curve point to test secp256r1 validation). Device DB carries `anti_spoofing_key` + `chipset` (MediaTek, Airoha, Bestechnic, Qualcomm, Actions, …); scan output flags `K` for devices with a known AS key, `SteadyState` for prime targets broadcasting account-key-filter beacons but not in pairing mode |

### Cameras

| Module Path | Description |
|-------------|-------------|
| `exploits/cameras/abus/abussecurity_camera_cve202326609variant1` | Abus security camera LFI, RCE, and SSH root access (CVE-2023-26609) |
| `exploits/cameras/acti/acm_5611_rce` | Command injection in ACTi ACM-5611 video cameras for RCE |
| `exploits/cameras/avtech/cve_2024_7029_avtech_camera` | AVTECH IP camera remote code execution (CVE-2024-7029) |
| `exploits/cameras/hikvision/hikvision_rce_cve_2021_36260` | Hikvision IP camera command injection RCE (CVE-2021-36260) |
| `exploits/cameras/reolink/reolink_rce_cve_2019_11001` | Reolink camera authenticated OS command injection via TestEmail (CVE-2019-11001) |
| `exploits/cameras/uniview/uniview_nvr_pwd_disclosure` | Uniview NVR remote credential extraction and decoding |
| `exploits/cameras/galayou_g2_rtsp_bypass_cve_2025_9983` | GALAYOU G2 IP camera RTSP DESCRIBE accepted without authentication; live feed exposed (CVE-2025-9983) |
| `exploits/cameras/xiongmai_xm530` | Xiongmai XM530 control protocol probe on TCP/34567; banner / login-handshake fingerprint |

### Cowrie (SSH Honeypot)

| Module Path | Description |
|-------------|-------------|
| `exploits/cowrie/ansi_log_injection` | Injects ANSI/OSC escape sequences into cowrie session logs via unsanitized crontab arguments for terminal-level code execution on replay |
| `exploits/cowrie/llm_prompt_injection` | Exploits cowrie LLM mode where attacker commands are concatenated into the system prompt, coercing the LLM to echo real configuration data |
| `exploits/cowrie/ssrf_ipv6` | Bypasses cowrie SSRF blocklist via IPv6 addresses (fc00::/7, fe80::/10, ::ffff:0:0/96) and DNS-rebinding TOCTOU |

### Crypto

| Module Path | Description |
|-------------|-------------|
| `exploits/crypto/geth_dos_cve_2026_22862` | Go-Ethereum ECIES panic DoS via malformed encrypted messages (CVE-2026-22862) |
| `exploits/crypto/heartbleed` | OpenSSL Heartbleed memory leak exploitation (CVE-2014-0160) |

### Dionaea (Honeypot)

| Module Path | Description |
|-------------|-------------|
| `exploits/dionaea/mqtt_underflow` | Malformed MQTT PUBLISH with TopicLength exceeding MessageLength triggers parser desync/UnicodeDecodeError in dionaea |
| `exploits/dionaea/mssql_dos` | Crafted TDS7 LOGIN7 packet with misaligned password slice triggers unhandled UnicodeDecodeError in dionaea MSSQL handler |
| `exploits/dionaea/mysql_sqli` | MySQL COM_FIELD_LIST with SQLite injection in table name leaks dionaea internal DB schema |
| `exploits/dionaea/tftp_crash` | Malformed TFTP RRQ without trailing NUL causes struct.error in dionaea options parser |

### DoS / CVE-flagged DoS

| Module Path | Description |
|-------------|-------------|
| `exploits/dos/apachebrpc_overflow_cve_2025_59789` | Apache bRPC <1.15.0 stack overflow via deeply recursive JSON; fingerprint probe (CVE-2025-59789) |
| `exploits/dos/http2_rapidreset_cve_2023_44487` | HTTP/2 Rapid Reset DoS exposure probe — detects h2 negotiation, does not exercise the abuse traffic (CVE-2023-44487) |
| `exploits/dos/px4_uav_dos` | PX4 Military UAV Autopilot 1.12.3 MAVLink fingerprint probe over UDP/14550 (CVE-2025-5640) |

### DoS / Stress Testing

| Module Path | Description |
|-------------|-------------|
| `exploits/dos/connection_exhaustion_flood` | FD-bounded TCP connection exhaustion with connect-and-drop |
| `exploits/dos/dns_amplification` | Spoofed DNS ANY queries to open resolvers for ~100x amplification |
| `exploits/dos/http_flood` | High-speed HTTP GET/POST flood with User-Agent rotation and cache busting |
| `exploits/dos/icmp_flood` | Raw ICMP echo request flood with optional source IP spoofing |
| `exploits/dos/memcached_amplification` | Spoofed memcached UDP stats requests for ~51,000x amplification |
| `exploits/dos/ntp_amplification` | Spoofed NTP MON_GETLIST_1 requests for ~556x amplification |
| `exploits/dos/null_syn_exhaustion` | Raw SYN flood with null-byte payloads, IP spoofing, >1M PPS |
| `exploits/dos/rudy` | R.U.D.Y. attack: slow POST body drip to exhaust server connection pools |
| `exploits/dos/slowloris` | Holds connections open with partial HTTP headers to exhaust connection pool |
| `exploits/dos/ssdp_amplification` | Spoofed SSDP M-SEARCH requests for ~30x amplification |
| `exploits/dos/syn_ack_flood` | SYN packets to reflectors with spoofed victim source IP for SYN-ACK reflection |
| `exploits/dos/tcp_connection_flood` | High-concurrency TCP connection flood with optional RST close and HTTP payload |
| `exploits/dos/telnet_iac_flood` | Telnet IAC negotiation flood exploiting unbounded SB/SE parsing and rapid WILL/DO option cycling |
| `exploits/dos/udp_flood` | High-speed UDP flood with random, null, and pattern payload modes |

### Frameworks

| Module Path | Description |
|-------------|-------------|
| `exploits/frameworks/apache_camel/cve_2025_27636_camel_header_injection` | Apache Camel < 4.10.2 HTTP header injection via Simple expression language for OS command execution (CVE-2025-27636) |
| `exploits/frameworks/apache_tomcat/catkiller_cve_2025_31650` | Apache Tomcat memory leak via invalid HTTP/2 priority headers (CVE-2025-31650) |
| `exploits/frameworks/apache_tomcat/cve_2025_24813_apache_tomcat_rce` | Apache Tomcat deserialization RCE (CVE-2025-24813) |
| `exploits/frameworks/apache_tomcat/cve_2025_24813_tomcat_put_rce` | Apache Tomcat unauthenticated RCE via partial PUT and Java deserialization (CVE-2025-24813) |
| `exploits/frameworks/exim/exim_etrn_sqli_cve_2025_26794` | Exim ETRN time-based SQL injection with SQLite backend (CVE-2025-26794) |
| `exploits/frameworks/http2/cve_2023_44487_http2_rapid_reset` | HTTP/2 Rapid Reset DoS via rapid stream creation and reset (CVE-2023-44487) |
| `exploits/frameworks/jenkins/jenkins_2_441_lfi` | Jenkins CLI arbitrary file read via args4j @-expansion (CVE-2024-23897) |
| `exploits/frameworks/jenkins/jenkins_args4j_rce_cve_2024_24549` | Jenkins CLI args4j file leak via connect-node command error messages |
| `exploits/frameworks/jenkins/jenkins_cli_rce_cve_2024_23897` | Jenkins CLI argument injection for arbitrary file read (CVE-2024-23897) |
| `exploits/frameworks/mongo/mongobleed` | MongoDB zlib decompression heap memory disclosure (CVE-2025-14847) |
| `exploits/frameworks/nginx/nginx_pwner` | Nginx misconfiguration scanner: alias traversal, CRLF injection, PHP detection, and more |
| `exploits/frameworks/php/cve_2024_4577` | PHP CGI argument injection on Windows XAMPP for RCE (CVE-2024-4577) |
| `exploits/frameworks/php/cve_2025_51373_php_rce` | PHP CGI on Windows soft hyphen code-page conversion allows argument injection for auto_prepend_file RCE (CVE-2025-51373) |
| `exploits/frameworks/wsus/cve_2025_59287_wsus_rce` | Unauthenticated RCE in Windows Server Update Services (CVE-2025-59287) |

### FTP

| Module Path | Description |
|-------------|-------------|
| `exploits/ftp/ftp_bounce_test` | FTP bounce attack test via PORT commands to third-party hosts |
| `exploits/ftp/pachev_ftp_path_traversal_1_0` | Directory traversal in Pachev FTP Server 1.0 to read files outside FTP root |

### HoneyTrap (Honeypot)

| Module Path | Description |
|-------------|-------------|
| `exploits/honeytrap/docker_panic` | POST /v1.40/images/create without fromImage causes nil map panic in HoneyTrap Docker emulation — daemon exit |
| `exploits/honeytrap/ftp_panic` | Malformed FTP PORT command with insufficient fields causes slice out-of-range panic in HoneyTrap — daemon exit |

### IPMI

| Module Path | Description |
|-------------|-------------|
| `exploits/ipmi/ipmi_enum_exploit` | IPMI enumeration with cipher 0 bypass, default credential brute force, and RAKP hash dumping |

### Network Infrastructure -- General

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/apache_modssl_bypass_cve_2025_23048` | Apache mod_ssl TLS 1.3 client-cert auth bypass via session resumption across vhosts (CVE-2025-23048) |
| `exploits/network_infra/arista_ngfw_disclose` | Arista NGFW 17.3.1 unauthenticated internal RPC disclosure |
| `exploits/network_infra/checkpoint_fileread_cve_2024_24919` | Check Point Security Gateway R80.40 / R81 unauthenticated arbitrary file read via /clients/MyCRL aCSHELL traversal (CVE-2024-24919) |
| `exploits/network_infra/hpprocurve_disclose` | HP ProCurve 4.00 admin web banner detect + credential dump probe |
| `exploits/network_infra/hpprocurve_snac_inject` | HP ProCurve SNAC Domain Controller PHP injection probe |
| `exploits/network_infra/juniper_screenos_scanner` | Juniper ScreenOS 6.2.0r15 SSH banner check (CVE-2015-7755 backdoor) |

### Network Infrastructure -- Cisco

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/cisco/cisco_ise_api_inject_cve_2025_20281` | Cisco ISE 3.1 / 3.2 ERS API unauthenticated command injection in InternalUser name field, RCE as root (CVE-2025-20281) |

### Network Infrastructure -- Commvault

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/commvault/cve_2025_34028_commvault_rce` | Commvault Command Center < 11.38.0 unauthenticated path traversal file upload to RCE (CVE-2025-34028) |

### Network Infrastructure -- Citrix

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/citrix/cve_2025_5777_citrixbleed2` | Citrix NetScaler ADC/Gateway out-of-bounds read in authentication endpoint |

### Network Infrastructure -- F5

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/f5/cve_2025_53521_f5_bigip_rce` | Unauthenticated RCE in F5 BIG-IP Access Policy Manager (CVE-2025-53521) |

### Network Infrastructure -- Fortinet

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/fortinet/forticloud_sso_auth_bypass_cve_2026_24858` | FortiCloud SSO authentication bypass via reused SSO tokens (CVE-2026-24858) |
| `exploits/network_infra/fortinet/fortigate_rce_cve_2024_21762` | FortiOS SSL VPN pre-auth heap-based buffer overflow RCE (CVE-2024-21762) |
| `exploits/network_infra/fortinet/fortimanager_rce_cve_2024_47575` | FortiManager fgfmd unauthenticated RCE via FGFM registration requests (CVE-2024-47575) |
| `exploits/network_infra/fortinet/fortios_auth_bypass_cve_2022_40684` | FortiOS/FortiProxy admin interface auth bypass via crafted HTTP headers (CVE-2022-40684) |
| `exploits/network_infra/fortinet/fortios_heap_overflow_cve_2023_27997` | FortiOS SSL VPN out-of-bounds write RCE via /remote/hostcheck_validate (CVE-2023-27997) |
| `exploits/network_infra/fortinet/fortios_ssl_vpn_cve_2018_13379` | FortiOS SSL VPN path traversal to leak session files with cleartext credentials (CVE-2018-13379) |
| `exploits/network_infra/fortinet/fortisiem_rce_cve_2025_64155` | FortiSIEM phMonitor unauthenticated RCE via argument injection in XML/SSL protocol (CVE-2025-64155) |
| `exploits/network_infra/fortinet/fortiweb_rce_cve_2021_22123` | FortiWeb authenticated command injection via SAML server-name parameter (CVE-2021-22123) |
| `exploits/network_infra/fortinet/fortiweb_sqli_rce_cve_2025_25257` | FortiWeb unauthenticated SQL injection to webshell deployment (CVE-2025-25257) |

### Network Infrastructure -- HPE

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/hpe/cve_2025_37164_hpe_oneview_rce` | Unauthenticated RCE via REST API command injection in HPE OneView (CVE-2025-37164) |

### Network Infrastructure -- Kubernetes

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/kubernetes/cve_2025_1974_ingress_nginx_rce` | ingress-nginx admission webhook config injection via annotations for arbitrary NGINX config, file read, and RCE (CVE-2025-1974) |

### Network Infrastructure -- Ivanti

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/ivanti/cve_2025_0282_ivanti_preauth_rce` | Pre-authentication buffer overflow in Ivanti Connect Secure (CVE-2025-0282) |
| `exploits/network_infra/ivanti/cve_2025_22457_ivanti_ics_rce` | Stack-based buffer overflow in Ivanti Connect Secure via X-Forwarded-For (CVE-2025-22457) |
| `exploits/network_infra/ivanti/ivanti_connect_secure_stack_based_buffer_overflow` | Ivanti Connect Secure stack-based buffer overflow, CVSS 9.0 |
| `exploits/network_infra/ivanti/ivanti_epmm_cve_2023_35082` | Ivanti EPMM unauthenticated API access to user information (CVE-2023-35082) |
| `exploits/network_infra/ivanti/ivanti_ics_auth_bypass_cve_2024_46352` | Ivanti Connect Secure auth bypass via TOTP backup code path traversal (CVE-2024-46352) |
| `exploits/network_infra/ivanti/ivanti_neurons_rce_cve_2025_22460` | Ivanti Neurons for ITSM unauthenticated RCE via deserialization (CVE-2025-22460) |

### Network Infrastructure -- QNAP

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/qnap/qnap_qts_rce_cve_2024_27130` | QNAP QTS stack buffer overflow via share.cgi for RCE (CVE-2024-27130) |

### Network Infrastructure -- SonicWall

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/sonicwall/cve_2025_40602_sonicwall_sma_rce` | SonicWall SMA1000 series remote code execution (CVE-2025-40602) |

### Network Infrastructure -- Trend Micro

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/trend_micro/cve_2025_5777` | Trend Micro MsgReceiver DLL loading for unauthenticated RCE on port 20001 |
| `exploits/network_infra/trend_micro/cve_2025_69258` | Trend Micro Apex Central unauthenticated command injection via Login.aspx |
| `exploits/network_infra/trend_micro/cve_2025_69259` | Trend Micro MsgReceiver out-of-bounds read DoS (CVE-2025-69259) |
| `exploits/network_infra/trend_micro/cve_2025_69260` | Trend Micro MsgReceiver unchecked NULL return value DoS (CVE-2025-69260) |

### Network Infrastructure -- VMware

| Module Path | Description |
|-------------|-------------|
| `exploits/network_infra/vmware/esxi_auth_bypass_cve_2024_37085` | ESXi authentication bypass via Active Directory 'ESX Admins' group manipulation (CVE-2024-37085) |
| `exploits/network_infra/vmware/esxi_vm_escape_check` | ESXi VM escape chain vulnerability check and IOC detection (CVE-2025-22224/22225/22226) |
| `exploits/network_infra/vmware/esxi_vsock_client` | VSOCK client for communicating with VSOCKpuppet backdoor on compromised ESXi hosts |
| `exploits/network_infra/vmware/vcenter_backup_rce` | vCenter Server authenticated RCE via flag injection in backup.validate API (CVSS 7.2) |
| `exploits/network_infra/vmware/vcenter_file_read` | vCenter Server authenticated partial arbitrary file read via RVC command (CVSS 4.9) |
| `exploits/network_infra/vmware/vcenter_rce_cve_2024_37079` | vCenter Server heap-overflow RCE via DCERPC protocol on port 443 (CVE-2024-37079) |

### Payload Generators

| Module Path | Description |
|-------------|-------------|
| `exploits/payloadgens/payloadgen` | Unified payload generator. Modes: `bat` (BAT chain dropper), `lnk` (NTLMv2-SSP hash disclosure CVE-2025-50154 / CVE-2025-59214), `narutto` (polymorphic 3-stage LOLBAS dropper + anti-VM), `polymorph` (3-stage Task Scheduler dropper), `encode` (multi-stage payload encoder — base16/32/64/url/shell/html/zero-width), `menu` (interactive selector). All driven by `native::payload_engine`. |
| `exploits/payloadgens/obfuscator` | Dynamic multi-layer obfuscator. 24 methods: XOR / RC4 / base16/32/32hex/64/64url/85/91 / ROT13 / ROT47 / reverse / gzip / URL / Caesar / bit-rotate / Vigenère / zero-width / hex-split / UTF-16LE / char-substitution / ANSI-escape / chunk-permute. Modes: `chain` (explicit), `random` (auto N rounds), `same` (one method × N). Output: `raw`, `recipe`, `python` / `powershell` / `bash` / `javascript` self-decoders, `c_array`. Default 4 rounds (user-configurable up to 32). |

### Routers -- D-Link

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/dlink/dlink_dcs_930l_auth_bypass` | D-Link DCS-930L/932L unauthenticated config disclosure and credential extraction |

### Routers -- Netgear

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/netgear/netgear_r6700v3_rce_cve_2022_27646` | Netgear R6700v3 pre-auth buffer overflow RCE in circled daemon (CVE-2022-27646) |

### Routers -- Palo Alto

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/palo_alto/panos_authbypass_cve_2025_0108` | PAN-OS auth bypass via path traversal in authentication mechanism (CVE-2025-0108) |
| `exploits/routers/palo_alto/panos_expedition_rce_cve_2024_9463` | Palo Alto Expedition unauthenticated OS command injection (CVE-2024-9463) |
| `exploits/routers/palo_alto/panos_globalprotect_rce_cve_2024_3400` | PAN-OS GlobalProtect gateway unauthenticated OS command injection (CVE-2024-3400) |

### Routers -- Ruijie

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/ruijie/ruijie_auth_bypass_rce_cve_2023_34644` | Ruijie device auth bypass to RCE on routers, switches, and access points (CVE-2023-34644) |
| `exploits/routers/ruijie/ruijie_reyee_ssrf_cve_2024_48874` | Ruijie Reyee cloud-connected device SSRF (CVE-2024-48874) |
| `exploits/routers/ruijie/ruijie_rg_ew_login_bypass_cve_2023_4415` | Ruijie RG-EW1200G auth bypass via crafted JSON login request (CVE-2023-4415) |
| `exploits/routers/ruijie/ruijie_rg_ew_password_reset_cve_2023_4169` | Ruijie RG-EW1200G unauthenticated admin password reset (CVE-2023-4169) |
| `exploits/routers/ruijie/ruijie_rg_ew_update_version_rce_cve_2021_43164` | Ruijie RG-EW Series firmware update command injection RCE (CVE-2021-43164) |
| `exploits/routers/ruijie/ruijie_rg_uac_ci_cve_2024_4508` | Ruijie RG-UAC unauthenticated command injection via static_route_edit (CVE-2024-4508) |
| `exploits/routers/ruijie/ruijie_rsr_router_ci_cve_2024_31616` | Ruijie RSR10-01G-T-S authenticated command injection via diagnostics (CVE-2024-31616) |

### Routers -- Tenda

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/tenda/tenda_cp3_rce_cve_2023_30353` | Tenda CP3 IP camera unauthenticated RCE via YGMP_CMD on UDP 5012 (CVE-2023-30353) |

### Routers -- TP-Link

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/tplink/tapo_c200_vulns` | TP-Link Tapo C200 multiple vulns: WiFi info leak, ONVIF overflow, HTTPS integer overflow |
| `exploits/routers/tplink/tplink_archer_c2_c20i_rce` | TP-Link Archer C2/C20i authenticated command injection via diagnostics |
| `exploits/routers/tplink/tplink_archer_c9_password_reset` | TP-Link Archer C9/C60 unauthenticated password reset via predictable PRNG |
| `exploits/routers/tplink/tplink_archer_rce_cve_2024_53375` | TP-Link Archer/Deco/Tapo authenticated command injection via OwnerId (CVE-2024-53375) |
| `exploits/routers/tplink/tplink_ax1800_rce_cve_2024_53375` | TP-Link Archer AX1800 authenticated command injection via NTP server field |
| `exploits/routers/tplink/tplink_deco_m4_rce` | TP-Link Deco M4 default credential check and ping command injection |
| `exploits/routers/tplink/tplink_tapo_c200` | TP-Link Tapo C200 IP camera command injection via setLanguage method |
| `exploits/routers/tplink/tplink_vigi_c385_rce_cve_2026_1457` | TP-Link VIGI C385 authenticated buffer overflow RCE (CVE-2026-1457) |
| `exploits/routers/tplink/tp_link_vn020_dos` | TP-Link VN020 UPnP DoS via malformed AddPortMapping SOAP request |
| `exploits/routers/tplink/tplink_wdr740n_backdoor` | TP-Link WDR740N debug page command execution with hardcoded credentials |
| `exploits/routers/tplink/tplink_wdr740n_path_traversal` | TP-Link WDR740N/ND path traversal for arbitrary file read via /help/ |
| `exploits/routers/tplink/tplink_wdr842n_configure_disclosure` | TP-Link WDR842N config download and DES decryption for credential extraction |
| `exploits/routers/tplink/tplink_wr740n_dos` | TP-Link TL-WR740N web server buffer overflow DoS |

### Routers -- Ubiquiti

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/ubiquiti/ubiquiti_edgerouter_ci_cve_2023_2376` | Ubiquiti EdgeRouter X command injection in web management (CVE-2023-2376) |

### Routers -- ZTE

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/zte/zte_zxv10_h201l_rce_authenticationbypass` | ZTE ZXV10 H201L auth bypass via config leak and DDNS command injection |

### Routers -- Zyxel

| Module Path | Description |
|-------------|-------------|
| `exploits/routers/zyxel/zyxel_cpe_ci_cve_2024_40890` | Zyxel legacy CPE unauthenticated HTTP command injection (CVE-2024-40890) |

### Sample

| Module Path | Description |
|-------------|-------------|
| `exploits/sample_exploit` | Template exploit module demonstrating info(), check(), and run() with cfg_prompt integration |

### SafeLine (WAF)

| Module Path | Description |
|-------------|-------------|
| `exploits/safeline/cookie_attributes` | SafeLine session cookie lacks HttpOnly, Secure, and SameSite attributes enabling XSS session theft and CSRF |
| `exploits/safeline/nginx_injection` | SafeLine tcontrollerd inserts Ports field verbatim into nginx config via fmt.Sprintf for arbitrary directive injection |
| `exploits/safeline/no_auth_probe` | Detects SafeLine NO_AUTH env bypass where `len(noAuth) >= 0` (always true) disables auth middleware |
| `exploits/safeline/pre_auth_tfa` | Fresh SafeLine install unauthenticated TFA secret rotation via /api/OTPUrl for full account takeover |
| `exploits/safeline/session_secret_entropy` | SafeLine JWT signing secret generated with math/rand seeded by time.Now().UnixNano() — as low as 39 bits effective entropy |
| `exploits/safeline/unauth_writes` | SafeLine publicRouters expose unauthenticated POST to /api/Behaviour and /api/FalsePositives for analytics pollution and request amplification |

### Snare (Honeypot)

| Module Path | Description |
|-------------|-------------|
| `exploits/snare/cookie_dos` | HTTP Cookie header without '=' separator causes IndexError crash in snare tanner_handler.py worker |
| `exploits/snare/tanner_version_mitm` | Rogue HTTP server on port 8090 returns forged version response to snare's unauthenticated GET /version check |

### SSH

| Module Path | Description |
|-------------|-------------|
| `exploits/ssh/asyncssh_beginauthpass` | AsyncSSH server begin_auth() returning False causes USERAUTH_SUCCESS bypass for unauthenticated session access |
| `exploits/ssh/erlang_otp_ssh_rce_cve_2025_32433` | Erlang/OTP SSH server unauthenticated RCE (CVE-2025-32433) |
| `exploits/ssh/libssh2_rogue_server` | Rogue SSH server capturing credentials from libssh2 clients that accept USERAUTH_SUCCESS without verifying KEX state |
| `exploits/ssh/libssh_auth_bypass_cve_2018_10933` | libSSH server authentication bypass (CVE-2018-10933) |
| `exploits/ssh/openssh_regresshion_cve_2024_6387` | OpenSSH sshd signal handler race condition for unauthenticated RCE (CVE-2024-6387) |
| `exploits/ssh/opensshserver_9_8p1race_condition` | OpenSSH 9.8p1 race condition for heap-based RCE |
| `exploits/ssh/paramiko_authnonepass` | Paramiko SSH server check_auth_none() returning AUTH_SUCCESSFUL allows unauthenticated session access |
| `exploits/ssh/paramiko_unknown_method` | Paramiko SSH server unrecognized auth method fallthrough to check_auth_none() allows authentication bypass |
| `exploits/ssh/sshpwn_auth_passwd` | OpenSSH auth2-passwd.c password length DoS, change info leak, timing enumeration |
| `exploits/ssh/sshpwn_pam` | OpenSSH auth-pam.c environment injection, memory leak DoS, username validation bypass |
| `exploits/ssh/sshpwn_scp_attacks` | OpenSSH SCP path traversal, command injection, and brace expansion DoS |
| `exploits/ssh/sshpwn_session` | OpenSSH session.c forced command bypass, env injection, privsep issues |
| `exploits/ssh/sshpwn_sftp_attacks` | OpenSSH SFTP symlink injection, chmod setuid abuse, path traversal, partial write |

### Telnet

| Module Path | Description |
|-------------|-------------|
| `exploits/telnet/telnet_auth_bypass_cve_2026_24061` | Telnet authentication bypass on vulnerable devices (CVE-2026-24061) |

### VNC

| Module Path | Description |
|-------------|-------------|
| `exploits/vnc/libvnc_checkrect_overflow` | LibVNCClient signed 32-bit bounds check integer overflow for heap overflow RCE |
| `exploits/vnc/libvnc_tight_filtergradient` | LibVNCClient Tight decoder unclamped numRows out-of-bounds write past allocated buffer |
| `exploits/vnc/libvnc_ultrazip` | LibVNCClient Ultra encoding unbounded cache rect loop for heap overflow (CVE-2018-20750) |
| `exploits/vnc/libvnc_websocket_overflow` | LibVNCServer WebSocket unbounded 64-bit payloadLen for heap overflow |
| `exploits/vnc/libvnc_zrle_tile` | LibVNCClient ZRLE decoder truncated RLE tile buffer over-read |
| `exploits/vnc/rfb` | Shared RFB protocol helpers for VNC exploit modules |
| `exploits/vnc/tigervnc_rre_overflow` | TigerVNC RRE decoder unbounded numSubrects loop for heap over-read |
| `exploits/vnc/tigervnc_timing_oracle` | TigerVNC VNC auth DES response timing side-channel for bit-by-bit key recovery |
| `exploits/vnc/tightvnc_decompression_bomb` | TightVNC FileUploadData uncapped uncompressedSize for heap exhaustion DoS |
| `exploits/vnc/tightvnc_des_hardcoded_key` | TightVNC hardcoded 8-byte DES key for offline Windows registry password decryption |
| `exploits/vnc/tightvnc_ft_path_traversal` | TightVNC file-transfer handler directory traversal for arbitrary file read/write |
| `exploits/vnc/tightvnc_predictable_challenge` | TightVNC srand(time(0)) predictable 16-byte RFB challenge for replay attacks |
| `exploits/vnc/tightvnc_rect_overflow` | TightVNC signed int32 multiplication overflow in Rect::area() for heap buffer overflow RCE |
| `exploits/vnc/x11vnc_dns_injection` | x11vnc reverse-DNS hostname passed unsanitized to system() for shell injection via crafted PTR record |
| `exploits/vnc/x11vnc_env_injection` | x11vnc RFB_CLIENT_IP environment variable injection into hook scripts |
| `exploits/vnc/x11vnc_unixpw_inject` | x11vnc -unixpw mode newline injection in plaintext username to confuse PAM flow |

### VoIP



| Module Path | Description |
|-------------|-------------|
| `exploits/voip/cve_2025_64328_freepbx_cmdi` | FreePBX filestore module post-authentication command injection (CVE-2025-64328) |
| `exploits/voip/magnusbilling_ssrf_cve_2023_30258` | MagnusBilling 6 SSRF, path traversal, and crypto weaknesses — admin panel detection (CVE-2023-30258) |
| `exploits/voip/xorcompbx_rce` | Xorcom CompletePBX 5.2.35 admin portal detection; auth-required RCE via shell injection |

### Web Applications

| Module Path | Description |
|-------------|-------------|
| `exploits/webapps/craftcms_key_rce_cve_2025_23209` | Craft CMS RCE when application security key is known or leaked (CVE-2025-23209) |
| `exploits/webapps/craftcms_rce_cve_2025_47726` | Craft CMS RCE via Server-Side Template Injection (CVE-2025-47726) |
| `exploits/webapps/dify/cve_2025_56157_dify_default_creds` | Dify default PostgreSQL credentials (postgres:difyai123456) exposure check (CVE-2025-56157) |
| `exploits/webapps/flowise/cve_2024_31621` | Flowise 1.6.5 unauthenticated credentials endpoint access (CVE-2024-31621) |
| `exploits/webapps/flowise/cve_2025_59528_flowise_rce` | Flowise < 3.0.5 unauthenticated API RCE (CVE-2025-59528) |
| `exploits/webapps/langflow_rce_cve_2025_3248` | Langflow unauthenticated RCE via Python exec() in code validation (CVE-2025-3248) |
| `exploits/webapps/laravel_livewire_rce_cve_2025_47949` | Laravel Livewire RCE via unsafe deserialization (CVE-2025-47949) |
| `exploits/webapps/misp_rce_cve_2025_27364` | MISP < 2.5.3 authenticated file upload to PHP webshell RCE via /events/upload_sample (CVE-2025-27364) |
| `exploits/webapps/mcpjam/cve_2026_23744_mcpjam_rce` | MCPJam Inspector <= 1.4.2 unauthenticated RCE (CVE-2026-23744) |
| `exploits/webapps/n8n/n8n_rce_cve_2025_68613` | n8n workflow automation RCE via expression injection (CVE-2025-68613) |
| `exploits/webapps/nextjs_middleware_bypass_cve_2025_29927` | Next.js < 15.2.3 middleware bypass via unauthenticated x-middleware-subrequest header (CVE-2025-29927) |
| `exploits/webapps/react/react2shell` | React Server Components / Next.js RCE via RSC Flight protocol deserialization |
| `exploits/webapps/roundcube/roundcube_postauth_rce` | Roundcube webmail post-auth RCE via deserialization in file upload |
| `exploits/webapps/sap_netweaver_rce_cve_2025_31324` | SAP NetWeaver Visual Composer unauthenticated file upload to RCE (CVE-2025-31324) |
| `exploits/webapps/sharepoint/cve_2024_38094` | SharePoint Server authenticated deserialization RCE via .bdcm upload (CVE-2024-38094) |
| `exploits/webapps/sharepoint/cve_2025_53770_sharepoint_toolpane_rce` | SharePoint on-premises unauthenticated deserialization RCE (CVE-2025-53770) |
| `exploits/webapps/solarwinds/cve_2025_40551_solarwinds_whd_rce` | SolarWinds Web Help Desk unauthenticated Java deserialization RCE (CVE-2025-40551) |
| `exploits/webapps/spotube/spotube` | Spotube API path traversal via WebSocket and denial of service |
| `exploits/webapps/termix/termix_xss_cve_2026_22804` | Termix File Manager stored XSS via SVG upload in Electron context (CVE-2026-22804) |
| `exploits/webapps/vite_path_traversal_cve_2025_30208` | Vite dev server < 6.2.3 /@fs/ path traversal via ?import&raw query parameter bypass (CVE-2025-30208) |
| `exploits/webapps/wordpress/vitepos_file_upload_cve_2025_13156` | Vitepos for WooCommerce authenticated arbitrary PHP file upload (CVE-2025-13156) |
| `exploits/webapps/wordpress/wp_bricks_rce_cve_2024_25600` | Bricks Builder for WordPress unauthenticated RCE via render_element (CVE-2024-25600) |
| `exploits/webapps/wordpress/wp_litespeed_rce_cve_2024_28000` | LiteSpeed Cache weak hash brute force for WordPress admin escalation (CVE-2024-28000) |
| `exploits/webapps/wordpress/wp_royal_elementor_rce_cve_2024_32suspended` | Royal Elementor Addons unauthenticated PHP webshell upload |
| `exploits/webapps/xwiki/cve_2025_24893_xwiki_rce` | XWiki SolrSearch unauthenticated RCE via Groovy template injection (CVE-2025-24893) |
| `exploits/webapps/zabbix/zabbix_7_0_0_sql_injection` | Zabbix 7.0.0 time-based SQL injection in API endpoints |
| `exploits/webapps/zimbra_sqli_auth_bypass_cve_2025_25064` | Zimbra ZCS < 10.0.12 unauthenticated SQL injection via /service/home~ for email metadata extraction (CVE-2025-25064) |
| `exploits/webapps/aiplugins_rce_cve_2025_23968` | WordPress AI Plugins (Cibeles AI / AI Feeds / AI Buddy) GitHub-import unauthenticated webshell upload (CVE-2025-23968 / 13595 / 13597) |
| `exploits/webapps/azureapim_checker` | Azure APIM developer portal v2 internal-status disclosure / cross-tenant signup bypass probe |
| `exploits/webapps/azuriom_csti_cve_2025_65271` | Azuriom CMS 1.2.6 admin dashboard client-side template injection privilege escalation (CVE-2025-65271) |
| `exploits/webapps/beego_traversal_lfi` | Beego 1.12.3 application directory traversal via percent-encoded backslash (`..%5c`) for arbitrary file read |
| `exploits/webapps/cacti_graph_rce_cve_2025_24367` | Cacti 1.2.29 authenticated Graph Template RCE — RRDtool field abuse to write PHP shell (CVE-2025-24367) |
| `exploits/webapps/casdoor_traversal_cve_2023_34927` | Casdoor 2.95.0 directory traversal via `..%5c` encoding for arbitrary file read (CVE-2023-34927) |
| `exploits/webapps/cbitrix_translate_upload_cve_2025_67887` | 1C-Bitrix CMS ≤ 25.100.500 Translate module unauthenticated file upload (CVE-2025-67887) |
| `exploits/webapps/cinnamon_kotaemon_zip_dos_cve_2025_63914` | Cinnamon kotaemon ≤ 0.11.0 authenticated zip-bomb upload DoS (CVE-2025-63914) |
| `exploits/webapps/cleo_harmony_filewrite_cve_2024_55956` | Cleo LexiCom / VLTrader / Harmony 5.8.0.23 unauthenticated arbitrary file write to JSP RCE (CVE-2024-55956) |
| `exploits/webapps/clipbucket_rce_cve_2025_55911` | ClipBucket 5.5.2 Build 90 authenticated RCE via moderator upload form (CVE-2025-55911) |
| `exploits/webapps/cloudbleed_scanner` | Cloudbleed-style memory leak scanner — sends malformed HTML probes to Cloudflare-fronted hosts |
| `exploits/webapps/commvault_cli_rce_cve_2025_57788` | Commvault CLI 11.36.60 unauthenticated RCE chain (CVE-2025-57788 / 57790 / 57791) — fingerprint probe |
| `exploits/webapps/convio_sqli` | Convio CMS 24.5 SQL injection in `navItem` parameter on PageNavigator |
| `exploits/webapps/coohom_xss` | Coohom application reflected XSS probe |
| `exploits/webapps/cpms_authbypass` | Clinic's Patient Management System 2.0 unauthenticated admin access (CVE-2022-2297, CVE-2025-3096) |
| `exploits/webapps/craftcms_logicflaw` | Craft CMS 5.0 image transform authentication logic flaw fingerprint |
| `exploits/webapps/craftcms_ssti_scanner` | Craft CMS 5.0 Twig template injection scanner — `{{7*7}}` reflection probe |
| `exploits/webapps/crafty_controller_rce_cve_2025_14700` | Crafty Controller 4.6.1 authenticated SSTI RCE in template config (CVE-2025-14700) |
| `exploits/webapps/django_sqli_cve_2025_64459` | Django 5.1.13 SQL injection in QuerySet/Lookup APIs (CVE-2025-64459) |
| `exploits/webapps/dnnplatform_upload_cve_2025_64095` | DNN Platform <10.1.1 unauthenticated arbitrary file upload via HTML editor (CVE-2025-64095) |
| `exploits/webapps/dotcms_blind_sqli_cve_2025_8311` | dotCMS 25.07.02-1 authenticated time-based blind SQL injection in Content API (CVE-2025-8311) |
| `exploits/webapps/dotcms_scanner` | dotCMS generic scanner — version disclosure via `/api/v1/system/version` |
| `exploits/webapps/drupal11_pathdisclose_cve_2024_45440` | Drupal 11.x full path disclosure via crafted query parameters (CVE-2024-45440) |
| `exploits/webapps/eduplus_idor` | EduplusCampus 3.0.1 student portal IDOR — payment record enumeration |
| `exploits/webapps/elementor_wb_sqli_cve_2023_0329` | Elementor Website Builder <3.12.2 admin SQL injection — readme fingerprint (CVE-2023-0329) |
| `exploits/webapps/eramba_grc_rce_cve_2023_36255` | Eramba GRC 3.19.1 authenticated command injection in download-test-pdf (CVE-2023-36255) |
| `exploits/webapps/ffcw_inject` | Fortra FileCatalyst Workflow 5.1.6 PHP code injection fingerprint |
| `exploits/webapps/flask_command_injection` | Flask 3.0.0 SSTI / command injection probe — reflected expression evaluation |
| `exploits/webapps/flatcore_upload_cve_2019_13961` | flatCore 1.5 authenticated file-upload-to-RCE chain detection (CVE-2019-13961) |
| `exploits/webapps/flatpress_xsrf_shell` | FlatPress 1.3 admin CSRF + shell upload fingerprint |
| `exploits/webapps/flowise_js_inject_cve_2025_59528` | Flowise 3.0.6 JS parsing injection RCE via crafted node payloads (CVE-2025-59528) |
| `exploits/webapps/foxcms_inject_cve_2025_29306` | FoxCMS 1.0 PHP code injection in admin endpoints (CVE-2025-29306) |
| `exploits/webapps/fuguhub_rsakey_disclose_cve_2025_65790` | FuguHub 8.1 public RSA private key + X.509 certificate disclosure (CVE-2025-65790) |
| `exploits/webapps/getsimple_csrf_cve_2021_28976` | GetSimple CMS 3.3.16 CSRF in backup management — wipe all backups (CVE-2021-28976) |
| `exploits/webapps/gnuboard5_install` | Gnuboard v5.6.23 exposed `/install/` endpoint allows config compromise (CVE-2020-18662) |
| `exploits/webapps/gravcms_sandbox_bypass_cve_2025_66294` | Grav CMS 1.7.49.5 Twig sandbox bypass authenticated RCE (CVE-2025-66294 / 66301) |
| `exploits/webapps/guppycms_shell` | GuppY CMS 6.00.10 admin login fingerprint + auth-required PHP code execution |
| `exploits/webapps/headlamp_unauth_disclose_cve_2025_14269` | Headlamp 0.38.0 unauthenticated cached Helm credentials disclosure (CVE-2025-14269) |
| `exploits/webapps/hestia_inject` | Hestia Control Panel 1.9.3 admin login fingerprint + auth-required PHP injection |
| `exploits/webapps/highcms_sqli` | HighCMS / HighPortal v12.x SQL error markers in `id=` parameter on /page.php |
| `exploits/webapps/hpe_oneview_rce` | HPE OneView REST API version disclosure + authenticated Java deserialization RCE |
| `exploits/webapps/ias25_idor` | Institute Admission Software 2.5 student profile IDOR enumeration |
| `exploits/webapps/ias25_sqli` | Institute Admission Software 2.5 SQL injection in admin login form |
| `exploits/webapps/ias25_upload` | Institute Admission Software 2.5 admin upload endpoint reachability |
| `exploits/webapps/ibmbigfix_disclose` | IBM BigFix Platform 9.2 bfgather endpoint reachability disclosure |
| `exploits/webapps/ictbroadcast_rce` | ICTBroadcast 7.0 banner detection + auth-required RCE via DBC |
| `exploits/webapps/iemm_eli_inject_cve_2025_4427` | Ivanti Endpoint Manager Mobile 12.5.0.0 expression-language injection (CVE-2025-4427 / 4428) |
| `exploits/webapps/invision_csti_cve_2025_ic506` | Invision Community 5.0.6 customCss expression injection (SSTI) |
| `exploits/webapps/invoiceninja_inject` | Invoice Ninja 5.8.22 detection via /api/v1/ping + auth-required PHP code injection |
| `exploits/webapps/ioncube_loader_scanner` | ionCube Loader Wizard 14.4.0 exposed `loader-wizard.php` scanner |
| `exploits/webapps/jenkins_fileread` | Jenkins ≤ 2.441 arbitrary file read via CLI args parser (CVE-2024-23897) — version detection via X-Jenkins header |
| `exploits/webapps/jsonpath_plus_rce_cve_2025_1302` | JSONPath Plus < 10.3.0 RCE expression evaluation probe (CVE-2025-1302) |
| `exploits/webapps/kalmia_user_enum_cve_2025_65899` | Kalmia CMS 0.2.0 user enumeration via JWT auth message leakage (CVE-2025-65899) |
| `exploits/webapps/laravel_pulse_inject_cve_2024_55661` | Laravel Pulse 1.3.1 dashboard fingerprint + arbitrary code injection (CVE-2024-55661) |
| `exploits/webapps/lepton_xss_rce` | LEPTON CMS 7.4.0 stored XSS escalating to PHP execution via Droplet engine |
| `exploits/webapps/lgsimpleeditor_inject` | LG Simple Editor 3.21.0 banner detection + PHP code injection |
| `exploits/webapps/librenms_inject` | LibreNMS 24.9.1 login fingerprint + auth-required PHP code injection |
| `exploits/webapps/limesurvey_filedownload` | LimeSurvey 2.0 detection — unauthenticated file download via export endpoint |
| `exploits/webapps/magento_session_reaper_cve_2025_54236` | Magento 2 / Adobe Commerce session reaper unauthenticated deserialization RCE (CVE-2025-54236) |
| `exploits/webapps/mangosweb_xss` | mangosweb 4.0.6 reflected XSS in search parameter |
| `exploits/webapps/mantisbt_exec` | Mantis Bug Tracker 2.30 login fingerprint + auth-required RCE |
| `exploits/webapps/mobiledetect_xss` | Mobile_Detect 2.8.31 reflected XSS via User-Agent header |
| `exploits/webapps/openrepeater_inject` | OpenRepeater 2.1 detection + auth-required command injection |
| `exploits/webapps/opensisce_sqli` | openSIS Classic 8.0 detection + auth-bypass / SQLi via login form |
| `exploits/webapps/phpipam_sqli` | phpIPAM 1.4 / 1.5.1 admin endpoint detection + SQL error probe |
| `exploits/webapps/phpmyadmin_sqli` | phpMyAdmin 5.0.0 detection at common paths + auth-required SQLi |
| `exploits/webapps/phpmyfaq_xss` | phpMyFAQ 3.1.7 / 2.9.8 detection + reflected XSS probes |
| `exploits/webapps/pihole_redis_rce_cve_2024_34361` | Pi-hole 5.18.3 admin UI detection + authenticated SSRF + Redis abuse for RCE (CVE-2024-34361) |
| `exploits/webapps/piwigo_sqli` | Piwigo 13.6.0 admin endpoint detection + SQLi probe |
| `exploits/webapps/pluck_upload` | Pluck CMS 4.7.10 / 4.7.7-dev2 admin upload to PHP RCE |
| `exploits/webapps/react_rsc_rce_cve_2025_55182` | React 19.2.0 server components RCE markers detection (CVE-2025-55182) |
| `exploits/webapps/redash_rce_hash` | Redash detection + auth-required RCE / hash recovery PoC |
| `exploits/webapps/rosariosis_xss` | RosarioSIS 6.7.2 login fingerprint + reflected XSS via search |
| `exploits/webapps/sharepoint_toolpane_cve_2025_53770` | Microsoft SharePoint ToolPane.aspx auth bypass + ViewState deserialization (CVE-2025-53770 / 53771 / 49704 / 49706) |
| `exploits/webapps/textpattern_xss` | Textpattern CMS 4.9.0 admin endpoint detection + auth stored XSS in /pref |
| `exploits/webapps/varnish_styx_smuggling` | Varnish ↔ Styx HTTP Request Smuggling (TE.CL) edge fingerprint |
| `exploits/webapps/visualstudio_debugger` | VS Code Remote Debugger (1.30 - 1.39) Node Inspector exposure (CVE-2019-1414) |
| `exploits/webapps/wfentlm_disclose` | Windows File Explorer NTLMv2 hash disclosure — UNC trigger HTML payload generator |
| `exploits/webapps/wp_storychief_rce_cve_2025_7441` | WordPress StoryChief 1.0.42 unauthenticated RCE via featured image (CVE-2025-7441) |
| `exploits/webapps/wpcpi_upload` | WP for CPI 1.0.2 unauthenticated arbitrary file upload |
| `exploits/webapps/wpgivewp_inject` | WordPress GiveWP 3.14.1 PHP object injection via donation form |
| `exploits/webapps/wpomnipress_xss` | WP OmniPress 1.6.3 plugin readme detection + auth admin stored XSS |
| `exploits/webapps/yourls_sqli_cve_2022_0088` | YOURLS 1.8.2 admin/upgrade.php SQL injection (CVE-2022-0088) |
| `exploits/webapps/yourls_xsrf_idor` | YOURLS 1.8.2 admin/ajax.php CSRF / IDOR probe (CVE-2022-0088) |
| `exploits/webapps/zimbra_postjournal_rce` | Zimbra Collaboration Suite postjournal helper unauthenticated RCE — SMTP banner fingerprint |

### Windows

| Module Path | Description |
|-------------|-------------|
| `exploits/windows/windows_dwm_cve_2026_20805` | Windows DWM kernel object pointer leak for KASLR bypass (CVE-2026-20805) |

---

## Scanners

| Module Path | Description |
|-------------|-------------|
| `scanners/api_endpoint_scanner` | REST API endpoint discovery and vulnerability scanner with fuzzing, auth bypass, and injection detection |
| `scanners/dir_brute` | HTTP directory and file enumeration via wordlist with recursive scanning and evasion techniques |
| `scanners/dns_recursion` | Open DNS resolver and amplification attack detection |
| `scanners/honeypot_scanner` | Honeypot indicator detection by probing 50 common TCP ports |
| `scanners/http_method_scanner` | HTTP method enumeration to identify dangerous or misconfigured endpoints |
| `scanners/http_title_scanner` | HTTP/HTTPS page title fetcher for target fingerprinting |
| `scanners/ipmi_enum_exploit` | IPMI version detection, cipher 0 bypass, default credentials, and RAKP hash dumping |
| `scanners/nbns_scanner` | NBNS name queries to UDP 137 for Windows host discovery |
| `scanners/ping_sweep` | Host discovery via ICMP echo, TCP connect, SYN, and ACK probes with CIDR support |
| `scanners/port_scanner` | TCP/UDP port scanner with service detection, banner grabbing, and configurable ranges |
| `scanners/proxy_scanner` | HTTP CONNECT, SOCKS4, SOCKS5, and transparent proxy discovery with authentication detection |
| `scanners/redis_scanner` | Redis instance discovery and unauthenticated access detection |
| `scanners/reflect_scanner` | UDP amplification vulnerability scanner for DNS, NTP monlist, SSDP, and Memcached reflectors |
| `scanners/sample_scanner` | Demonstration scanner checking HTTP/HTTPS reachability and response codes |
| `scanners/sequential_fuzzer` | Character-based HTTP fuzzer with 10+ encodings, custom charsets, and concurrent requests |
| `scanners/service_scanner` | Service port banner grabbing and version identification |
| `scanners/smtp_user_enum` | SMTP username enumeration via VRFY commands with wordlist scanning |
| `scanners/snmp_scanner` | SNMP v1/v2c community string testing against target devices |
| `scanners/source_port_scanner` | Firewall bypass scanner discovering which source ports are allowed through |
| `scanners/ssdp_msearch` | UPnP device discovery via SSDP M-SEARCH multicast and unicast probes |
| `scanners/ssh_scanner` | SSH banner grabbing with CIDR range support and concurrent scanning |
| `scanners/ssl_scanner` | SSL/TLS certificate and configuration analysis, expired certificate detection |
| `scanners/stalkroute_full_traceroute` | Advanced traceroute with ICMP/TCP/UDP probes, OS fingerprint spoofing, and decoy packets |
| `scanners/subdomain_scanner` | Subdomain brute-force enumeration via DNS resolution |
| `scanners/vnc_scanner` | VNC protocol version and security type enumeration |
| `scanners/vuln_checker` | Fingerprint-based vulnerability scanner with detection signatures across all exploit modules |
| `scanners/waf_detector` | Web Application Firewall and CDN provider detection via HTTP response analysis |

---

## Credential Modules

### Generic

| Module Path | Description |
|-------------|-------------|
| `creds/generic/couchdb_bruteforce` | CouchDB session cookie and HTTP Basic auth brute force with default credential testing and subnet scanning |
| `creds/generic/elasticsearch_bruteforce` | Elasticsearch HTTP Basic auth brute force against cluster root and security API with subnet scanning |
| `creds/generic/enablebruteforce` | Raises file descriptor limits (ulimit) for high-concurrency brute-force operations |
| `creds/generic/fortinet_bruteforce` | Fortinet FortiGate SSL VPN web auth brute force with certificate pinning and realm support |
| `creds/generic/ftp_anonymous` | FTP anonymous access check with FTPS, IPv4/IPv6, and mass scanning support |
| `creds/generic/ftp_bruteforce` | FTP/FTPS brute force with combo mode, concurrent connections, and subnet scanning |
| `creds/generic/http_basic_bruteforce` | HTTP Basic Authentication brute force with HTTPS support, default credentials, and subnet scanning |
| `creds/generic/imap_bruteforce` | IMAP/IMAPS LOGIN command brute force over raw TCP with TLS support and subnet scanning |
| `creds/generic/l2tp_bruteforce` | L2TP/IPsec VPN CHAP auth brute force against L2TP concentrators |
| `creds/generic/memcached_bruteforce` | Memcached open instance detection and SASL PLAIN auth brute force over binary protocol |
| `creds/generic/mqtt_bruteforce` | MQTT 3.1.1 auth testing with TLS/SSL, anonymous detection, and multiple attack modes |
| `creds/generic/mysql_bruteforce` | MySQL native password wire protocol brute force with HandshakeV10 parsing and subnet scanning |
| `creds/generic/pop3_bruteforce` | POP3/POP3S brute force with SSL/TLS support, retry logic, and subnet scanning |
| `creds/generic/postgres_bruteforce` | PostgreSQL protocol v3 brute force supporting cleartext and MD5 auth with subnet scanning |
| `creds/generic/proxy_bruteforce` | HTTP CONNECT, SOCKS5, and HTTP forward proxy authentication brute force |
| `creds/generic/rdp_bruteforce` | RDP auth brute force with NLA, TLS, Standard RDP, and Negotiate security levels |
| `creds/generic/redis_bruteforce` | Redis AUTH brute force supporting legacy and ACL mode with server info gathering on success |
| `creds/generic/rtsp_bruteforce` | RTSP auth brute force for IP cameras with path bruting and custom headers |
| `creds/generic/sample_cred_check` | Sample module testing HTTP Basic Auth with default admin:admin credentials |
| `creds/generic/smtp_bruteforce` | SMTP auth brute force supporting PLAIN and LOGIN mechanisms with combo mode |
| `creds/generic/snmp_bruteforce` | SNMPv1/v2c community string brute force with read/write detection and subnet scanning |
| `creds/generic/ssh_bruteforce` | SSH password brute force with default credential testing, combo mode, and subnet scanning |
| `creds/generic/ssh_spray` | SSH password spray across multiple targets with lockout-aware delays |
| `creds/generic/ssh_user_enum` | SSH username enumeration via timing-based side-channel attack (CVE-2018-15473 inspired) |
| `creds/generic/telnet_bruteforce` | Telnet brute force with full IAC negotiation, multiple attack modes, and subnet scanning |
| `creds/generic/telnet_hose` | Mass internet Telnet default credential scanner with 500 workers and disk-based state |
| `creds/generic/vnc_bruteforce` | VNC DES challenge-response brute force with bit-reversed key derivation and subnet scanning |

### Camera

| Module Path | Description |
|-------------|-------------|
| `creds/camera/acti/acti_camera_default` | ACTi IP camera default credential check across FTP, SSH, Telnet, and HTTP |

### Camxploit

| Module Path | Description |
|-------------|-------------|
| `creds/camxploit/camxploit` | Mass camera discovery and default credential testing across RTSP, HTTP, and HTTPS |

---

## OSINT (Open-Source Intelligence)

Reconnaissance modules that gather public information without sending traffic to the target itself — DNS records, certificate transparency logs, subdomain enumeration via public APIs, etc. Run these *before* scanners, when you only have a domain or organisation name. New category in v0.4.9.

| Module Path | Description |
|-------------|-------------|
| `osint/cert_transparency` | Subdomain enumeration via crt.sh certificate transparency logs. Polls `is_cancelled()` in the parsing loop; persists deduplicated subdomains to the loot store; supports the standard CIDR / file / random target dispatcher even though the target is normally a domain |

---

## Plugins

| Module Path | Description |
|-------------|-------------|
| `plugins/sample_plugin` | Template plugin demonstrating the RustSploit plugin API with mass scan and cfg_prompt integration. Note: "plugins" are compile-time module templates, not loadable shared objects |
