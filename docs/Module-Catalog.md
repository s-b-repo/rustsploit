# Module Catalog

All modules live under `src/modules/` and are auto-discovered by `build.rs`. Use the shell's `modules` command or `find <keyword>` for the live list. The table below reflects the current module set.

---

## Exploits

### Cameras

| Module Path | CVE / Notes |
|-------------|-------------|
| `exploits/cameras/abussecurity_camera_cve202326609variant1` | Abus Security Camera RCE (variant 1) |
| `exploits/cameras/abussecurity_camera_cve202326609variant2` | Abus Security Camera RCE (variant 2) |
| `exploits/cameras/avtech_cve_2024_7029` | Avtech Camera RCE |
| `exploits/cameras/uniview_password_disclosure` | Uniview password disclosure |
| `exploits/cameras/acti` | ACTi camera RCE |
| `exploits/hikvision/hikvision_rce_cve_2021_36260` | Hikvision command injection — safe check, blind exec, SSH shell setup |

### Routers & Network Infrastructure

| Module Path | CVE / Notes |
|-------------|-------------|
| `exploits/routers/tplink_vn020_dos` | TP-Link VN020 DoS |
| `exploits/routers/tplink_wr740n_dos` | TP-Link WR740N DoS |
| `exploits/routers/tplink_tapo_c200_cve_2021_4045` | TP-Link Tapo C200 RCE |
| `exploits/network_infra/ivanti_connect_secure_bof` | Ivanti Connect Secure stack buffer overflow |
| `exploits/network_infra/pan_os_auth_bypass` | PAN-OS auth bypass |
| `exploits/network_infra/heartbleed` | Heartbleed (CVE-2014-0160) |
| `exploits/network_infra/zabbix_sqli_700` | Zabbix 7.0.0 SQL injection |
| `exploits/network_infra/forticloud_sso_cve_2026_24858` | FortiCloud SSO auth bypass |
| `exploits/network_infra/ruijie/*` | 7 Ruijie modules — RCE, Auth Bypass, SSRF |

### Web Applications

| Module Path | CVE / Notes |
|-------------|-------------|
| `exploits/webapps/apache_tomcat_cve_2025_24813` | Apache Tomcat partial PUT RCE |
| `exploits/webapps/apache_tomcat_catkiller_cve_2025_31650` | Apache Tomcat CatKiller DoS |
| `exploits/webapps/roundcube_postauth_rce` | Roundcube post-auth RCE |
| `exploits/webapps/spotube_zero_day` | Spotube zero-day |
| `exploits/webapps/flowise_cve_2025_59528` | Flowise RCE |
| `exploits/webapps/react2shell_cve_2025_55182` | React2Shell RCE |
| `exploits/webapps/jenkins_2_441_lfi` | Jenkins LFI |
| `exploits/webapps/sharepoint_cve_2024_38094` | SharePoint deserialization RCE |

### SSH

| Module Path | CVE / Notes |
|-------------|-------------|
| `exploits/ssh/openssh_9_8p1_race` | OpenSSH 9.8p1 race condition |
| `exploits/ssh/sshpwn_framework` | SFTP symlink/setuid/traversal, SCP injection/DoS, session env injection |

### Telnet

| Module Path | CVE / Notes |
|-------------|-------------|
| `exploits/telnet/cve_2026_24061` | GNU inetutils-telnetd auth bypass via `NEW_ENVIRON` — mass-scan capable |

### Frameworks & Other

| Module Path | CVE / Notes |
|-------------|-------------|
| `exploits/frameworks/n8n_rce_cve_2025_68613` | n8n workflow expression injection — 6 payloads (info, cmd, env, read, write, reverse shell) |
| `exploits/frameworks/fortiweb_sqli_rce_cve_2025_25257` | FortiWeb SQLi → webshell deploy |
| `exploits/mongo/mongobleed` | CVE-2025-14847 — MongoDB zlib memory disclosure, deep-scan mode |
| `exploits/nginx/nginx_pwner` | Nginx misconfiguration scanner — 10 checks (CRLF, alias traversal, PHP detection, etc.) |
| `exploits/windows/dwm_cve_2026_20805` | Windows DWM info disclosure |
| `exploits/crypto/geth_cve_2026_22862` | Go-Ethereum ecies panic DoS |
| `exploits/frameworks/termix_cve_2026_22804` | Termix stored XSS |

### DoS / Stress Testing

| Module Path | Description |
|-------------|-------------|
| `exploits/dos/connection_exhaustion_flood` | FD-bounded semaphore, connect & drop, infinite mode |
| `exploits/dos/null_syn_exhaustion` | Raw packet IP spoofing, XorShift128+ RNG, >1M PPS |
| `exploits/dos/tcp_connection_flood` | Pre-resolved DNS, high-concurrency, infinite mode |
| `exploits/dos/http2_rapid_reset` | CVE-2023-44487 HTTP/2 Rapid Reset |

### Payload Generators

| Module Path | Description |
|-------------|-------------|
| `exploits/payloadgens/narutto_dropper` | Batch malware dropper |
| `exploits/payloadgens/bat_payload_generator` | BAT payload generator |

---

## Scanners

| Module Path | Description |
|-------------|-------------|
| `scanners/port_scanner` | TCP/UDP/SYN/ACK port scanner |
| `scanners/ping_sweep` | ICMP/TCP/UDP/SYN/ACK ping sweep |
| `scanners/ssdp_msearch` | SSDP M-SEARCH device enumerator |
| `scanners/http_title_scanner` | HTTP title fetcher |
| `scanners/http_method_scanner` | HTTP method enumeration |
| `scanners/dns_recursion` | DNS recursion / amplification tester (uses hickory-client v0.25) |
| `scanners/stalkroute_full_traceroute` | Firewall-evasion traceroute (root required) |
| `scanners/ssh_scanner` | SSH banner grabbing with CIDR support |
| `scanners/dir_brute` | Directory bruteforcer — recursive, extensions, smart filtering |
| `scanners/sequential_fuzzer` | URL / header / body fuzzer — 10+ encodings, custom charsets |
| `scanners/api_endpoint_scanner` | API vulnerability scanner — SQLi, NoSQLi, CMDi, Path Traversal |
| `scanners/smtp_user_enum` | SMTP user enumeration |
| `scanners/ipmi_enum_exploit` | IPMI enumeration and exploitation |

---

## Credential Modules

### Generic

| Module Path | Description |
|-------------|-------------|
| `creds/generic/ftp_anonymous` | FTP anonymous auth check |
| `creds/generic/ftp_bruteforce` | FTPS brute force — 5 modes, JSON config, streaming wordlist |
| `creds/generic/ssh_bruteforce` | SSH password brute force |
| `creds/generic/ssh_user_enum` | SSH user enumeration via timing attack (CVE-2018-15473 inspired) |
| `creds/generic/ssh_password_spray` | SSH password spray |
| `creds/generic/telnet_bruteforce` | Telnet — full IAC negotiation, state machine, verbose mode |
| `creds/generic/telnet_hose` | Mass internet Telnet scanner — 500 workers, disk-based state, auto-exclusion |
| `creds/generic/pop3_bruteforce` | POP3(S) brute force |
| `creds/generic/smtp_bruteforce` | SMTP brute force |
| `creds/generic/rtsp_bruteforce` | RTSP path + header bruting |
| `creds/generic/rdp_bruteforce` | RDP auth brute — streaming >150MB wordlists, multi security levels |
| `creds/generic/mqtt_bruteforce` | MQTT 3.1.1 brute force — proper CONNECT/CONNACK |
| `creds/generic/snmp_bruteforce` | SNMP community string brute force |
| `creds/generic/l2tp_bruteforce` | L2TP/IPsec — strongswan, xl2tpd, NetworkManager, rasdial, networksetup |
| `creds/generic/fortinet_bruteforce` | Fortinet SSL VPN brute force |

### Camera

| Module Path | Description |
|-------------|-------------|
| `creds/camxploit/camxploit` | Mass camera scanner with masscan-style parallel scanning, EXCLUDED_RANGES |
| `creds/camera/acti/acti_camera_default` | ACTi camera default credential check |
