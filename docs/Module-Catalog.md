# Module Catalog

All modules live under `src/modules/` and are auto-discovered by `build.rs`. Use the shell's `modules` command or `find <keyword>` for the live list. Use `info <module>` to see metadata (CVE, author, rank) if available.

> **Module categories:** `exploits/`, `scanners/`, `creds/`, `plugins/` -- all auto-discovered at build time. Adding a new subdirectory under `src/modules/` automatically creates a new category.

**Totals:** 137 exploit modules (24 with `check()`), 24 scanners, 19 credential modules, 1 plugin.

---

## Exploits

### Bluetooth

| Module Path | Description |
|-------------|-------------|
| `exploits/bluetooth/wpair` | Hijacks Bluetooth accessories via Google Fast Pair protocol flaw allowing unauthorized bonding, account key injection, and audio interception |

### Cameras

| Module Path | Description |
|-------------|-------------|
| `exploits/cameras/abus/abussecurity_camera_cve202326609variant1` | Abus security camera LFI, RCE, and SSH root access (CVE-2023-26609) |
| `exploits/cameras/acti/acm_5611_rce` | Command injection in ACTi ACM-5611 video cameras for RCE |
| `exploits/cameras/avtech/cve_2024_7029_avtech_camera` | AVTECH IP camera remote code execution (CVE-2024-7029) |
| `exploits/cameras/hikvision/hikvision_rce_cve_2021_36260` | Hikvision IP camera command injection RCE (CVE-2021-36260) |
| `exploits/cameras/reolink/reolink_rce_cve_2019_11001` | Reolink camera authenticated OS command injection via TestEmail (CVE-2019-11001) |
| `exploits/cameras/uniview/uniview_nvr_pwd_disclosure` | Uniview NVR remote credential extraction and decoding |

### Crypto

| Module Path | Description |
|-------------|-------------|
| `exploits/crypto/geth_dos_cve_2026_22862` | Go-Ethereum ECIES panic DoS via malformed encrypted messages (CVE-2026-22862) |
| `exploits/crypto/heartbleed` | OpenSSL Heartbleed memory leak exploitation (CVE-2014-0160) |

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
| `exploits/dos/udp_flood` | High-speed UDP flood with random, null, and pattern payload modes |

### Frameworks

| Module Path | Description |
|-------------|-------------|
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
| `exploits/frameworks/wsus/cve_2025_59287_wsus_rce` | Unauthenticated RCE in Windows Server Update Services (CVE-2025-59287) |

### FTP

| Module Path | Description |
|-------------|-------------|
| `exploits/ftp/ftp_bounce_test` | FTP bounce attack test via PORT commands to third-party hosts |
| `exploits/ftp/pachev_ftp_path_traversal_1_0` | Directory traversal in Pachev FTP Server 1.0 to read files outside FTP root |

### IPMI

| Module Path | Description |
|-------------|-------------|
| `exploits/ipmi/ipmi_enum_exploit` | IPMI enumeration with cipher 0 bypass, default credential brute force, and RAKP hash dumping |

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
| `exploits/payloadgens/batgen` | Creates multi-stage .bat dropper chains with PowerShell download and execution |
| `exploits/payloadgens/lnkgen` | Malicious Windows LNK files for SMB NTLMv2-SSP hash disclosure (CVE-2025-50154, CVE-2025-59214) |
| `exploits/payloadgens/narutto_dropper` | Polymorphic 3-stage stealth droppers with LOLBAS support and anti-VM evasion |
| `exploits/payloadgens/payload_encoder` | Payload encoding (XOR, base64, hex, zero-width, etc.) for AV evasion |
| `exploits/payloadgens/polymorph_dropper` | 3-stage polymorphic payload chain using Task Scheduler for persistence |

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

### SSH

| Module Path | Description |
|-------------|-------------|
| `exploits/ssh/erlang_otp_ssh_rce_cve_2025_32433` | Erlang/OTP SSH server unauthenticated RCE (CVE-2025-32433) |
| `exploits/ssh/libssh_auth_bypass_cve_2018_10933` | libSSH server authentication bypass (CVE-2018-10933) |
| `exploits/ssh/openssh_regresshion_cve_2024_6387` | OpenSSH sshd signal handler race condition for unauthenticated RCE (CVE-2024-6387) |
| `exploits/ssh/opensshserver_9_8p1race_condition` | OpenSSH 9.8p1 race condition for heap-based RCE |
| `exploits/ssh/sshpwn_auth_passwd` | OpenSSH auth2-passwd.c password length DoS, change info leak, timing enumeration |
| `exploits/ssh/sshpwn_pam` | OpenSSH auth-pam.c environment injection, memory leak DoS, username validation bypass |
| `exploits/ssh/sshpwn_scp_attacks` | OpenSSH SCP path traversal, command injection, and brace expansion DoS |
| `exploits/ssh/sshpwn_session` | OpenSSH session.c forced command bypass, env injection, privsep issues |
| `exploits/ssh/sshpwn_sftp_attacks` | OpenSSH SFTP symlink injection, chmod setuid abuse, path traversal, partial write |

### Telnet

| Module Path | Description |
|-------------|-------------|
| `exploits/telnet/telnet_auth_bypass_cve_2026_24061` | Telnet authentication bypass on vulnerable devices (CVE-2026-24061) |

### VoIP

| Module Path | Description |
|-------------|-------------|
| `exploits/voip/cve_2025_64328_freepbx_cmdi` | FreePBX filestore module post-authentication command injection (CVE-2025-64328) |

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
| `exploits/webapps/mcpjam/cve_2026_23744_mcpjam_rce` | MCPJam Inspector <= 1.4.2 unauthenticated RCE (CVE-2026-23744) |
| `exploits/webapps/n8n/n8n_rce_cve_2025_68613` | n8n workflow automation RCE via expression injection (CVE-2025-68613) |
| `exploits/webapps/react/react2shell` | React Server Components / Next.js RCE via RSC Flight protocol deserialization |
| `exploits/webapps/roundcube/roundcube_postauth_rce` | Roundcube webmail post-auth RCE via deserialization in file upload |
| `exploits/webapps/sap_netweaver_rce_cve_2025_31324` | SAP NetWeaver Visual Composer unauthenticated file upload to RCE (CVE-2025-31324) |
| `exploits/webapps/sharepoint/cve_2024_38094` | SharePoint Server authenticated deserialization RCE via .bdcm upload (CVE-2024-38094) |
| `exploits/webapps/sharepoint/cve_2025_53770_sharepoint_toolpane_rce` | SharePoint on-premises unauthenticated deserialization RCE (CVE-2025-53770) |
| `exploits/webapps/solarwinds/cve_2025_40551_solarwinds_whd_rce` | SolarWinds Web Help Desk unauthenticated Java deserialization RCE (CVE-2025-40551) |
| `exploits/webapps/spotube/spotube` | Spotube API path traversal via WebSocket and denial of service |
| `exploits/webapps/termix/termix_xss_cve_2026_22804` | Termix File Manager stored XSS via SVG upload in Electron context (CVE-2026-22804) |
| `exploits/webapps/wordpress/vitepos_file_upload_cve_2025_13156` | Vitepos for WooCommerce authenticated arbitrary PHP file upload (CVE-2025-13156) |
| `exploits/webapps/wordpress/wp_bricks_rce_cve_2024_25600` | Bricks Builder for WordPress unauthenticated RCE via render_element (CVE-2024-25600) |
| `exploits/webapps/wordpress/wp_litespeed_rce_cve_2024_28000` | LiteSpeed Cache weak hash brute force for WordPress admin escalation (CVE-2024-28000) |
| `exploits/webapps/wordpress/wp_royal_elementor_rce_cve_2024_32suspended` | Royal Elementor Addons unauthenticated PHP webshell upload |
| `exploits/webapps/xwiki/cve_2025_24893_xwiki_rce` | XWiki SolrSearch unauthenticated RCE via Groovy template injection (CVE-2025-24893) |
| `exploits/webapps/zabbix/zabbix_7_0_0_sql_injection` | Zabbix 7.0.0 time-based SQL injection in API endpoints |

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
| `scanners/redis_scanner` | Redis instance discovery and unauthenticated access detection |
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
| `scanners/waf_detector` | Web Application Firewall and CDN provider detection via HTTP response analysis |

---

## Credential Modules

### Generic

| Module Path | Description |
|-------------|-------------|
| `creds/generic/ssh_bruteforce` | SSH password brute force with default credential testing, combo mode, and subnet scanning |
| `creds/generic/rdp_bruteforce` | RDP auth brute force with NLA, TLS, Standard RDP, and Negotiate security levels |
| `creds/generic/ftp_bruteforce` | FTP/FTPS brute force with combo mode, concurrent connections, and subnet scanning |
| `creds/generic/telnet_bruteforce` | Telnet brute force with full IAC negotiation, multiple attack modes, and subnet scanning |
| `creds/generic/smtp_bruteforce` | SMTP auth brute force supporting PLAIN and LOGIN mechanisms with combo mode |
| `creds/generic/pop3_bruteforce` | POP3/POP3S brute force with SSL/TLS support, retry logic, and subnet scanning |
| `creds/generic/mqtt_bruteforce` | MQTT 3.1.1 auth testing with TLS/SSL, anonymous detection, and multiple attack modes |
| `creds/generic/snmp_bruteforce` | SNMPv1/v2c community string brute force with read/write detection and subnet scanning |
| `creds/generic/rtsp_bruteforce` | RTSP auth brute force for IP cameras with path bruting and custom headers |
| `creds/generic/l2tp_bruteforce` | L2TP/IPsec VPN CHAP auth brute force against L2TP concentrators |
| `creds/generic/fortinet_bruteforce` | Fortinet FortiGate SSL VPN web auth brute force with certificate pinning and realm support |
| `creds/generic/ftp_anonymous` | FTP anonymous access check with FTPS, IPv4/IPv6, and mass scanning support |
| `creds/generic/telnet_hose` | Mass internet Telnet default credential scanner with 500 workers and disk-based state |
| `creds/generic/ssh_user_enum` | SSH username enumeration via timing-based side-channel attack (CVE-2018-15473 inspired) |
| `creds/generic/ssh_spray` | SSH password spray across multiple targets with lockout-aware delays |
| `creds/generic/enablebruteforce` | Raises file descriptor limits (ulimit) for high-concurrency brute-force operations |
| `creds/generic/sample_cred_check` | Sample module testing HTTP Basic Auth with default admin:admin credentials |

### Camera

| Module Path | Description |
|-------------|-------------|
| `creds/camera/acti/acti_camera_default` | ACTi IP camera default credential check across FTP, SSH, Telnet, and HTTP |

### Camxploit

| Module Path | Description |
|-------------|-------------|
| `creds/camxploit/camxploit` | Mass camera discovery and default credential testing across RTSP, HTTP, and HTTPS |

---

## Plugins

| Module Path | Description |
|-------------|-------------|
| `plugins/sample_plugin` | Template plugin demonstrating the RustSploit plugin API with mass scan and cfg_prompt integration |
