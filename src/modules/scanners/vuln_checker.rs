use anyhow::Result;
use colored::*;
use std::time::Duration;
use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};
use crate::utils::{cfg_prompt_default, cfg_prompt_required, normalize_target};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Vulnerability Checker".to_string(),
        description: "Runs fingerprint probes against a target to identify vulnerable products/services.\n\
                       Covers all exploit modules with built-in detection signatures.\n\
                       Usage: use scanners/vuln_checker → set target → run"
            .to_string(),
        authors: vec!["RustSploit Team".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

pub async fn run(target: &str) -> Result<()> {
    if !crate::utils::is_batch_mode() {
        if !crate::utils::is_batch_mode() {
            print_banner();
        }
    }

    let raw = if target.is_empty() {
        cfg_prompt_required("target", "Target IP/hostname").await?
    } else {
        target.to_string()
    };
    let target = normalize_target(&raw)?;

    let filter = cfg_prompt_default("filter", "Module filter (blank = all)", "").await?;
    let show_all_str = cfg_prompt_default("show_all", "Show not-vulnerable results? (y/n)", "n")
        .await?
        .to_lowercase();
    let show_all = matches!(show_all_str.as_str(), "y" | "yes" | "true");

    let probes = build_probe_registry();
    let filtered: Vec<&Probe> = probes
        .iter()
        .filter(|p| filter.is_empty() || p.module.to_lowercase().contains(&filter.to_lowercase()))
        .collect();

    let total = filtered.len();
    crate::mprintln!("{} Running {} probes against {}...", "[*]".cyan(), total, target);
    crate::mprintln!();

    let mut vulnerable = Vec::new();
    let mut unknown = Vec::new();
    let mut not_vulnerable = 0u32;
    let mut errors = 0u32;

    let http_client = crate::utils::build_http_client(Duration::from_secs(5)).ok();

    for (i, probe) in filtered.iter().enumerate() {
        if (i + 1) % 10 == 0 || i + 1 == total {
            crate::mprintln!("{} [{}/{}] ...", "[*]".blue(), i + 1, total);
        }

        let result = run_probe(probe, &target, http_client.as_ref()).await;

        match &result {
            CheckResult::Vulnerable(msg) => {
                crate::mprintln!("{} {} — {}", "[+]".green().bold(), probe.module, msg);
                vulnerable.push((probe.module.to_string(), msg.clone()));
            }
            CheckResult::Unknown(msg) => {
                crate::mprintln!("{} {} — {}", "[?]".yellow(), probe.module, msg);
                unknown.push((probe.module.to_string(), msg.clone()));
            }
            CheckResult::NotVulnerable(msg) => {
                not_vulnerable += 1;
                if show_all {
                    crate::mprintln!("{} {} — {}", "[-]".dimmed(), probe.module, msg);
                }
            }
            CheckResult::Error(msg) => {
                errors += 1;
                if show_all {
                    crate::mprintln!("{} {} — {}", "[!]".red(), probe.module, msg);
                }
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "═══════════════════════════════════════════".cyan());
    crate::mprintln!("{} Scan Summary for {}", "[*]".cyan(), target);
    crate::mprintln!("{}", "═══════════════════════════════════════════".cyan());
    crate::mprintln!();

    if !vulnerable.is_empty() {
        crate::mprintln!("{} VULNERABLE ({})", "[+]".green().bold(), vulnerable.len());
        for (path, msg) in &vulnerable {
            crate::mprintln!("    {} — {}", path.green(), msg);
        }
        crate::mprintln!();
    }

    if !unknown.is_empty() {
        crate::mprintln!("{} Detected / Possible ({})", "[?]".yellow(), unknown.len());
        for (path, msg) in &unknown {
            crate::mprintln!("    {} — {}", path.yellow(), msg);
        }
        crate::mprintln!();
    }

    crate::mprintln!("  {} not vulnerable, {} errors", not_vulnerable, errors);
    crate::mprintln!();

    Ok(())
}

// ─── Probe types ───────────────────────────────────────────────────────────

enum ProbeType {
    Http { scheme: &'static str, port: u16, path: &'static str, markers: &'static [&'static str] },
    Tcp { port: u16 },
    TcpBanner { port: u16, marker: &'static str },
    Skip,
}

struct Probe {
    module: &'static str,
    probe: ProbeType,
}

async fn run_probe(probe: &Probe, target: &str, client: Option<&reqwest::Client>) -> CheckResult {
    match &probe.probe {
        ProbeType::Http { scheme, port, path, markers } => {
            let client = match client {
                Some(c) => c,
                None => return CheckResult::Error("no HTTP client".into()),
            };
            let base = format!("{}://{}:{}", scheme, target, port);
            let url = format!("{}{}", base, path);
            match client.get(&url).send().await {
                Ok(resp) => {
                    let server = resp.headers()
                        .get("server")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_lowercase();
                    let body = resp.text().await.unwrap_or_default().to_lowercase();
                    for &m in *markers {
                        let ml = m.to_lowercase();
                        if body.contains(&ml) || server.contains(&ml) {
                            return CheckResult::Unknown(format!(
                                "'{}' detected at {} ({})", m, base, probe.module
                            ));
                        }
                    }
                    CheckResult::NotVulnerable(format!("no markers at {}", base))
                }
                Err(_) => CheckResult::NotVulnerable(format!("{} not reachable", base)),
            }
        }
        ProbeType::Tcp { port } => {
            let addr = format!("{}:{}", target, port);
            match crate::utils::network::tcp_connect(&addr, Duration::from_secs(3)).await {
                Ok(_) => CheckResult::Unknown(format!("port {} open at {}", port, target)),
                Err(_) => CheckResult::NotVulnerable(format!("{}:{} closed", target, port)),
            }
        }
        ProbeType::TcpBanner { port, marker } => {
            let addr = format!("{}:{}", target, port);
            match crate::utils::network::tcp_connect(&addr, Duration::from_secs(3)).await {
                Ok(mut stream) => {
                    let mut buf = [0u8; 512];
                    match tokio::time::timeout(
                        Duration::from_secs(3),
                        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
                    ).await {
                        Ok(Ok(n)) if n > 0 => {
                            let banner = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                            if banner.contains(&marker.to_lowercase()) {
                                CheckResult::Unknown(format!(
                                    "{} service at {}: {}", marker, addr, banner.trim()
                                ))
                            } else {
                                CheckResult::NotVulnerable(format!("non-{} service at {}", marker, addr))
                            }
                        }
                        _ => CheckResult::Unknown(format!("port {} open at {} (no banner)", port, target)),
                    }
                }
                Err(_) => CheckResult::NotVulnerable(format!("{}:{} closed", target, port)),
            }
        }
        ProbeType::Skip => {
            CheckResult::NotVulnerable(format!("{}: local-only / payload generator", probe.module))
        }
    }
}

// ─── Probe registry ────────────────────────────────────────────────────────

fn build_probe_registry() -> Vec<Probe> {
    vec![
        // ── SSH ──
        p("exploits/ssh/libssh_auth_bypass_cve_2018_10933", tcp_banner(22, "SSH")),
        p("exploits/ssh/openssh_regresshion_cve_2024_6387", tcp_banner(22, "OpenSSH")),
        p("exploits/ssh/opensshserver_9_8p1race_condition", tcp_banner(22, "SSH")),
        p("exploits/ssh/erlang_otp_ssh_rce_cve_2025_32433", tcp_banner(22, "SSH")),
        p("exploits/ssh/asyncssh_beginauthpass", tcp_banner(22, "SSH")),
        p("exploits/ssh/paramiko_authnonepass", tcp_banner(22, "SSH")),
        p("exploits/ssh/paramiko_unknown_method", tcp_banner(22, "SSH")),
        p("exploits/ssh/sshpwn_auth_passwd", tcp_banner(22, "SSH")),
        p("exploits/ssh/sshpwn_pam", tcp_banner(22, "SSH")),
        p("exploits/ssh/sshpwn_scp_attacks", tcp_banner(22, "SSH")),
        p("exploits/ssh/sshpwn_session", tcp_banner(22, "SSH")),
        p("exploits/ssh/sshpwn_sftp_attacks", tcp_banner(22, "SSH")),
        p("exploits/ssh/libssh2_rogue_server", tcp_banner(22, "SSH")),

        // ── Telnet ──
        p("exploits/telnet/telnet_auth_bypass_cve_2026_24061", tcp_banner(23, "login")),

        // ── FTP ──
        p("exploits/ftp/ftp_bounce_test", tcp_banner(21, "FTP")),
        p("exploits/ftp/pachev_ftp_path_traversal_1_0", tcp_banner(21, "FTP")),

        // ── Crypto ──
        p("exploits/crypto/heartbleed", tcp(443)),
        p("exploits/crypto/geth_dos_cve_2026_22862", tcp(30303)),

        // ── Fortinet ──
        p("exploits/network_infra/fortinet/fortigate_rce_cve_2024_21762", https("/remote/login", &["Fortinet", "SVPNCOOKIE", "sslvpn"])),
        p("exploits/network_infra/fortinet/fortimanager_rce_cve_2024_47575", https("/", &["FortiManager", "Fortinet"])),
        p("exploits/network_infra/fortinet/fortios_heap_overflow_cve_2023_27997", https("/remote/login", &["Fortinet", "SVPNCOOKIE"])),
        p("exploits/network_infra/fortinet/fortios_auth_bypass_cve_2022_40684", https("/login", &["FortiGate", "FortiOS", "Fortinet"])),
        p("exploits/network_infra/fortinet/fortios_ssl_vpn_cve_2018_13379", https("/remote/login", &["Fortinet", "SVPNCOOKIE", "sslvpn"])),
        p("exploits/network_infra/fortinet/fortiweb_rce_cve_2021_22123", https("/", &["FortiWeb", "Fortinet"])),
        p("exploits/network_infra/fortinet/fortiweb_sqli_rce_cve_2025_25257", https("/fwb/login", &["FortiWeb", "Fortinet"])),
        p("exploits/network_infra/fortinet/fortisiem_rce_cve_2025_64155", tcp(443)),
        p("exploits/network_infra/fortinet/forticloud_sso_auth_bypass_cve_2026_24858", https("/", &["FortiCloud", "Fortinet"])),

        // ── Ivanti ──
        p("exploits/network_infra/ivanti/ivanti_neurons_rce_cve_2025_22460", https("/api/now/", &["Ivanti", "Neurons", "ITSM"])),
        p("exploits/network_infra/ivanti/cve_2025_0282_ivanti_preauth_rce", https("/dana-na/auth/url_default/welcome.cgi", &["Ivanti", "Pulse Secure"])),
        p("exploits/network_infra/ivanti/cve_2025_22457_ivanti_ics_rce", https("/dana-na/auth/url_default/welcome.cgi", &["Ivanti", "Connect Secure"])),
        p("exploits/network_infra/ivanti/ivanti_epmm_cve_2023_35082", https("/mifs/login.jsp", &["MobileIron", "Ivanti"])),
        p("exploits/network_infra/ivanti/ivanti_ics_auth_bypass_cve_2024_46352", https("/dana-na/auth/url_default/welcome.cgi", &["Ivanti", "Pulse Secure"])),
        p("exploits/network_infra/ivanti/ivanti_connect_secure_stack_based_buffer_overflow", https("/dana-na/auth/url_default/welcome.cgi", &["Ivanti", "Connect Secure"])),

        // ── VMware ──
        p("exploits/network_infra/vmware/vcenter_rce_cve_2024_37079", https("/ui", &["vSphere", "vCenter", "vmware"])),
        p("exploits/network_infra/vmware/esxi_auth_bypass_cve_2024_37085", https("/ui", &["vSphere", "ESXi"])),
        p("exploits/network_infra/vmware/vcenter_backup_rce", https("/ui", &["vSphere", "vCenter"])),
        p("exploits/network_infra/vmware/vcenter_file_read", https("/ui", &["vSphere", "vCenter"])),
        p("exploits/network_infra/vmware/esxi_vm_escape_check", https("/ui", &["vSphere", "ESXi"])),
        p("exploits/network_infra/vmware/esxi_vsock_client", ProbeType::Skip),

        // ── Palo Alto ──
        p("exploits/routers/palo_alto/panos_authbypass_cve_2025_0108", https("/php/login.php", &["Palo Alto", "PAN-OS"])),
        p("exploits/routers/palo_alto/panos_expedition_rce_cve_2024_9463", https("/os/login", &["Expedition", "Palo Alto"])),
        p("exploits/routers/palo_alto/panos_globalprotect_rce_cve_2024_3400", https("/ssl-vpn/hipreport.esp", &["PAN-OS", "GlobalProtect"])),

        // ── Citrix / SonicWall / HPE / QNAP / Commvault / Kubernetes ──
        p("exploits/network_infra/citrix/cve_2025_5777_citrixbleed2", https("/", &["Citrix", "NetScaler"])),
        p("exploits/network_infra/sonicwall/sonicwall_sslvpn_rce_cve_2025_32820", https("/", &["SonicWall", "SonicOS"])),
        p("exploits/network_infra/hpe/cve_2025_37164_hpe_oneview_rce", https("/", &["HPE OneView", "Hewlett"])),
        p("exploits/network_infra/qnap/qnap_qts_rce_cve_2024_27130", https("/", &["QNAP", "QTS"])),
        p("exploits/network_infra/commvault/cve_2025_34028_commvault_rce", https("/", &["Commvault"])),
        p("exploits/network_infra/kubernetes/cve_2025_1974_ingress_nginx_rce", https("/", &["nginx", "ingress"])),

        // ── Trend Micro ──
        p("exploits/network_infra/trend_micro/cve_2025_5777", tcp(443)),
        p("exploits/network_infra/trend_micro/cve_2025_69258", tcp(20001)),
        p("exploits/network_infra/trend_micro/cve_2025_69259", tcp(20001)),
        p("exploits/network_infra/trend_micro/cve_2025_69260", tcp(20001)),

        // ── Frameworks ──
        p("exploits/frameworks/apache_tomcat/cve_2025_24813_apache_tomcat_rce", http("/", &["Apache Tomcat", "tomcat"])),
        p("exploits/frameworks/apache_tomcat/cve_2025_24813_tomcat_put_rce", http("/", &["Apache Tomcat", "tomcat"])),
        p("exploits/frameworks/apache_tomcat/catkiller_cve_2025_31650", http("/", &["Apache Tomcat", "tomcat"])),
        p("exploits/frameworks/apache_camel/cve_2025_27636_camel_header_injection", http("/", &["Camel", "Apache"])),
        p("exploits/frameworks/jenkins/jenkins_cli_rce_cve_2024_23897", http_port(8080, "/login", &["Jenkins"])),
        p("exploits/frameworks/jenkins/jenkins_args4j_rce_cve_2024_24549", http_port(8080, "/login", &["Jenkins"])),
        p("exploits/frameworks/jenkins/jenkins_2_441_lfi", http_port(8080, "/login", &["Jenkins"])),
        p("exploits/frameworks/nginx/nginx_pwner", http("/", &["nginx"])),
        p("exploits/frameworks/mongo/mongobleed", tcp(27017)),
        p("exploits/frameworks/http2/cve_2023_44487_http2_rapid_reset", tcp(443)),
        p("exploits/frameworks/php/cve_2024_4577", http("/", &["PHP", "php"])),
        p("exploits/frameworks/php/cve_2025_51373_php_rce", http("/", &["PHP", "php"])),
        p("exploits/frameworks/exim/exim_etrn_sqli_cve_2025_26794", tcp_banner(25, "Exim")),
        p("exploits/frameworks/wsus/wsus_mitm", tcp(8530)),

        // ── Webapps ──
        p("exploits/webapps/craftcms_rce_cve_2025_47726", https("/", &["Craft CMS", "craft"])),
        p("exploits/webapps/craftcms_key_rce_cve_2025_23209", https("/", &["Craft CMS", "craft"])),
        p("exploits/webapps/langflow_rce_cve_2025_3248", http_port(7860, "/", &["Langflow"])),
        p("exploits/webapps/laravel_livewire_rce_cve_2025_47949", http("/", &["Laravel", "livewire"])),
        p("exploits/webapps/sap_netweaver_rce_cve_2025_31324", https("/", &["SAP NetWeaver", "SAP"])),
        p("exploits/webapps/misp_rce_cve_2025_27364", https("/", &["MISP"])),
        p("exploits/webapps/zimbra_sqli_auth_bypass_cve_2025_25064", https("/", &["Zimbra"])),
        p("exploits/webapps/vite_path_traversal_cve_2025_30208", http("/", &["Vite"])),
        p("exploits/webapps/nextjs_middleware_bypass_cve_2025_29927", http("/", &["Next.js", "__next"])),
        p("exploits/webapps/xwiki/cve_2025_24893_xwiki_rce", http("/", &["XWiki"])),
        p("exploits/webapps/flowise/cve_2024_31621", http_port(3000, "/", &["Flowise"])),
        p("exploits/webapps/flowise/cve_2025_59528_flowise_rce", http_port(3000, "/", &["Flowise"])),
        p("exploits/webapps/n8n/n8n_rce_cve_2025_68613", http_port(5678, "/", &["n8n"])),
        p("exploits/webapps/roundcube/roundcube_postauth_rce", http("/", &["Roundcube"])),
        p("exploits/webapps/react/react2shell", http("/", &["React", "react"])),
        p("exploits/webapps/spotube/spotube", http("/", &["Spotube"])),
        p("exploits/webapps/termix/termix_xss_cve_2026_22804", http("/", &["Termix"])),
        p("exploits/webapps/zabbix/zabbix_7_0_0_sql_injection", http("/", &["Zabbix"])),
        p("exploits/webapps/sharepoint/cve_2024_38094", https("/", &["SharePoint", "Microsoft"])),
        p("exploits/webapps/sharepoint/cve_2025_53770_sharepoint_toolpane_rce", https("/", &["SharePoint", "Microsoft"])),
        p("exploits/webapps/wordpress/vitepos_file_upload_cve_2025_13156", http("/", &["WordPress", "wp-content"])),
        p("exploits/webapps/wordpress/wp_bricks_rce_cve_2024_25600", http("/", &["WordPress", "wp-content"])),
        p("exploits/webapps/wordpress/wp_litespeed_rce_cve_2024_28000", http("/", &["WordPress", "wp-content"])),
        p("exploits/webapps/wordpress/wp_royal_elementor_rce_cve_2024_32suspended", http("/", &["WordPress", "wp-content"])),
        p("exploits/webapps/dify/cve_2025_56157_dify_default_creds", http_port(3000, "/", &["Dify"])),
        p("exploits/webapps/mcpjam/mcpjam_prompt_injection_cve_2026_10293", http("/", &["MCPJam"])),

        // ── Routers ──
        p("exploits/routers/ruijie/ruijie_auth_bypass_rce_cve_2023_34644", http("/", &["Ruijie"])),
        p("exploits/routers/ruijie/ruijie_reyee_ssrf_cve_2024_48874", http("/", &["Ruijie", "Reyee"])),
        p("exploits/routers/ruijie/ruijie_rg_ew_login_bypass_cve_2023_4415", http("/login.htm", &["Ruijie"])),
        p("exploits/routers/ruijie/ruijie_rg_ew_password_reset_cve_2023_4169", http("/login.htm", &["Ruijie"])),
        p("exploits/routers/ruijie/ruijie_rg_ew_update_version_rce_cve_2021_43164", http("/login.htm", &["Ruijie"])),
        p("exploits/routers/ruijie/ruijie_rg_uac_ci_cve_2024_4508", http("/", &["Ruijie"])),
        p("exploits/routers/ruijie/ruijie_rsr_router_ci_cve_2024_31616", http("/login.htm", &["Ruijie"])),
        p("exploits/routers/tplink/tapo_c200_vulns", http("/", &["TP-Link", "Tapo"])),
        p("exploits/routers/tplink/tplink_archer_c2_c20i_rce", http("/", &["TP-Link", "Archer"])),
        p("exploits/routers/tplink/tplink_archer_c9_password_reset", http("/", &["TP-Link", "Archer"])),
        p("exploits/routers/tplink/tplink_archer_rce_cve_2024_53375", http("/", &["TP-Link", "Archer"])),
        p("exploits/routers/tplink/tplink_ax1800_rce_cve_2024_53375", http("/", &["TP-Link"])),
        p("exploits/routers/tplink/tplink_deco_m4_rce", http("/", &["TP-Link", "Deco"])),
        p("exploits/routers/tplink/tplink_tapo_c200", https("/", &["TP-Link", "Tapo"])),
        p("exploits/routers/tplink/tplink_vigi_c385_rce_cve_2026_1457", http("/", &["TP-Link", "VIGI"])),
        p("exploits/routers/tplink/tp_link_vn020_dos", http_port(5431, "/", &["TP-Link"])),
        p("exploits/routers/tplink/tplink_wdr740n_backdoor", http("/", &["TP-Link", "WDR740"])),
        p("exploits/routers/tplink/tplink_wdr740n_path_traversal", http("/", &["TP-Link", "WDR740"])),
        p("exploits/routers/tplink/tplink_wdr842n_configure_disclosure", http("/", &["TP-Link", "WDR842"])),
        p("exploits/routers/tplink/tplink_wr740n_dos", http("/", &["TP-Link", "WR740"])),
        p("exploits/routers/dlink/dlink_dcs_930l_auth_bypass", http_port(8080, "/", &["D-Link", "DCS"])),
        p("exploits/routers/ubiquiti/ubiquiti_edgerouter_ci_cve_2023_2376", https("/", &["Ubiquiti", "EdgeOS"])),
        p("exploits/routers/zte/zte_zxv10_h201l_rce_authenticationbypass", http("/", &["ZTE", "ZXV10"])),
        p("exploits/routers/zyxel/zyxel_cpe_ci_cve_2024_40890", http("/", &["Zyxel"])),
        p("exploits/routers/netgear/netgear_r6700v3_rce_cve_2022_27646", http("/", &["NETGEAR"])),
        p("exploits/routers/tenda/tenda_cp3_rce_cve_2023_30353", http("/", &["Tenda"])),

        // ── Cameras ──
        p("exploits/cameras/reolink/reolink_rce_cve_2019_11001", http("/", &["Reolink"])),
        p("exploits/cameras/abus/abussecurity_camera_cve202326609variant1", http("/", &["ABUS"])),
        p("exploits/cameras/avtech/cve_2024_7029_avtech_camera", http("/", &["AVTECH"])),
        p("exploits/cameras/hikvision/hikvision_rce_cve_2021_36260", http("/", &["Hikvision", "DNVRS-Webs"])),
        p("exploits/cameras/acti/acm_5611_rce", http("/", &["ACTi"])),
        p("exploits/cameras/uniview/uniview_nvr_pwd_disclosure", http("/", &["Uniview", "NVR"])),

        // ── DoS (port-open check only) ──
        p("exploits/dos/http_flood", tcp(80)),
        p("exploits/dos/slowloris", tcp(80)),
        p("exploits/dos/rudy", tcp(80)),
        p("exploits/dos/connection_exhaustion_flood", tcp(80)),
        p("exploits/dos/tcp_connection_flood", tcp(80)),
        p("exploits/dos/udp_flood", ProbeType::Skip),
        p("exploits/dos/icmp_flood", ProbeType::Skip),
        p("exploits/dos/syn_ack_flood", ProbeType::Skip),
        p("exploits/dos/null_syn_exhaustion", ProbeType::Skip),
        p("exploits/dos/dns_amplification", ProbeType::Skip),
        p("exploits/dos/ntp_amplification", ProbeType::Skip),
        p("exploits/dos/ssdp_amplification", ProbeType::Skip),
        p("exploits/dos/memcached_amplification", ProbeType::Skip),

        // ── IPMI ──
        p("exploits/ipmi/ipmi_enum_exploit", tcp(623)),

        // ── Windows ──
        p("exploits/windows/windows_dwm_cve_2026_20805", ProbeType::Skip),

        // ── Payload generators (no target) ──
        p("exploits/payloadgens/batgen", ProbeType::Skip),
        p("exploits/payloadgens/lnkgen", ProbeType::Skip),
        p("exploits/payloadgens/narutto_dropper", ProbeType::Skip),
        p("exploits/payloadgens/payload_encoder", ProbeType::Skip),
        p("exploits/payloadgens/polymorph_dropper", ProbeType::Skip),

        // ── Honeytrap / Snare / Cowrie / Dionaea / SafeLine ──
        p("exploits/honeytrap/ftp_panic", tcp_banner(21, "FTP")),
        p("exploits/honeytrap/docker_panic", tcp(2375)),
        p("exploits/snare/cookie_dos", tcp(80)),
        p("exploits/snare/tanner_version_mitm", tcp(8090)),
        p("exploits/cowrie/llm_prompt_injection", tcp_banner(22, "SSH")),
        p("exploits/cowrie/ansi_log_injection", tcp_banner(22, "SSH")),
        p("exploits/dionaea/mysql_sqli", tcp(3306)),
        p("exploits/dionaea/mssql_dos", tcp(1433)),
        p("exploits/dionaea/mqtt_underflow", tcp(1883)),
        p("exploits/dionaea/tftp_crash", tcp(69)),

        // ── VNC ──
        p("exploits/vnc/libvnc_checkrect_overflow", tcp(5900)),
        p("exploits/vnc/libvnc_tight_filtergradient", tcp(5900)),
        p("exploits/vnc/libvnc_ultrazip", tcp(5900)),
        p("exploits/vnc/libvnc_websocket_overflow", tcp(5900)),
        p("exploits/vnc/libvnc_zrle_tile", tcp(5900)),
        p("exploits/vnc/tigervnc_rre_overflow", tcp(5900)),
        p("exploits/vnc/tigervnc_timing_oracle", tcp(5900)),
        p("exploits/vnc/tightvnc_decompression_bomb", tcp(5900)),
        p("exploits/vnc/tightvnc_des_hardcoded_key", tcp(5900)),
        p("exploits/vnc/tightvnc_ft_path_traversal", tcp(5900)),
        p("exploits/vnc/tightvnc_predictable_challenge", tcp(5900)),
        p("exploits/vnc/tightvnc_rect_overflow", tcp(5900)),
        p("exploits/vnc/x11vnc_dns_injection", tcp(5900)),
        p("exploits/vnc/x11vnc_env_injection", tcp(5900)),
        p("exploits/vnc/x11vnc_unixpw_inject", tcp(5900)),

        // ── SafeLine ──
        p("exploits/safeline/cookie_attributes", http_port(9443, "/", &["SafeLine", "safeline"])),
        p("exploits/safeline/no_auth_probe", http_port(9443, "/", &["SafeLine", "safeline"])),
        p("exploits/safeline/session_secret_entropy", http_port(9443, "/", &["SafeLine", "safeline"])),
        p("exploits/safeline/unauth_writes", http_port(9443, "/", &["SafeLine", "safeline"])),
        p("exploits/safeline/nginx_injection", http_port(9443, "/", &["SafeLine", "safeline"])),
        p("exploits/safeline/pre_auth_tfa", http_port(9443, "/", &["SafeLine", "safeline"])),
    ]
}

// ─── Builder helpers ───────────────────────────────────────────────────────

fn p(module: &'static str, probe: ProbeType) -> Probe {
    Probe { module, probe }
}

fn http(path: &'static str, markers: &'static [&'static str]) -> ProbeType {
    ProbeType::Http { scheme: "http", port: 80, path, markers }
}

fn https(path: &'static str, markers: &'static [&'static str]) -> ProbeType {
    ProbeType::Http { scheme: "https", port: 443, path, markers }
}

fn http_port(port: u16, path: &'static str, markers: &'static [&'static str]) -> ProbeType {
    ProbeType::Http { scheme: "http", port, path, markers }
}

fn tcp(port: u16) -> ProbeType {
    ProbeType::Tcp { port }
}

fn tcp_banner(port: u16, marker: &'static str) -> ProbeType {
    ProbeType::TcpBanner { port, marker }
}

fn print_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln_block!(
        format!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan()),
        format!("{}", "║              Vulnerability Checker                         ║".cyan()),
        format!("{}", "║   Fingerprints target against all exploit module signatures ║".cyan()),
        format!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan())
    );
}
