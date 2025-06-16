# Rustsploit 🛠️

A Rust-based modular exploitation framework inspired by RouterSploit. This tool allows for running modules such as exploits, scanners, and credential checkers against embedded devices like routers.

![Screenshot](https://github.com/s-b-repo/rustsploit/raw/main/preview.png)

📚 **Developer Documentation**:  
→ [Full Dev Guide (modules, proxy logic, shell flow, dispatch system)](https://github.com/s-b-repo/rustsploit/blob/main/docs/readme.md)

---
### Goals & To Do lists

Convert exploits and add modules

# completed
```

added stalkroute a traceroute with firewall evasion requires root 
added malware dropper narruto dropper
added refactored and fixed and improve alot of modules
added added new version of payloadgen
added smtp bruteforcer
added pop3 bruteforcer
added zte zte_zxv10_h201l_rce_authenticationbypass
added ivanti ivanti_connect_secure_stack_based_buffer_overflow
added apache_tomcat cve_2025_24813_apache_tomcat_rce
added apache_tomcat catkiller_cve_2025_31650
added palto_alto CVE-2025-0108. auth bypass
added acm_5611_rce
added zabbix_7_0_0_sql_injection
added cve_2024_7029_avtech_camera
added pachev_ftp_path_traversal_1_0
added ipv6 support for rstp rdp and ssh cant find any ipv6 address i cant test on so untested
added ftps support
added ipv6 support to ftp anon and brute
added rdp ipv6 support unable to find rpd ipv6 device to test on with shodan
added exploit openssh server race condition 9.8.p1 |Server Destruction fork |
bomb Persistence create SSH user | Remote Root Shell

added spotube exploit zero day exploit as of 24 april reported to spotube
added exploit tplink_wr740n Buffer Overflow 'DOS'
added exploit tp_link_vn020  Denial Of Service (DOS) 
added exploit abussecurity_camera_cve 2023 26609 variant2 RCE and SSH Root Access adds persistant account
added exploit abussecurity_camera_cve 2023 26609 variant1 LFI, RCE and SSH Root Access
added exploit uniview_nvr_pwd_disclosure password disclore 
updated docs again and readme
rework command system to automaticly detect new modules
added uniview_nvr_pwd_disclosure  
added ssdp_msearch  
added hearbleed  info leak from server saved to a bin file
added port scanner
added ping_sweep network scanner
added http_title_scanner
added log4j_scanner
added heartbleed_scanner
added find command
updated docs
created docs
added wordlist for camera paths  
added acti camera module  
created bat payload generator for malware  
added proxy support https/http socks4/socks5  
telnet brute forcing module  
ssh brute forcing module  
ftp anonymous login module  
ftp brute forcing module  
added rtsp_bruteforce module  
dynamic modules listing and colored listing  
```

---
```
## 🚀 Building & Running
## 📦🛠️  requirements 
`
sudo apt update
sudo apt install freerdp2-x11  

for rdp bruteforce modudle


```
```
### 📦 Clone the Repository

```
git clone https://github.com/s-b-repo/rustsploit.git
cd rustsploit
```

### 🛠️ Build the Project

```
cargo build
```

To build and run:
```
cargo run
```

To install:
```
cargo install
```

---

### 🖥️ Run in Interactive Shell Mode

Launch the interactive RSF shell:

```
cargo run
```

Once inside the shell:

```text
rsf> help
rsf> modules
rsf> show_proxies
rsf> proxy_on / proxy_off
rsf> proxy_load proxies.txt
rsf> find
rsf> use exploits/heartbleed
rsf> set target 192.168.1.1
rsf> run
```

🌀 Supports retrying proxies until one works (if proxy_on is enabled).

---

### 🔧 Run in CLI Mode

#### ▶ Exploit
```
cargo run -- --command exploit --module heartbleed --target 192.168.1.1
```

#### 🧪 Scanner
```
cargo run -- --command scanner --module port_scanner --target 192.168.1.1
```

#### 🔐 Credentials
```
cargo run -- --command creds --module ssh_brute --target 192.168.1.1
```

---

## 🌐 Proxy Retry Logic (Shell Mode)

- If proxies are loaded and `proxy_on` is active:
  - Random proxy is used from list
  - On failure, tries another until successful
  - If all fail, it runs once **without proxy**

---

## 📂 Module System

Modules are automatically detected using `build.rs` and registered as:
- Short: `port_scanner`
- Full: `scanners/port_scanner`

Each module must define:
```
pub async fn run(target: &str) -> Result<()>
```

Optional:
```
pub async fn run_interactive(target: &str) -> Result<()>
```

---

## 🧼 Shell State

The shell keeps:
- Current module
- Current target
- Proxy list + state

No session state is saved — everything resets on restart.

---

## 💡 Want to Add a Module?

See the full [Developer Guide](https://github.com/s-b-repo/rustsploit/blob/main/docs/readme.md)  
Includes:
- ✅ How to write modules
- 🧠 Auto-dispatch system explained
- 📦 Module placement
- 🌐 Proxy logic details
- 🔍 Scanner vs Exploit vs Credential paths

---

## 👥 Contributors

- **Main Developer**: me.
- **Language**: 100% Rust.
- **Inspired by**: RouterSploit, Metasploit, pwntools

## 👥 Credits

- **wordlists*: seclists & me


---
