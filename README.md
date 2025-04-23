# Rustsploit 🛠️

A Rust-based modular exploitation framework inspired by RouterSploit. This tool allows for running modules such as exploits, scanners, and credential checkers against embedded devices like routers.

![Screenshot](https://github.com/s-b-repo/r-routersploit/raw/main/lat.png)

📚 **Developer Documentation**:  
→ [Full Dev Guide (modules, proxy logic, shell flow, dispatch system)](https://github.com/s-b-repo/r-routersploit/blob/main/docs/doc.md)

---
    println!(" 1.
    println!(" 2. 
    println!(" 3. 
### Goals & To Do lists

Convert exploits and add modules

# completed
```
added exploit openssh server race condition 9.8.p1 |Server Destruction fork |
bomb Persistence create SSH user | Remote Root Shell

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

## 🚀 Building & Running

### 📦 Clone the Repository

```
git clone https://github.com/s-b-repo/r-routersploit.git
cd r-routersploit
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
```rust
pub async fn run(target: &str) -> Result<()>
```

Optional:
```rust
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

See the full [Developer Guide](https://github.com/s-b-repo/r-routersploit/blob/main/docs/doc.md)  
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
```

---
