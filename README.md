
---

# R-RouterSploit 🛠️

A Rust-based modular exploitation framework inspired by RouterSploit. This tool allows for running modules such as exploits, scanners, and credential checkers against embedded devices like routers.

![Screenshot](https://github.com/s-b-repo/r-routersploit/raw/main/Screenshot_20250416_111212.png)

---

### Goals & To Do lists

docs

convert exploits and add modules

add wordlists and brute forcing modules

# completed

telnet_bruteforce

ftp anonymous login module

ftp brute forcing  module

dynamic modules listing and colored listing


## 🚀 Building & Running

### 📦 Clone the Repository

```
git clone https://github.com/s-b-repo/r-routersploit.git
cd r-routersploit
```

### 🛠️ Build the Project

```bash
cargo build
```

### 🔧 Run in CLI Mode

You can run specific modules via CLI using subcommands:

#### ▶ Exploit

```
cargo run -- --command exploit --module sample_exploit --target 192.168.1.1
```

#### 🧪 Scanner

```
cargo run -- --command scanner --module sample_scanner --target 192.168.1.1
```

#### 🔐 Credentials

```
cargo run -- --command creds --module sample_cred_check --target 192.168.1.1
```

### 🖥️ Run in Interactive Shell Mode

Launch the interactive RSF shell:

```
cargo run
```

Once inside the shell, you can explore and execute modules:

```shell
rsf> help
rsf> modules
rsf> use exploits/sample_exploit
rsf> set target 192.168.1.1
rsf> run
```

---

