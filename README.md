
---

# Rustsploit 🛠️

A Rust-based modular exploitation framework inspired by RouterSploit. This tool allows for running modules such as exploits, scanners, and credential checkers against embedded devices like routers.

![Screenshot](https://github.com/s-b-repo/r-routersploit/raw/main/Screenshot_20250416_111212.png)

---

### Goals & To Do lists


convert exploits and add modules


# completed
```
created docs

added acti camera module

created bat payload generator for malware

added proxy support https/http socks4/socks5

telnet brute forcing  module
 
ssh brute forcing  module

ftp anonymous login module

ftp brute forcing  module

added rtsp_bruteforce module

dynamic modules listing and colored listing

```

## 🚀 Building & Running

### 📦 Clone the Repository

```
git clone https://github.com/s-b-repo/r-routersploit.git
cd r-routersploit
```

### 🛠️ Build the Project

```
cargo build

or if you just want to run the tool and see after builing run this command in folder

cargo run
```
if you want it installed run
```
cargo install
```



### 🖥️ Run in Interactive Shell Mode

Launch the interactive RSF shell:

```

rustsploit

cargo run


```

Once inside the shell, you can explore and execute modules:

```
rsf> help
rsf> modules
rsf> use exploits/sample_exploit
rsf> set target 192.168.1.1
rsf> run
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
---

