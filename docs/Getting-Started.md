# Getting Started

Rustsploit is a modular offensive tooling framework for embedded targets, written in Rust and inspired by RouterSploit/Metasploit. It ships an interactive shell, a CLI runner, a REST API server, and an ever-growing library of exploits, scanners, and credential modules.

---

## Requirements

### System Dependencies

**Debian / Ubuntu / Kali:**
```bash
sudo apt update
sudo apt install pkg-config libssl-dev rustc libdbus-1-dev 
```

**Arch Linux:**
```bash
sudo pacman -S pkgconf openssl freerdp rustc
```

**Gentoo:**
```bash
sudo emerge dev-libs/openssl dev-util/pkgconf net-misc/freerdp
```

**Fedora / RHEL:**
```bash
sudo dnf install pkgconf-pkg-config openssl-devel freerdp rustc
```

### Rust & Cargo

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

> The minimum supported Rust version tracks stable. Run `rustup update` to stay current.

---

## Clone & Build

```bash
git clone https://github.com/s-b-repo/rustsploit.git
cd rustsploit
cargo build
```

For a release-optimized binary:
```bash
cargo build --release
# Binary written to target/release/rustsploit
```

---

## Run

### Interactive Shell
```bash
cargo run
```

### CLI (non-interactive)
```bash
cargo run -- -m exploits/heartbleed -t 192.168.1.1
```

See [CLI Reference](CLI-Reference.md) for all flags.

### API Server
```bash
cargo run -- --api
```

This starts the PQ-encrypted API server on port 8080. On first run it generates a host key pair at `~/.rustsploit/pq_host_key` and prints its fingerprint. Clients must be listed in `~/.rustsploit/pq_authorized_keys` to connect. No TLS or API keys — authentication uses SSH-style post-quantum identity keys. See [API Server](API-Server.md) and [API Usage Examples](API-Usage-Examples.md) for details.

---

## Docker Deployment

Rustsploit ships a provisioning script that builds and launches the API inside Docker.

### Requirements

- Docker Engine 24+ (or Docker Desktop)
- Docker Compose plugin (`docker compose`) or legacy `docker-compose`
- Python 3.8+

### Interactive Setup

```bash
python3 scripts/setup_docker.py
```

The helper will:
1. Confirm you are in the repository root (`Cargo.toml` present).
2. Ask how the API should bind (`127.0.0.1`, `0.0.0.0`, detected LAN IP, or custom `host:port`).
3. Generate or configure PQ identity keys for the API server.
4. Toggle hardening mode and tune the IP limit.
5. Generate:
   - `docker/Dockerfile.api`
   - `docker/entrypoint.sh`
   - `.env.rustsploit-docker`
   - `docker-compose.rustsploit.yml`
6. Optionally run `docker compose up -d --build` with BuildKit enabled.

Existing files are never overwritten without confirmation.

### Non-Interactive / CI

```bash
python3 scripts/setup_docker.py \
  --bind 0.0.0.0:8443 \
  --generate-key \
  --enable-hardening \
  # PQ identity keys auto-generated on first run
  --skip-up \
  --force \
  --non-interactive
```

To start the stack later:
```bash
docker compose -f docker-compose.rustsploit.yml up -d --build
```

---

## Privacy / VPN

The built-in proxy system has been removed in favor of system-level VPN solutions.

We recommend **[Mullvad VPN](https://mullvad.net)**:
- No registration — account numbers generated without email or personal data
- Proven no-logs policy with audited infrastructure
- WireGuard support for high-performance, low-latency tunneling
- Excellent Linux CLI for headless setups

Connect the VPN on your host before running Rustsploit and all traffic routes through the tunnel automatically.

---

> ⚠️ For authorized security testing and research only. Obtain explicit written permission before targeting any system you do not own.
