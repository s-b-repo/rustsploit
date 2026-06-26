# Getting Started

Rustsploit is a modular offensive tooling framework for embedded targets, written in Rust and inspired by RouterSploit/Metasploit. It ships an interactive shell, a CLI runner, a WebSocket API server with post-quantum encryption, and an ever-growing library of exploits, scanners, and credential modules.

---

## Requirements

### System Dependencies

**Debian / Ubuntu / Kali:**
```bash
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev libdbus-1-dev cmake clang lld mold
```

> `clang`, `lld`, and `mold` are optional but strongly recommended — the repo's `.cargo/config.toml` is preconfigured to use a fast linker (see [Faster Builds](#faster-builds) below).

**Arch Linux:**
```bash
sudo pacman -S base-devel pkgconf openssl dbus cmake
```

**Gentoo:**
```bash
sudo emerge dev-libs/openssl dev-util/pkgconf sys-apps/dbus dev-build/cmake
```

**Fedora / RHEL:**
```bash
sudo dnf install gcc make pkgconf-pkg-config openssl-devel dbus-devel cmake
```

### Rust & Cargo

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

> Rust 1.85+ is required (edition 2024). Run `rustup update` to stay current.

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

## Faster Builds

The repository ships with build-performance tuning already applied:

- **`.cargo/config.toml`** — uses `clang` + `lld` as the linker on Linux and enables the sparse crates.io registry protocol.
- **`Cargo.toml` `[profile.dev]`** — `debug = "line-tables-only"` and `codegen-units = 256` for fast incremental builds with usable backtraces.
- **`[profile.dev.package."*"]`** — dependencies are still compiled at `opt-level = 2` so runtime stays fast.
- **`[profile.fast-release]`** — `cargo build --profile fast-release` for release-like binaries with thin LTO and parallel codegen (much faster than `--release`).

### Recommended optional tooling

**1. Install `mold` (fastest linker on Linux).** It's already in the apt install line above. To switch from `lld` to `mold`, edit `.cargo/config.toml` and replace `-fuse-ld=lld` with `-fuse-ld=mold`.

**2. `cargo check` instead of `cargo build`** during iteration — skips codegen entirely:
```bash
cargo check
# or auto-rerun on save:
cargo install cargo-watch
cargo watch -x check
```

**3. `sccache` for cross-project caching:**
```bash
cargo install sccache
export RUSTC_WRAPPER=sccache   # add to ~/.zshrc or ~/.bashrc
```

**4. Share a target directory across projects** to reuse compiled deps:
```bash
export CARGO_TARGET_DIR="$HOME/.cargo-target"
```

### Reducing memory / CPU usage

If `cargo build` thrashes RAM or pegs all cores, cap parallelism:
```bash
cargo build -j 4                   # limit parallel compile jobs
CARGO_BUILD_JOBS=4 cargo build     # or via env
```
A good rule of thumb: `-j $(($(nproc) / 2))` on memory-constrained machines. Each rustc job can use 1–2 GiB on heavy crates.

### Quick reference

| Goal | Command |
|------|---------|
| Type-check only (fastest) | `cargo check` |
| Dev build | `cargo build` |
| Release-like, fast to compile | `cargo build --profile fast-release` |
| Fully optimized release | `cargo build --release` |
| Limit RAM/CPU | `cargo build -j 4` |

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
