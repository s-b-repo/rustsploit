#!/usr/bin/env python3
"""
Interactive generator for RustSploit Docker-Compose stack.
Produces:
  docker-compose.rustsploit.yml (with embedded Dockerfile)
  .env.rustsploit-docker
and prints the command to bring the stack up.

This variant includes runtime fixes to avoid permission-denied on /app/data
and ensures the container starts as root briefly to fix ownership, then
executes the rustsploit binary as the less-privileged `rustsploit` user.
"""
import secrets
import os
import stat
import socket
import ipaddress
import subprocess
import pwd
from pathlib import Path

# Fix: Use parent.parent since script is in scripts/ directory
repo = Path(__file__).resolve().parent.parent
if not (repo / "Cargo.toml").exists():
    print("[-] Error: Run this script from the RustSploit repository root.")
    print(f"    Expected Cargo.toml at: {repo / 'Cargo.toml'}")
    exit(1)

# ---------- Helper functions ----------
def ask(prompt, default=None, validator=None):
    """Interactive prompt with validation."""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        val = input(f"{prompt}{suffix}: ").strip()
        if not val and default is not None:
            val = default
        if not val:
            print("Value cannot be empty.")
            continue
        if validator:
            try:
                validator(val)
            except ValueError as e:
                print(f"Invalid input: {e}")
                continue
        return val


def ask_yes_no(prompt, default=True):
    """Yes/No prompt."""
    hint = "Y/n" if default else "y/N"
    while True:
        val = input(f"{prompt} ({hint}): ").strip().lower()
        if not val:
            return default
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


def validate_host(host):
    """Validate host/IP address."""
    host = host.strip()
    if not host:
        raise ValueError("Host cannot be empty")
    # Allow localhost
    if host == "localhost":
        return
    # Try to parse as IP
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Not a valid IP, check if it's a valid hostname
        if len(host) > 253:
            raise ValueError("Hostname too long (max 253 chars)")
        if any(c.isspace() for c in host):
            raise ValueError("Hostname cannot contain whitespace")


def validate_port(port_str):
    """Validate port number."""
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError("Port must be a number")
        raise


def detect_private_ip():
    """Try to detect private IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))
            return sock.getsockname()[0]
    except OSError:
        return None

# ---------- Interactive prompts ----------
print("\n[+] RustSploit Docker Setup\n")

# Host selection
print("Select bind address:")
print("  [1] 127.0.0.1 (localhost only)")
print("  [2] 0.0.0.0 (all interfaces)")
print("  [3] Private LAN IP (auto-detect)")
print("  [4] Custom IP/hostname")

choice = ask("Choice", "2")
if choice == "1":
    host = "127.0.0.1"
elif choice == "2":
    host = "0.0.0.0"
elif choice == "3":
    detected = detect_private_ip()
    if detected:
        print(f"[+] Detected private IP: {detected}")
        use_detected = ask_yes_no("Use detected IP?", True)
        host = detected if use_detected else ask("Enter IP/hostname", validator=validate_host)
    else:
        print("[-] Could not auto-detect private IP")
        host = ask("Enter IP/hostname", validator=validate_host)
else:
    host = ask("Enter IP/hostname", validator=validate_host)

# Port
# Default changed to 9000 as this is a common API port and matches user's prior usage
port_str = ask("Host port to expose", "9000", validator=validate_port)
port = int(port_str)

# API Key
print("\n[+] API Key Configuration")
generate_key = ask_yes_no("Generate random API key?", True)
if generate_key:
    api_key = secrets.token_urlsafe(32)
    print(f"[+] Generated API key: {api_key}")
else:
    api_key = ask("Enter API key (ASCII, max 128 chars)", validator=lambda k: None if (len(k) <= 128 and all(32 <= ord(c) <= 126 for c in k)) else ValueError("API key must be printable ASCII, max 128 chars"))

# Hardening
print("\n[+] Security Hardening")
harden = ask_yes_no("Enable API hardening (auto-rotate key on suspicious activity)?", False)
ip_limit = 10
if harden:
    ip_limit_str = ask("Max unique IPs before rotation", "10", validator=lambda v: validate_port(v) if v else None)
    ip_limit = int(ip_limit_str)

# ---------- File generation ----------
env_file = ".env.rustsploit-docker"
compose_file = "docker-compose.rustsploit.yml"

env_path = repo / env_file
compose_path = repo / compose_file

# Check for existing .env file
if env_path.exists():
    print(f"\n[!] Warning: {env_path.relative_to(repo)} already exists.")
    if not ask_yes_no("Overwrite .env file?", False):
        print("[-] Aborted.")
        exit(0)

# Check for existing docker-compose file
if compose_path.exists():
    print(f"\n[!] Warning: {compose_path.relative_to(repo)} already exists.")
    if not ask_yes_no("Overwrite docker-compose file?", False):
        print("[-] Aborted.")
        exit(0)

# ---- .env ----
container_interface = f"0.0.0.0:{port}"
env_content = f"""RUSTSPLOIT_INTERFACE={container_interface}
RUSTSPLOIT_API_KEY={api_key}
RUSTSPLOIT_HARDEN={"true" if harden else "false"}
RUSTSPLOIT_IP_LIMIT={ip_limit}
"""
env_path.write_text(env_content)
# Set permissions: owner read/write only (0600) to keep API key private while still readable by docker-compose
os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)
print(f"\n[+] Generated: {env_path}")

# Fix ownership if file was created with sudo (owned by root)
if env_path.stat().st_uid == 0:
    print("[!] File was created as root. Fixing ownership...")
    try:
        # Get the actual user (SUDO_USER if running via sudo, otherwise current user)
        user = os.environ.get('SUDO_USER') or os.environ.get('USER')
        if not user:
            user = pwd.getpwuid(os.getuid()).pw_name
        
        # If we're running as root (via sudo), we can chown directly
        if os.geteuid() == 0:
            user_info = pwd.getpwnam(user)
            os.chown(env_path, user_info.pw_uid, user_info.pw_gid)
            print(f"[+] Ownership fixed: {user}:{user}")
        else:
            # Not root, need to use sudo
            subprocess.run(['sudo', 'chown', f'{user}:{user}', str(env_path)], check=True)
            print(f"[+] Ownership fixed: {user}:{user}")
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError) as e:
        print(f"[!] Warning: Could not automatically fix ownership: {e}")
        print(f"    Please run manually: sudo chown $USER:$USER {env_path}")

# ---- docker-compose.yml with embedded Dockerfile ----
# Note: The serve stage runs the entrypoint as root so it can fix ownership of
# /app/data at container startup, then it drops privileges and executes the
# rustsploit binary as the less-privileged `rustsploit` user via runuser.

dockerfile_content = """FROM rust:1.83-slim AS builder
WORKDIR /workspace
ENV CARGO_TERM_COLOR=always

RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
        build-essential \\
        pkg-config \\
        libssl-dev \\
        libclang-dev \\
        libpcap-dev \\
        libsqlite3-dev \\
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY Cargo.lock* ./

COPY . .
RUN cargo build --release --bin rustsploit

FROM debian:bookworm-slim AS serve
RUN apt-get update \\
    && apt-get install -y --no-install-recommends ca-certificates util-linux \\
    && rm -rf /var/lib/apt/lists/*

# create non-root user
RUN useradd --system --home /app --shell /usr/sbin/nologin rustsploit
WORKDIR /app

# create data dir (image-level), but runtime entrypoint will chown the volume target
RUN mkdir -p /app/data && chown rustsploit:rustsploit /app/data

COPY --from=builder /workspace/target/release/rustsploit /usr/local/bin/rustsploit

# entrypoint runs as root (default) so it can fix ownership of mounted volumes
RUN echo '#!/bin/sh' > /entrypoint.sh && \\
    echo 'set -e' >> /entrypoint.sh && \\
    echo 'ARGS="--api --api-key \"${RUSTSPLOIT_API_KEY}\" --interface \"${RUSTSPLOIT_INTERFACE}\""' >> /entrypoint.sh && \\
    echo 'if [ "\"$RUSTSPLOIT_HARDEN\"" = "\"true\"" ]; then' >> /entrypoint.sh && \\
    echo '  ARGS="$ARGS --harden"' >> /entrypoint.sh && \\
    echo '  if [ -n "\"$RUSTSPLOIT_IP_LIMIT\"" ]; then' >> /entrypoint.sh && \\
    echo '    ARGS="$ARGS --ip-limit $RUSTSPLOIT_IP_LIMIT"' >> /entrypoint.sh && \\
    echo '  fi' >> /entrypoint.sh && \\
    echo 'fi' >> /entrypoint.sh && \\
    # ensure data dir exists and is owned by rustsploit so that non-root process can write
    echo 'mkdir -p /app/data' >> /entrypoint.sh && \\
    echo 'mkdir -p /app/data/logs || true' >> /entrypoint.sh && \\
    echo 'chown -R rustsploit:rustsploit /app/data || true' >> /entrypoint.sh && \\
    echo 'LOG_FILE=/app/data/logs/rustsploit_api.log' >> /entrypoint.sh && \\
    echo 'touch "$LOG_FILE" || true' >> /entrypoint.sh && \\
    echo 'chown rustsploit:rustsploit "$LOG_FILE" || true' >> /entrypoint.sh && \\
    echo 'ln -sf "$LOG_FILE" /app/rustsploit_api.log || true' >> /entrypoint.sh && \\
    # finally, execute rustsploit as the rustsploit user using runuser
    echo 'exec runuser -u rustsploit -- /usr/local/bin/rustsploit $ARGS' >> /entrypoint.sh && \\
    chmod +x /entrypoint.sh && \\
    chown root:root /entrypoint.sh && \\
    chown root:root /usr/local/bin/rustsploit

# keep default user root so entrypoint can perform ownership fixes; runtime drops to rustsploit
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
"""

# Create Dockerfile in repo root (hardcoded in script, not in docker/ folder)
dockerfile_path = repo / "Dockerfile.rustsploit"
dockerfile_path.write_text(dockerfile_content)
print(f"[+] Generated: {dockerfile_path}")

# Generate docker-compose.yml
compose_content = f"""# Generated by {Path(__file__).name}
services:
  rustsploit-api:
    container_name: rustsploit-api
    build:
      context: .
      dockerfile: Dockerfile.rustsploit
      target: serve
    restart: unless-stopped
    env_file:
      - {env_file}
    ports:
      - "{host}:{port}:{port}"
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - rustsploit-data:/app/data

volumes:
  rustsploit-data:
    name: rustsploit-data
"""

compose_path.write_text(compose_content)
print(f"[+] Generated: {compose_path}")

print("\n[+] Setup complete!")
print("\n[+] Generated files:")
print(f"    - {env_path.relative_to(repo)}")
print(f"    - {compose_path.relative_to(repo)}")
print(f"    - {dockerfile_path.relative_to(repo)}")
print(f"\n[!] Note: Run docker compose commands from the repository root:")
print(f"    cd {repo}")
print("\n[+] To start the stack, run:")
print(f"    cd {repo} && docker compose -f {compose_file} up -d --build")
print(f"    # OR from any directory:")
print(f"    docker compose -f {compose_path} up -d --build")
print("\n[+] To view logs:")
print(f"    cd {repo} && docker compose -f {compose_file} logs -f")
print(f"    # OR from any directory:")
print(f"    docker compose -f {compose_path} logs -f")
print("\n[+] To stop the stack:")
print(f"    cd {repo} && docker compose -f {compose_file} down")
print(f"    # OR from any directory:")
print(f"    docker compose -f {compose_path} down")
