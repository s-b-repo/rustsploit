#!/usr/bin/env python3
"""
Interactive helper for provisioning the RustSploit API inside Docker.

This script will:
  • Ask you how the API should bind (127.0.0.1, 0.0.0.0, LAN IP, custom).
  • Let you supply or randomly generate the API key.
  • Optionally toggle API hardening and tweak limits.
  • Generate a dedicated Dockerfile, entrypoint script, docker-compose file, and env file.
  • Run `docker compose up -d --build` to launch the stack.

The workflow mirrors vxcontrol/pentagi’s Dockerfile stages (build + serve),
but tailored for RustSploit’s API binary.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO_MARKER = "Cargo.toml"
DEFAULT_PORT = 8080
MAX_PROXY_ENTRIES = 10_000


def ensure_repo_root() -> Path:
    here = Path(__file__).resolve()
    repo_root = here.parent.parent
    if not (repo_root / REPO_MARKER).exists():
        print(f"[!] Could not locate {REPO_MARKER} next to script – please run from the repo checkout.")
        sys.exit(1)
    return repo_root


def which_compose() -> Sequence[str]:
    candidates = [
        shutil.which("docker-compose"),
        None,  # placeholder for docker compose
    ]
    for cmd in candidates:
        if cmd:
            return [cmd]
    docker = shutil.which("docker")
    if docker:
        try:
            subprocess.run([docker, "compose", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return [docker, "compose"]
        except subprocess.CalledProcessError:
            pass
    print("[!] Neither docker-compose nor docker compose found in PATH.")
    sys.exit(1)


def detect_private_ip() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))
            ip = s.getsockname()[0]
            ipaddress.ip_address(ip)  # validate
            return ip
    except OSError:
        return None


def prompt_choice(prompt: str, options: List[Tuple[str, str]]) -> str:
    print(prompt)
    for idx, (label, desc) in enumerate(options, start=1):
        print(f"  [{idx}] {label:15} {desc}")
    while True:
        selection = input("Select option number: ").strip()
        if not selection.isdigit():
            print("Please enter a numeric choice.")
            continue
        index = int(selection) - 1
        if 0 <= index < len(options):
            return options[index][0]
        print("Choice out of range.")


def prompt_str(prompt: str, default: Optional[str] = None, allow_empty: bool = False) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value or allow_empty:
            return value
        print("Value cannot be empty.")


def prompt_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{prompt} ({hint}): ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please answer with 'y' or 'n'.")


def resolve_bind_address() -> Tuple[str, str]:
    private_ip = detect_private_ip()
    private_label = private_ip if private_ip else "auto-detect failed"
    options = [
        ("127.0.0.1", "Localhost only (loopback)"),
        ("0.0.0.0", "All interfaces (public)"),
        ("private", f"Private LAN ({private_label})"),
        ("custom", "Specify a custom IP/host"),
    ]
    choice = prompt_choice("Select bind address for the API server:", options)
    if choice == "private":
        if private_ip:
            print(f"Using detected private address: {private_ip}")
            return private_ip, f"{private_ip}:{DEFAULT_PORT}"
        print("Could not auto-detect private IP. Please enter manually.")
        choice = "custom"
    if choice == "custom":
        while True:
            custom = prompt_str("Enter IP/host (optionally host:port)", allow_empty=False)
            if ":" in custom:
                host, port = custom.rsplit(":", 1)
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    if host not in {"localhost", "0.0.0.0"}:
                        print("Warning: host is not a valid IP – continuing anyway.")
                if not port.isdigit():
                    print("Port must be numeric.")
                    continue
                return host, custom
            try:
                ipaddress.ip_address(custom)
            except ValueError:
                if custom not in {"localhost"}:
                    print("Warning: input is not a recognized IP – continuing anyway.")
            return custom, f"{custom}:{DEFAULT_PORT}"
    # default choices (no port specified)
    return choice, f"{choice}:{DEFAULT_PORT}"


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def prompt_api_settings() -> Dict[str, str]:
    use_custom = prompt_yes_no("Would you like to set a custom API key?", default=True)
    if use_custom:
        while True:
            key = prompt_str("Enter API key (ASCII, 128 chars max)", allow_empty=False)
            if len(key) > 128:
                print("API key too long.")
                continue
            if not all(ord(c) < 128 and not c.isspace() for c in key):
                print("API key must be printable ASCII without spaces.")
                continue
            api_key = key
            break
    else:
        api_key = generate_api_key()
        print(f"Generated API key: {api_key}")

    harden = prompt_yes_no("Enable API hardening (auto-rotate key on suspicious activity)?", default=False)
    ip_limit = "10"
    if harden:
        while True:
            candidate = prompt_str("Max unique IPs before rotation", default="10", allow_empty=False)
            if candidate.isdigit() and int(candidate) > 0:
                ip_limit = candidate
                break
            print("Please enter a positive integer.")
    return {
        "RUSTSPLOIT_API_KEY": api_key,
        "RUSTSPLOIT_HARDEN": "true" if harden else "false",
        "RUSTSPLOIT_IP_LIMIT": ip_limit,
    }


def confirm_overwrite(path: Path) -> None:
    if path.exists():
        overwrite = prompt_yes_no(f"{path} exists. Overwrite?", default=False)
        if not overwrite:
            print("Aborting to avoid overwriting existing files.")
            sys.exit(0)


def write_file(path: Path, content: str, make_executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if make_executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def render_dockerfile() -> str:
    return """# Generated by scripts/setup_docker.py
# Build stage: compile RustSploit with release optimizations
FROM rust:1.81-slim AS builder
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

# Pre-fetch dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo fetch
RUN rm -rf src

# Copy full source and build
COPY . .
RUN cargo build --release --bin rustsploit

# Runtime stage: minimal image with the compiled binary
FROM debian:bookworm-slim AS serve
RUN apt-get update \\
    && apt-get install -y --no-install-recommends ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --home /app --shell /usr/sbin/nologin rustsploit
WORKDIR /app

COPY --from=builder /workspace/target/release/rustsploit /usr/local/bin/rustsploit
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \\
    && chown rustsploit:rustsploit /usr/local/bin/rustsploit

USER rustsploit
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
"""


def render_entrypoint() -> str:
    return """#!/bin/sh
set -eu

API_KEY="${RUSTSPLOIT_API_KEY:-}"
if [ -z "$API_KEY" ]; then
  echo "RUSTSPLOIT_API_KEY must be set." >&2
  exit 1
fi

INTERFACE="${RUSTSPLOIT_INTERFACE:-0.0.0.0:8080}"
if ! printf '%s' "$INTERFACE" | grep -q ':'; then
  INTERFACE="${INTERFACE}:8080"
fi

ARGS="--api --api-key ${API_KEY} --interface ${INTERFACE}"

HARDEN="$(printf '%s' "${RUSTSPLOIT_HARDEN:-false}" | tr '[:upper:]' '[:lower:]')"
if [ "$HARDEN" = "true" ] || [ "$HARDEN" = "1" ]; then
  ARGS="${ARGS} --harden"
  if [ -n "${RUSTSPLOIT_IP_LIMIT:-}" ]; then
    ARGS="${ARGS} --ip-limit ${RUSTSPLOIT_IP_LIMIT}"
  fi
fi

exec /usr/local/bin/rustsploit ${ARGS}
"""


def render_compose(bind_host: str) -> str:
    return f"""# Generated by scripts/setup_docker.py
services:
  rustsploit-api:
    container_name: rustsploit-api
    build:
      context: .
      dockerfile: docker/Dockerfile.api
      target: serve
    restart: unless-stopped
    env_file:
      - .env.rustsploit-docker
    environment:
      RUSTSPLOIT_INTERFACE: "{bind_host}:{DEFAULT_PORT}"
    ports:
      - "{bind_host}:{DEFAULT_PORT}:{DEFAULT_PORT}"
    volumes:
      - rustsploit-data:/app/data

volumes:
  rustsploit-data:
    name: rustsploit-data
"""


def render_env(vars_: Dict[str, str]) -> str:
    lines = [f"{key}={value}" for key, value in vars_.items()]
    return "\n".join(lines) + "\n"


def docker_compose_up(compose_cmd: Sequence[str], compose_file: Path) -> None:
    command = list(compose_cmd) + ["-f", str(compose_file), "up", "-d", "--build"]
    print(f"[+] Running: {' '.join(command)}")
    subprocess.run(command, check=True)


def main() -> None:
    repo_root = ensure_repo_root()
    compose_cmd = which_compose()

    bind_ip, bind_combo = resolve_bind_address()
    api_settings = prompt_api_settings()
    compose_path = repo_root / "docker-compose.rustsploit.yml"
    dockerfile_path = repo_root / "docker" / "Dockerfile.api"
    entrypoint_path = repo_root / "docker" / "entrypoint.sh"
    env_path = repo_root / ".env.rustsploit-docker"

    confirm_overwrite(compose_path)
    confirm_overwrite(dockerfile_path)
    confirm_overwrite(entrypoint_path)
    confirm_overwrite(env_path)

    write_file(dockerfile_path, render_dockerfile())
    write_file(entrypoint_path, render_entrypoint(), make_executable=True)

    write_file(env_path, render_env(api_settings))
    write_file(compose_path, render_compose(bind_ip))

    print("\n[+] Files generated:")
    for path in (dockerfile_path, entrypoint_path, env_path, compose_path):
        print(f"    - {path}")

    if prompt_yes_no("Build and start the Docker Compose stack now?", default=True):
        docker_compose_up(compose_cmd, compose_path)
        print("[+] Docker Compose stack is up. Use `docker compose logs -f` to monitor.")
    else:
        print("[*] Skipped docker compose run. You can start it later with:")
        compose_exe = " ".join(compose_cmd)
        print(f"    {compose_exe} -f {compose_path} up -d --build")

    print("\nDone.")


if __name__ == "__main__":
    main()

