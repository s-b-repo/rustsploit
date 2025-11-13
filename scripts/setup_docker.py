#!/usr/bin/env python3
"""
RustSploit Docker setup utility.

This helper can run fully interactively or accept CLI flags for automated use.
It will:
  • Validate the repository root and Docker tooling.
  • Collect (or generate) safe values for the API bind address, port, and key.
  • Produce a hardened multi-stage Dockerfile, entrypoint script, Compose file, and env file.
  • Optionally launch `docker compose up -d --build`.

The build/serve stages follow the guidance seen in vxcontrol/pentagi’s Dockerfile.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

REPO_MARKER = "Cargo.toml"
DEFAULT_PORT = 8080


@dataclass(frozen=True)
class BindConfig:
    host: str
    port: int

    @property
    def host_port(self) -> str:
        return f"{self.host}:{self.port}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision the RustSploit API behind Docker Compose.")
    parser.add_argument(
        "--bind",
        help="Host or host:port to bind (e.g. 127.0.0.1 or 0.0.0.0:8080). "
        "If omitted, an interactive selector is shown.",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Host port to expose (defaults to 8080). Ignored if --bind already includes a port.",
    )
    parser.add_argument("--api-key", help="Pre-shared API key to bake into the container.")
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help="Generate a random API key instead of prompting. Mutually exclusive with --api-key.",
    )
    parser.add_argument(
        "--enable-hardening",
        action="store_true",
        help="Force-enable hardening (auto-rotate API key on suspicious activity).",
    )
    parser.add_argument(
        "--disable-hardening",
        action="store_true",
        help="Force-disable hardening. If omitted, an interactive prompt is shown.",
    )
    parser.add_argument(
        "--ip-limit",
        type=int,
        help="Max unique IPs allowed before rotating the API key (requires hardening).",
    )
    parser.add_argument(
        "--compose-cmd",
        help="Override docker compose binary (e.g. 'docker compose'). Defaults to auto-detection.",
    )
    parser.add_argument(
        "--compose-file",
        default="docker-compose.rustsploit.yml",
        help="Output path for the generated docker compose file.",
    )
    parser.add_argument(
        "--dockerfile-path",
        default="docker/Dockerfile.api",
        help="Output path for the generated Dockerfile.",
    )
    parser.add_argument(
        "--entrypoint-path",
        default="docker/entrypoint.sh",
        help="Output path for the generated entrypoint script.",
    )
    parser.add_argument(
        "--env-file",
        default=".env.rustsploit-docker",
        help="Output path for the generated environment file.",
    )
    parser.add_argument(
        "--skip-up",
        action="store_true",
        help="Generate files but do not invoke docker compose up.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files without confirmation.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail if required values are missing instead of prompting.",
    )
    return parser.parse_args()


def ensure_repo_root() -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    if not (repo_root / REPO_MARKER).exists():
        print(f"[!] Could not locate {REPO_MARKER}. Run this script from inside the RustSploit repository.")
        sys.exit(1)
    return repo_root


def resolve_compose_command(preferred: Optional[str]) -> Sequence[str]:
    def validate(cmd: Sequence[str]) -> Optional[Sequence[str]]:
        if not cmd:
            return None
        try:
            subprocess.run(list(cmd) + ["version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return list(cmd)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return None

    if preferred:
        command = validate(shlex.split(preferred))
        if command:
            return command
        print(f"[!] Provided compose command '{preferred}' is not usable.")
        sys.exit(1)

    for candidate in (["docker-compose"], ["docker", "compose"]):
        resolved = validate(candidate)
        if resolved:
            return resolved

    print("[!] Could not find docker-compose or docker compose in PATH.")
    sys.exit(1)


def detect_private_ip() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def prompt_choice(prompt: str, options: List[str]) -> str:
    print(prompt)
    for idx, option in enumerate(options, start=1):
        print(f"  [{idx}] {option}")
    while True:
        choice = input("Select option number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Please enter a valid number.")


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


def prompt_port_value(default: int) -> int:
    while True:
        value = prompt_str("API port", str(default))
        if value.isdigit():
            port = int(value)
            if 1 <= port <= 65535:
                return port
        print("Please provide a valid TCP port (1-65535).")


def parse_bind_value(value: str, fallback_port: int) -> BindConfig:
    value = value.strip()
    if not value:
        raise ValueError("Bind value cannot be empty.")

    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        if not port_str.isdigit():
            raise ValueError("Port portion must be numeric.")
        port = int(port_str)
    else:
        host = value
        port = fallback_port

    if not host or any(ch.isspace() for ch in host):
        raise ValueError("Host must not be empty or contain whitespace.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host not in {"localhost"} and len(host) > 253:
            raise ValueError("Host looks invalid or too long.")

    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")

    return BindConfig(host=host, port=port)


def interactive_bind_config() -> BindConfig:
    choices = [
        "127.0.0.1 (loopback)",
        "0.0.0.0 (all interfaces)",
        "Private LAN (auto-detect)",
        "Custom",
    ]
    selection = prompt_choice("Select API bind address:", choices)

    if selection.startswith("127.0.0.1"):
        host = "127.0.0.1"
    elif selection.startswith("0.0.0.0"):
        host = "0.0.0.0"
    elif selection.startswith("Private"):
        detected = detect_private_ip()
        if detected:
            print(f"Detected private IP: {detected}")
            host = detected
        else:
            print("Unable to auto-detect LAN IP.")
            host = prompt_str("Enter LAN IP", allow_empty=False)
    else:
        custom = prompt_str("Enter IP or host (optionally host:port)", allow_empty=False)
        try:
            return parse_bind_value(custom, DEFAULT_PORT)
        except ValueError as exc:
            print(f"[!] {exc}")
            return interactive_bind_config()

    port = prompt_port_value(DEFAULT_PORT)
    return BindConfig(host=host, port=port)


def collect_bind_config(args: argparse.Namespace) -> BindConfig:
    if args.bind:
        try:
            return parse_bind_value(args.bind, args.port or DEFAULT_PORT)
        except ValueError as exc:
            print(f"[!] Invalid --bind value: {exc}")
            sys.exit(1)

    if args.non_interactive:
        host = "0.0.0.0"
        port = args.port or DEFAULT_PORT
        return BindConfig(host=host, port=port)

    bind = interactive_bind_config()
    if args.port and args.port != bind.port:
        print("[*] Overriding interactive port with --port.")
        bind = BindConfig(host=bind.host, port=args.port)
    return bind


def validate_api_key(key: str) -> None:
    if not key:
        raise ValueError("API key cannot be empty.")
    if len(key) > 128:
        raise ValueError("API key exceeds 128 characters.")
    if not all(32 <= ord(c) <= 126 for c in key):
        raise ValueError("API key must be printable ASCII without whitespace.")


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def collect_api_settings(args: argparse.Namespace, non_interactive: bool) -> Dict[str, str]:
    if args.api_key and args.generate_key:
        print("[!] --api-key and --generate-key are mutually exclusive.")
        sys.exit(1)

    if args.api_key:
        try:
            validate_api_key(args.api_key)
        except ValueError as exc:
            print(f"[!] Invalid API key: {exc}")
            sys.exit(1)
        api_key = args.api_key
    elif args.generate_key:
        api_key = generate_api_key()
        print(f"[+] Generated API key: {api_key}")
    elif non_interactive:
        print("[!] --non-interactive requires --api-key or --generate-key.")
        sys.exit(1)
    else:
        if prompt_yes_no("Would you like to specify an API key?", default=True):
            while True:
                candidate = prompt_str("Enter API key (ASCII, 128 chars max)", allow_empty=False)
                try:
                    validate_api_key(candidate)
                except ValueError as exc:
                    print(f"[!] {exc}")
                    continue
                api_key = candidate
                break
        else:
            api_key = generate_api_key()
            print(f"[+] Generated API key: {api_key}")

    if args.enable_hardening and args.disable_hardening:
        print("[!] --enable-hardening and --disable-hardening cannot both be provided.")
        sys.exit(1)

    if args.enable_hardening:
        harden = True
    elif args.disable_hardening:
        harden = False
    elif non_interactive:
        harden = False
    else:
        harden = prompt_yes_no("Enable API hardening (auto-rotate key on suspicious activity)?", default=False)

    ip_limit = args.ip_limit
    if harden:
        if ip_limit is not None and ip_limit <= 0:
            print("[!] --ip-limit must be positive.")
            sys.exit(1)
        if ip_limit is None:
            if non_interactive:
                ip_limit = 10
            else:
                while True:
                    value = prompt_str("Max unique IPs before rotation", default="10")
                    if value.isdigit() and int(value) > 0:
                        ip_limit = int(value)
                        break
                    print("Please provide a positive integer.")
    else:
        if ip_limit and not args.enable_hardening:
            print("[!] --ip-limit is ignored unless hardening is enabled.")
        ip_limit = ip_limit or 10

    return {
        "RUSTSPLOIT_API_KEY": api_key,
        "RUSTSPLOIT_HARDEN": "true" if harden else "false",
        "RUSTSPLOIT_IP_LIMIT": str(ip_limit),
    }


def confirm_overwrite(path: Path, force: bool) -> None:
    if not path.exists() or force:
        return
    if prompt_yes_no(f"{path} exists. Overwrite?", default=False):
        return
    print("Aborting to avoid overwriting existing files.")
    sys.exit(0)


def write_file(path: Path, content: str, make_executable: bool = False, mode: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        os.chmod(path, mode)
    elif make_executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    elif path.name.startswith(".env"):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def render_dockerfile() -> str:
    return """# Generated by scripts/setup_docker.py
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

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo fetch
RUN rm -rf src

COPY . .
RUN cargo build --release --bin rustsploit

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


def render_compose(bind: BindConfig, env_file: str) -> str:
    env_ref = Path(env_file).as_posix()
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
      - {env_ref}
    ports:
      - "{bind.host}:{bind.port}:8080"
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


def render_env(bind: BindConfig, vars_: Dict[str, str]) -> str:
    merged = {
        "RUSTSPLOIT_INTERFACE": bind.host_port,
        **vars_,
    }
    return "\n".join(f"{key}={value}" for key, value in merged.items()) + "\n"


def docker_compose_up(compose_cmd: Sequence[str], compose_file: Path) -> None:
    command = list(compose_cmd) + ["-f", str(compose_file), "up", "-d", "--build"]
    print(f"[+] Running: {' '.join(command)}")
    subprocess.run(command, check=True, env={**os.environ, "DOCKER_BUILDKIT": "1"})


def main() -> None:
    args = parse_args()
    repo_root = ensure_repo_root()
    compose_cmd = resolve_compose_command(args.compose_cmd)

    bind = collect_bind_config(args)
    api_settings = collect_api_settings(args, args.non_interactive)

    compose_path = repo_root / args.compose_file
    dockerfile_path = repo_root / args.dockerfile_path
    entrypoint_path = repo_root / args.entrypoint_path
    env_path = repo_root / args.env_file

    for path in (compose_path, dockerfile_path, entrypoint_path, env_path):
        confirm_overwrite(path, args.force)

    write_file(dockerfile_path, render_dockerfile())
    write_file(entrypoint_path, render_entrypoint(), make_executable=True)
    write_file(env_path, render_env(bind, api_settings))
    write_file(compose_path, render_compose(bind, args.env_file))

    print("\n[+] Generated files:")
    for path in (dockerfile_path, entrypoint_path, env_path, compose_path):
        print(f"    - {path.relative_to(repo_root)}")

    if args.skip_up:
        print("\n[*] Skipped docker compose run. Start manually with:")
        cmd = " ".join(compose_cmd)
        print(f"    {cmd} -f {compose_path} up -d --build")
        return

    docker_compose_up(compose_cmd, compose_path)
    print("[+] Docker Compose stack is running. Use `docker compose logs -f` to follow output.")


if __name__ == "__main__":
    main()

