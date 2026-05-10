#!/usr/bin/env python3
"""
RustSploit + ArcticAlopex bootstrap helper.

Discovers the two halves of the stack (Rust backend in `Cargo.toml`,
Next.js control plane in `arcticalopex/package.json`) starting from the
current directory or `--path <dir>`, then either runs the install / build
/ start steps automatically, or prints the exact commands so the user can
run them by hand.

Usage:

    # auto-pilot the whole stack from the repo root
    python3 scripts/setup_stack.py auto

    # auto from anywhere, pointing at an explicit checkout
    python3 scripts/setup_stack.py auto --path /home/me/rustsploit-main

    # don't run anything; print the commands the auto path would issue
    python3 scripts/setup_stack.py manual

    # individual steps (composable)
    python3 scripts/setup_stack.py doctor
    python3 scripts/setup_stack.py docker up
    python3 scripts/setup_stack.py rust build
    python3 scripts/setup_stack.py rust run
    python3 scripts/setup_stack.py arctic install
    python3 scripts/setup_stack.py arctic env          # generate .env w/ secrets
    python3 scripts/setup_stack.py arctic migrate
    python3 scripts/setup_stack.py arctic dev          # foreground dev server
    python3 scripts/setup_stack.py arctic build        # production build
    python3 scripts/setup_stack.py arctic start        # serve the prod build
    python3 scripts/setup_stack.py status              # what's installed/running

The tool only uses Python's standard library. It runs on Linux and macOS;
Windows is best-effort (subprocess works, ANSI colors fall back to plain).
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


# ─── Terminal helpers ────────────────────────────────────────────────────


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


_COLOR = _supports_color()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def info(s: str) -> None:
    print(_c("36", "[*]"), s)


def ok(s: str) -> None:
    print(_c("32", "[+]"), s)


def warn(s: str) -> None:
    print(_c("33", "[!]"), s)


def err(s: str) -> None:
    print(_c("31", "[-]"), s, file=sys.stderr)


def head(s: str) -> None:
    print()
    print(_c("1;36", f"── {s} ──"))


# ─── Repo discovery ──────────────────────────────────────────────────────


@dataclass
class Repo:
    root: Path
    has_rust: bool
    has_arctic: bool
    has_compose: bool

    @property
    def arctic(self) -> Path:
        return self.root / "arcticalopex"

    @property
    def cargo_toml(self) -> Path:
        return self.root / "Cargo.toml"

    @property
    def compose(self) -> Path:
        return self.arctic / "docker-compose.yml"

    @property
    def env_example(self) -> Path:
        return self.arctic / ".env.example"

    @property
    def env_file(self) -> Path:
        return self.arctic / ".env"


def discover(start: Path) -> Repo:
    """Walk up from `start` looking for the first dir that contains either
    `Cargo.toml` or `arcticalopex/package.json`. We don't insist both are
    present — the tool degrades to whichever half exists.
    """
    start = start.resolve()
    candidate = start
    while True:
        rust = (candidate / "Cargo.toml").is_file()
        arctic = (candidate / "arcticalopex" / "package.json").is_file()
        if rust or arctic:
            return Repo(
                root=candidate,
                has_rust=rust,
                has_arctic=arctic,
                has_compose=(candidate / "arcticalopex" / "docker-compose.yml").is_file(),
            )
        if candidate.parent == candidate:
            err(
                "Could not find a RustSploit checkout — neither Cargo.toml nor "
                "arcticalopex/package.json exists in the current directory or "
                "any parent. Pass --path <dir> to point at a checkout."
            )
            sys.exit(2)
        candidate = candidate.parent


# ─── Tool detection ──────────────────────────────────────────────────────


@dataclass
class Tool:
    name: str
    cmd: str
    install_hint: str
    needed_for: str


_TOOLS = [
    Tool("rustc", "rustc", "https://rustup.rs/", "rust build/run"),
    Tool("cargo", "cargo", "https://rustup.rs/", "rust build/run"),
    Tool("node", "node", "https://nodejs.org/ (>=20)", "arctic install/dev/build"),
    Tool("pnpm", "pnpm", "npm install -g pnpm", "arctic install/dev/build"),
    Tool("docker", "docker", "https://docs.docker.com/engine/install/", "docker up"),
    Tool("openssl", "openssl", "system package manager (used to mint MASTER_KEY)", "arctic env"),
]


def which(name: str) -> str | None:
    return shutil.which(name)


def doctor(repo: Repo) -> int:
    """Report installed tools. Returns the count of *missing* tools."""
    head("Doctor")
    info(f"Repo root:       {repo.root}")
    info(f"Rust backend:    {'present' if repo.has_rust else 'missing'}")
    info(f"ArcticAlopex:    {'present' if repo.has_arctic else 'missing'}")
    info(f"docker-compose:  {'present' if repo.has_compose else 'missing'}")

    missing = 0
    print()
    for t in _TOOLS:
        path = which(t.cmd)
        if path:
            ok(f"{t.name:<10} → {path}")
        else:
            warn(f"{t.name:<10} — not found ({t.install_hint})")
            missing += 1
    return missing


# ─── Command runner ──────────────────────────────────────────────────────


def run(
    cmd: Sequence[str] | str,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    dry_run: bool = False,
) -> int:
    """Run a command, streaming its output to the parent terminal. If
    `dry_run` is True we just print what *would* run and return 0."""
    if isinstance(cmd, str):
        rendered = cmd
        cmd_list: list[str] | str = cmd
        shell = True
    else:
        rendered = " ".join(_quote(c) for c in cmd)
        cmd_list = list(cmd)
        shell = False
    cwd_str = f"  (cwd: {cwd})" if cwd else ""
    print(_c("90", f"$ {rendered}{cwd_str}"))
    if dry_run:
        return 0
    proc = subprocess.run(cmd_list, cwd=cwd, env=env, shell=shell)
    if check and proc.returncode != 0:
        err(f"Command failed (exit {proc.returncode}): {rendered}")
        sys.exit(proc.returncode)
    return proc.returncode


def _quote(s: str) -> str:
    if not s or any(c in s for c in " \t\"'$`\\!"):
        return "'" + s.replace("'", "'\\''") + "'"
    return s


# ─── Port checks ─────────────────────────────────────────────────────────


def _port_in_use(host: str, port: int) -> bool:
    """Best-effort `is anything listening on host:port`. Checks both IPv4
    and IPv6 loopback when the caller passes 127.0.0.1, because Node and
    Next dev servers commonly bind to [::1] only and the v4 probe would
    otherwise report 'free' while the dev server is plainly running.
    """
    candidates: list[tuple[int, str]] = []
    if host == "127.0.0.1":
        candidates.extend([(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")])
    elif host == "::1":
        candidates.append((socket.AF_INET6, "::1"))
    else:
        try:
            for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                candidates.append((info[0], info[4][0]))
        except socket.gaierror:
            return False
    for family, addr in candidates:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((addr, port)) == 0:
                    return True
        except OSError:
            continue
    return False


def check_ports(ports: Iterable[tuple[str, int, str]]) -> None:
    """Warn (don't fail) when a port we care about is already taken."""
    for host, port, label in ports:
        if _port_in_use(host, port):
            warn(f"{label} port {host}:{port} is already in use")


# ─── .env generation ─────────────────────────────────────────────────────


_ENV_KEYS = [
    "POSTGRES_PASSWORD",
    "DATABASE_URL",
    "REDIS_PASSWORD",
    "REDIS_URL",
    "MINIO_ENDPOINT",
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
    "MINIO_ACCESS_KEY",
    "MINIO_SECRET_KEY",
    "MINIO_BUCKET",
    "MASTER_KEY",
    "WS_PORT",
    "WS_SERVER_URL",
    "APP_URL",
    "SESSION_TTL_SECONDS",
    "INVITE_TTL_SECONDS",
]


def gen_env(repo: Repo, *, overwrite: bool = False, dry_run: bool = False) -> None:
    """Generate `arcticalopex/.env` from `.env.example` with random secrets.

    The template's `CHANGE_ME_*` placeholders are replaced with values
    minted via `secrets.token_hex(32)`. Existing files are preserved
    unless `overwrite=True`.
    """
    head("Generate arcticalopex/.env")
    if not repo.env_example.is_file():
        err(f"Template not found: {repo.env_example}")
        sys.exit(1)
    if repo.env_file.is_file() and not overwrite:
        ok(f"{repo.env_file.relative_to(repo.root)} already exists — leaving it alone")
        return

    pg_pw = secrets.token_hex(32)
    redis_pw = secrets.token_hex(32)
    minio_user = "arctic-" + secrets.token_hex(4)
    minio_pw = secrets.token_hex(32)
    master = secrets.token_hex(32)

    body = (
        "# Generated by scripts/setup_stack.py — do not commit.\n"
        f"POSTGRES_PASSWORD={pg_pw}\n"
        f"DATABASE_URL=postgres://arcticalopex:{pg_pw}@127.0.0.1:5432/arcticalopex\n"
        f"REDIS_PASSWORD={redis_pw}\n"
        f"REDIS_URL=redis://:{redis_pw}@127.0.0.1:6379\n"
        f"MINIO_ENDPOINT=http://127.0.0.1:9000\n"
        f"MINIO_ROOT_USER={minio_user}\n"
        f"MINIO_ROOT_PASSWORD={minio_pw}\n"
        f"MINIO_ACCESS_KEY={minio_user}\n"
        f"MINIO_SECRET_KEY={minio_pw}\n"
        f"MINIO_BUCKET=arcticalopex\n"
        f"MASTER_KEY={master}\n"
        f"WS_PORT=3001\n"
        f"WS_SERVER_URL=ws://127.0.0.1:3001\n"
        f"APP_URL=http://127.0.0.1:3000\n"
        f"SESSION_TTL_SECONDS=28800\n"
        f"INVITE_TTL_SECONDS=259200\n"
    )

    if dry_run:
        info(f"would write {repo.env_file} ({len(body)} bytes, secrets randomised)")
        return

    repo.env_file.parent.mkdir(parents=True, exist_ok=True)
    repo.env_file.write_text(body)
    try:
        os.chmod(repo.env_file, 0o600)
    except OSError:
        pass
    ok(f"wrote {repo.env_file.relative_to(repo.root)} (mode 0600, secrets randomised)")


def env_keys_used(_unused: tuple[str, ...] = tuple(_ENV_KEYS)) -> tuple[str, ...]:
    """Returned for tests / introspection — the list of keys we manage."""
    return _unused


# ─── docker-compose helpers ──────────────────────────────────────────────


def _docker_compose_args(repo: Repo) -> list[str]:
    """Return the executable + leading flags for `docker compose -f …`. We
    always run with `--env-file` pointing at the generated `.env` so the
    compose template's variable substitution lands the random secrets
    instead of the placeholder strings from `.env.example`.
    """
    return [
        "docker",
        "compose",
        "-f",
        str(repo.compose),
        "--env-file",
        str(repo.env_file),
    ]


def docker_up(repo: Repo, *, dry_run: bool = False) -> None:
    head("Bring up docker-compose dependencies")
    if not repo.has_compose:
        err(f"docker-compose.yml not found at {repo.compose}")
        sys.exit(1)
    if not repo.env_file.is_file():
        warn("arcticalopex/.env not found — generating it first.")
        gen_env(repo, dry_run=dry_run)
    check_ports(
        [
            ("127.0.0.1", 5432, "Postgres"),
            ("127.0.0.1", 6379, "Redis"),
            ("127.0.0.1", 9000, "MinIO"),
        ]
    )
    run(_docker_compose_args(repo) + ["up", "-d", "postgres", "redis", "minio"], dry_run=dry_run)


def docker_down(repo: Repo, *, dry_run: bool = False) -> None:
    head("Stop docker-compose dependencies")
    if not repo.has_compose:
        err(f"docker-compose.yml not found at {repo.compose}")
        sys.exit(1)
    run(_docker_compose_args(repo) + ["down"], dry_run=dry_run)


def docker_logs(repo: Repo, follow: bool = False, *, dry_run: bool = False) -> None:
    cmd = _docker_compose_args(repo) + ["logs"]
    if follow:
        cmd.append("-f")
    run(cmd, dry_run=dry_run, check=False)


# ─── Rust ────────────────────────────────────────────────────────────────


def rust_build(repo: Repo, *, release: bool = False, dry_run: bool = False) -> None:
    head(f"cargo build{' --release' if release else ''}")
    if not repo.has_rust:
        err("Cargo.toml not found")
        sys.exit(1)
    cmd = ["cargo", "build"]
    if release:
        cmd.append("--release")
    run(cmd, cwd=repo.root, dry_run=dry_run)


def rust_run(
    repo: Repo,
    *,
    bind: str = "127.0.0.1:8080",
    release: bool = False,
    dry_run: bool = False,
) -> None:
    head("Run RustSploit API server")
    if not repo.has_rust:
        err("Cargo.toml not found")
        sys.exit(1)
    check_ports([("127.0.0.1", int(bind.split(":")[-1]), "Rust API")])
    cmd = ["cargo", "run"]
    if release:
        cmd.append("--release")
    cmd += ["--", "--api", "--interface", bind]
    run(cmd, cwd=repo.root, dry_run=dry_run)


# ─── Arctic ──────────────────────────────────────────────────────────────


def arctic_install(repo: Repo, *, dry_run: bool = False) -> None:
    head("Install ArcticAlopex dependencies (pnpm install)")
    if not repo.has_arctic:
        err("arcticalopex/package.json not found")
        sys.exit(1)
    run(["pnpm", "install"], cwd=repo.arctic, dry_run=dry_run)


def arctic_migrate(repo: Repo, *, dry_run: bool = False) -> None:
    head("Run database migrations (pnpm db:migrate)")
    if not repo.env_file.is_file():
        warn("arcticalopex/.env not found — generating it first.")
        gen_env(repo, dry_run=dry_run)
    run(["pnpm", "db:migrate"], cwd=repo.arctic, dry_run=dry_run)


def arctic_dev(repo: Repo, *, dry_run: bool = False) -> None:
    head("Start ArcticAlopex dev server (pnpm dev)")
    check_ports([("127.0.0.1", 3000, "ArcticAlopex dev"), ("::1", 3000, "ArcticAlopex dev")])
    run(["pnpm", "dev"], cwd=repo.arctic, dry_run=dry_run)


def arctic_build(repo: Repo, *, dry_run: bool = False) -> None:
    head("Production build (pnpm build)")
    run(["pnpm", "build"], cwd=repo.arctic, dry_run=dry_run)


def arctic_start(repo: Repo, *, dry_run: bool = False) -> None:
    head("Start ArcticAlopex production server (pnpm start)")
    check_ports([("127.0.0.1", 3000, "ArcticAlopex prod")])
    run(["pnpm", "start"], cwd=repo.arctic, dry_run=dry_run)


# ─── auto / manual ───────────────────────────────────────────────────────


# `--only` picker — what slice of the stack to operate on.
ONLY_CHOICES = ("both", "rust", "arctic")


def _pick_only(repo: Repo) -> str:
    """Resolve `--only` when the user didn't pass it.

    On a TTY we ask. Off a TTY (CI, scripts, piped) we fall back to whatever
    the checkout supports — both halves if both exist, otherwise the one
    half that does.
    """
    if repo.has_rust and not repo.has_arctic:
        return "rust"
    if repo.has_arctic and not repo.has_rust:
        return "arctic"
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return "both"
    print()
    print(_c("1;36", "Which framework do you want to set up?"))
    print(f"  [{_c('1', '1')}] both    — RustSploit backend + ArcticAlopex frontend (default)")
    print(f"  [{_c('1', '2')}] rust    — RustSploit backend only")
    print(f"  [{_c('1', '3')}] arctic  — ArcticAlopex frontend only")
    while True:
        try:
            ans = input("Choice [1/2/3] (Enter = 1): ").strip().lower()
        except EOFError:
            return "both"
        if ans in ("", "1", "both"):
            return "both"
        if ans in ("2", "rust", "r"):
            return "rust"
        if ans in ("3", "arctic", "a", "arcticalopex"):
            return "arctic"
        warn("Please enter 1, 2, or 3.")


def _resolve_only(repo: Repo, only: str) -> tuple[bool, bool]:
    """Return `(do_rust, do_arctic)` after applying the user's `--only`
    choice and dropping things the checkout doesn't actually have. Errors
    if the user asked for a half that isn't present so we don't silently
    do nothing."""
    do_rust = only in ("both", "rust")
    do_arctic = only in ("both", "arctic")
    if do_rust and not repo.has_rust:
        if only == "rust":
            err("--only rust was requested but Cargo.toml is not in this checkout.")
            sys.exit(2)
        do_rust = False
    if do_arctic and not repo.has_arctic:
        if only == "arctic":
            err("--only arctic was requested but arcticalopex/package.json is not in this checkout.")
            sys.exit(2)
        do_arctic = False
    if not (do_rust or do_arctic):
        err("Nothing to do — neither half of the stack is present in the resolved repo.")
        sys.exit(2)
    return do_rust, do_arctic


def auto(
    repo: Repo,
    *,
    only: str = "both",
    skip_docker: bool = False,
    release: bool = False,
    dry_run: bool = False,
) -> None:
    do_rust, do_arctic = _resolve_only(repo, only)
    head(f"Auto setup ({'rust+arctic' if do_rust and do_arctic else 'rust only' if do_rust else 'arctic only'})")
    if doctor(repo) > 0 and not dry_run:
        warn("Some tools are missing — install them and re-run, or use 'manual' to print commands.")

    # 1. .env (random secrets)
    if do_arctic:
        gen_env(repo, dry_run=dry_run)

    # 2. infrastructure (only matters for the arctic half)
    if do_arctic and repo.has_compose and not skip_docker:
        docker_up(repo, dry_run=dry_run)
    elif do_arctic and skip_docker:
        warn("Skipping docker (--no-docker): you must provide Postgres / Redis / MinIO yourself.")

    # 3. install + migrate frontend
    if do_arctic:
        arctic_install(repo, dry_run=dry_run)
        arctic_migrate(repo, dry_run=dry_run)

    # 4. build backend
    if do_rust:
        rust_build(repo, release=release, dry_run=dry_run)

    head("Done")
    info("Next steps:")
    if do_rust:
        print(_c("90", f"  $ python3 {Path(__file__).name} rust run"))
    if do_arctic:
        print(_c("90", f"  $ python3 {Path(__file__).name} arctic dev"))
        info("Then open http://127.0.0.1:3000")


def manual(
    repo: Repo,
    *,
    only: str = "both",
    skip_docker: bool = False,
    release: bool = False,
) -> None:
    """Print every command the auto path would run, in order, without
    executing anything. Useful when the user wants to copy-paste into a
    notes doc, a runbook, or another shell.
    """
    do_rust, do_arctic = _resolve_only(repo, only)
    head(f"Manual command list ({'rust+arctic' if do_rust and do_arctic else 'rust only' if do_rust else 'arctic only'})")
    info("Run these in order, from anywhere — paths are absolute:")
    print()
    arctic = repo.arctic
    n = 1
    if do_arctic:
        print(_c("1", f"# {n}. Generate arcticalopex/.env with random secrets"))
        print(_c("90", f"   python3 {Path(__file__).resolve()} arctic env --path {repo.root}"))
        print()
        n += 1

    if do_arctic and repo.has_compose and not skip_docker:
        print(_c("1", f"# {n}. Bring up Postgres / Redis / MinIO"))
        compose = " ".join(_quote(c) for c in _docker_compose_args(repo))
        print(_c("90", f"   {compose} up -d postgres redis minio"))
        print()
        n += 1

    if do_arctic:
        print(_c("1", f"# {n}. Install frontend dependencies"))
        print(_c("90", f"   cd {arctic} && pnpm install"))
        print()
        n += 1
        print(_c("1", f"# {n}. Apply DB migrations"))
        print(_c("90", f"   cd {arctic} && pnpm db:migrate"))
        print()
        n += 1

    if do_rust:
        flag = " --release" if release else ""
        print(_c("1", f"# {n}. Build the Rust backend"))
        print(_c("90", f"   cd {repo.root} && cargo build{flag}"))
        print()
        n += 1
        print(_c("1", f"# {n}. Run the Rust API server (terminal 1)"))
        print(
            _c(
                "90",
                f"   cd {repo.root} && cargo run{flag} -- --api --interface 127.0.0.1:8080",
            )
        )
        print()
        n += 1

    if do_arctic:
        print(_c("1", f"# {n}. Start the ArcticAlopex dev server (terminal {2 if do_rust else 1})"))
        print(_c("90", f"   cd {arctic} && pnpm dev"))
        print()

    info("That's the full sequence. Each step is also exposed as its own subcommand.")


# ─── status ──────────────────────────────────────────────────────────────


def status(repo: Repo) -> None:
    head("Status")
    info(f"Repo:                 {repo.root}")
    info(f".env file:            {'present' if repo.env_file.is_file() else 'missing'}")

    if repo.has_compose and which("docker"):
        try:
            out = subprocess.check_output(
                _docker_compose_args(repo) + ["ps", "--format", "{{.Service}}\t{{.State}}\t{{.Health}}"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            print()
            print(_c("1", "docker-compose services:"))
            print(out.rstrip() or "  (none up)")
        except subprocess.CalledProcessError:
            warn("docker compose ps failed (is Docker running?)")
        except FileNotFoundError:
            warn("docker not found")

    print()
    print(_c("1", "ports:"))
    for host, port, label in [
        ("127.0.0.1", 5432, "Postgres"),
        ("127.0.0.1", 6379, "Redis"),
        ("127.0.0.1", 9000, "MinIO"),
        ("127.0.0.1", 8080, "Rust API (default)"),
        ("127.0.0.1", 3000, "ArcticAlopex (default)"),
        ("127.0.0.1", 3001, "ArcticAlopex WS"),
    ]:
        marker = _c("32", "open  ") if _port_in_use(host, port) else _c("90", "free  ")
        print(f"  {marker} {host}:{port}  {label}")


# ─── argparse ────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="setup_stack",
        description="Bootstrap RustSploit + ArcticAlopex (auto, manual, or step-by-step).",
    )
    p.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        help="Path to a checkout root (default: cwd).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands instead of running them (applies to every subcommand).",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sub_auto = sub.add_parser("auto", help="Run the full setup sequence end-to-end.")
    sub_auto.add_argument(
        "--only",
        choices=ONLY_CHOICES,
        default=None,
        help="Which framework(s) to set up. Default: prompt on a TTY, else 'both'.",
    )
    sub_auto.add_argument("--no-docker", action="store_true", help="Do not bring up docker-compose.")
    sub_auto.add_argument("--release", action="store_true", help="Build cargo --release.")

    sub_manual = sub.add_parser("manual", help="Print the commands without running them.")
    sub_manual.add_argument(
        "--only",
        choices=ONLY_CHOICES,
        default=None,
        help="Which framework(s) to print commands for. Default: prompt on a TTY, else 'both'.",
    )
    sub_manual.add_argument("--no-docker", action="store_true")
    sub_manual.add_argument("--release", action="store_true")

    sub.add_parser("doctor", help="Check installed tools.")
    sub.add_parser("status", help="Show service / port status.")

    sub_docker = sub.add_parser("docker", help="docker-compose subcommands.")
    sub_docker.add_argument("op", choices=["up", "down", "logs", "logs-follow"])

    sub_rust = sub.add_parser("rust", help="Rust backend operations.")
    sub_rust.add_argument("op", choices=["build", "run"])
    sub_rust.add_argument("--release", action="store_true")
    sub_rust.add_argument("--bind", default="127.0.0.1:8080", help="host:port for `rust run`.")

    sub_arctic = sub.add_parser("arctic", help="ArcticAlopex frontend operations.")
    sub_arctic.add_argument("op", choices=["install", "env", "migrate", "dev", "build", "start"])
    sub_arctic.add_argument("--overwrite", action="store_true", help="Overwrite an existing .env (op=env).")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = discover(Path(args.path))

    try:
        if args.cmd == "auto":
            only = args.only or _pick_only(repo)
            auto(repo, only=only, skip_docker=args.no_docker, release=args.release, dry_run=args.dry_run)
        elif args.cmd == "manual":
            only = args.only or _pick_only(repo)
            manual(repo, only=only, skip_docker=args.no_docker, release=args.release)
        elif args.cmd == "doctor":
            sys.exit(1 if doctor(repo) else 0)
        elif args.cmd == "status":
            status(repo)
        elif args.cmd == "docker":
            if args.op == "up":
                docker_up(repo, dry_run=args.dry_run)
            elif args.op == "down":
                docker_down(repo, dry_run=args.dry_run)
            elif args.op == "logs":
                docker_logs(repo, follow=False, dry_run=args.dry_run)
            elif args.op == "logs-follow":
                docker_logs(repo, follow=True, dry_run=args.dry_run)
        elif args.cmd == "rust":
            if args.op == "build":
                rust_build(repo, release=args.release, dry_run=args.dry_run)
            else:  # run
                rust_run(repo, bind=args.bind, release=args.release, dry_run=args.dry_run)
        elif args.cmd == "arctic":
            if args.op == "install":
                arctic_install(repo, dry_run=args.dry_run)
            elif args.op == "env":
                gen_env(repo, overwrite=args.overwrite, dry_run=args.dry_run)
            elif args.op == "migrate":
                arctic_migrate(repo, dry_run=args.dry_run)
            elif args.op == "dev":
                arctic_dev(repo, dry_run=args.dry_run)
            elif args.op == "build":
                arctic_build(repo, dry_run=args.dry_run)
            elif args.op == "start":
                arctic_start(repo, dry_run=args.dry_run)
    except KeyboardInterrupt:
        warn("Interrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
