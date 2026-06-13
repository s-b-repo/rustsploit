// src/prescan.rs
//
// Optional CIDR pre-scan via an external mass-scan tool (masscan or zmap).
// When enabled, the scheduler hands the CIDR to the prescan tool, ingests
// the live-host list, and only fans the module out against hits — instead
// of blindly probing every host in the range.
//
// Speedup is dramatic on sparse internet ranges: a /16 with 65535 hosts
// and a 0.1% live-host rate means ~65 hosts hit instead of 65535. At a
// per-host module timeout of 5 s and concurrency of 50, that's ~6 s
// instead of ~110 minutes.
//
// Configuration:
//   setg prescan masscan        # use masscan if installed
//   setg prescan zmap           # use zmap if installed
//   setg prescan auto           # masscan first, fall back to zmap (default)
//   setg prescan none           # disabled (legacy behaviour)
//   setg prescan_port 80,443    # port(s) to probe (default: depends on `port`)
//   setg prescan_rate 1000      # packets/sec for masscan (--rate flag)
//
// Pre-scan is opt-in: when `prescan` is unset or `none`, behaviour is
// identical to v0.5.1. Auto mode tries masscan/zmap in order and silently
// falls through to per-IP fan-out if neither is installed.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const DEFAULT_PRESCAN_PORTS: &str = "80,443";
const DEFAULT_PRESCAN_RATE: u32 = 1000;

/// Which prescan tool to use, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prescan {
    /// No prescan — fan out to every host in the CIDR.
    None,
    /// Use masscan (`-rate`, fast SYN scan, root required).
    Masscan,
    /// Use zmap (`-r`, faster than masscan, root required).
    Zmap,
}

impl Prescan {
    /// Resolve the operator's `setg prescan` choice, falling back to `auto`
    /// → `masscan` → `zmap` → `none`.
    pub fn from_global_options() -> Self {
        let scope = crate::tenant::resolve();
        let raw = scope
            .global_options()
            .try_get("prescan")
            .unwrap_or_default();
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => {
                if which_path("masscan").is_some() {
                    Self::Masscan
                } else if which_path("zmap").is_some() {
                    Self::Zmap
                } else {
                    Self::None
                }
            }
            "masscan" => {
                if which_path("masscan").is_some() {
                    Self::Masscan
                } else {
                    crate::meprintln!(
                        "[!] setg prescan=masscan but `masscan` not on PATH — falling back to none."
                    );
                    Self::None
                }
            }
            "zmap" => {
                if which_path("zmap").is_some() {
                    Self::Zmap
                } else {
                    crate::meprintln!(
                        "[!] setg prescan=zmap but `zmap` not on PATH — falling back to none."
                    );
                    Self::None
                }
            }
            "none" | "off" | "false" | "0" | "no" => Self::None,
            other => {
                crate::meprintln!(
                    "[!] setg prescan='{}' not recognised — using none. Valid: auto/masscan/zmap/none.",
                    other
                );
                Self::None
            }
        }
    }

    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Masscan | Self::Zmap)
    }
}

fn which_path(bin: &str) -> Option<PathBuf> {
    which::which(bin).ok()
}

/// Probe the network with the configured prescan tool. Returns the list of
/// live IPs (as strings — masscan/zmap output IPs in dotted-decimal form).
///
/// Caps:
///   - Max output size: 100 MiB. masscan can be misconfigured to spew many
///     gigabytes of JSON; the cap keeps memory bounded.
///   - Hard wall-clock timeout: 4× (host_count / rate) seconds, plus 30 s
///     of slack — so a misconfigured tool can't hang forever.
pub async fn discover_live(cidr: &IpNetwork, tool: Prescan) -> Result<Vec<String>> {
    if !tool.is_enabled() {
        return Ok(Vec::new());
    }
    let ports = port_spec_from_options();
    let rate = rate_from_options();
    let max_output = 100 * 1024 * 1024usize;

    let host_count = crate::utils::subnet_host_count(cidr);
    let est_secs = host_count
        .saturating_div(u128::from(rate.max(1)))
        .saturating_add(30)
        .min(u64::MAX as u128) as u64;
    let wall_timeout = Duration::from_secs(est_secs.saturating_mul(4).min(3600));

    crate::mprintln!(
        "[*] prescan: {:?} → {} ports={} rate={}pps wall_timeout={}s",
        tool, cidr, ports, rate, wall_timeout.as_secs()
    );

    let cmd = match tool {
        Prescan::Masscan => masscan_cmd(cidr, &ports, rate),
        Prescan::Zmap => zmap_cmd(cidr, &ports, rate),
        Prescan::None => unreachable!("prescan::None handled above"),
    };

    // The wall-clock timeout is enforced *inside* run_capture_lines so it can
    // explicitly kill the (root-privileged) child before returning. Wrapping
    // the future in tokio::time::timeout here would merely drop the future on
    // timeout; even with kill_on_drop that races the orphan-cleanup against
    // network traffic, so we kill explicitly instead.
    match run_capture_lines(cmd, tool, max_output, wall_timeout).await {
        Ok(CaptureResult::Completed(ips)) => Ok(ips),
        Ok(CaptureResult::TimedOut) => {
            // Distinguishable from a genuine empty result: a timeout means the
            // scan never finished, so callers should fall back to per-IP
            // fan-out rather than trust an empty live-host list.
            crate::meprintln!(
                "[!] prescan timed out after {}s (child killed) — falling back to per-IP fan-out.",
                wall_timeout.as_secs()
            );
            Ok(Vec::new())
        }
        Err(e) => Err(e.context("prescan tool exited with error")),
    }
}

/// Outcome of a capture run. `TimedOut` is kept distinct from
/// `Completed(vec![])` so the caller can tell "scan hit the wall clock and was
/// killed" apart from "scan finished and found nothing live".
enum CaptureResult {
    Completed(Vec<String>),
    TimedOut,
}

fn port_spec_from_options() -> String {
    let scope = crate::tenant::resolve();
    let opts = scope.global_options();
    if let Some(p) = opts.try_get("prescan_port") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(p) = opts.try_get("port").and_then(|v| v.parse::<u16>().ok()) {
        return p.to_string();
    }
    DEFAULT_PRESCAN_PORTS.to_string()
}

fn rate_from_options() -> u32 {
    crate::tenant::resolve()
        .global_options()
        .try_get("prescan_rate")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_PRESCAN_RATE)
}

fn masscan_cmd(cidr: &IpNetwork, ports: &str, rate: u32) -> Command {
    // `--open-only` skips closed/filtered host reports, `-oG -` writes
    // grepable output to stdout (one finding per line), `--wait 0` ends
    // immediately after the last packet's window closes.
    let mut cmd = Command::new("masscan");
    cmd.arg(cidr.to_string())
        .args(["-p", ports])
        .args(["--rate", &rate.to_string()])
        .arg("--open-only")
        .args(["-oG", "-"])
        .args(["--wait", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Without this, dropping the future on the wall-clock timeout path
        // leaves a root-privileged SYN flooder running orphaned at `--rate`
        // pps. kill_on_drop ensures the child dies with the future.
        .kill_on_drop(true);
    cmd
}

fn zmap_cmd(cidr: &IpNetwork, ports: &str, rate: u32) -> Command {
    // zmap's port flag is comma-separated `-p`; output IPs to stdout.
    let mut cmd = Command::new("zmap");
    cmd.arg(cidr.to_string())
        .args(["-p", ports])
        .args(["-r", &rate.to_string()])
        .args(["-o", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // See masscan_cmd: kill the orphaned root scanner when the capturing
        // future is dropped (e.g. wall-clock timeout).
        .kill_on_drop(true);
    cmd
}

/// Run the prescan command, capture stdout, parse out live IPs. Bounded by
/// `max_output` so a misconfigured run can't OOM us, and by `wall_timeout` so
/// a hung/misconfigured tool can't run forever. The wall-clock timeout is
/// enforced here (rather than via an outer tokio::time::timeout) so we own the
/// `Child` and can explicitly kill the root-privileged scanner before
/// returning, instead of relying on the future being dropped.
async fn run_capture_lines(
    mut cmd: Command,
    tool: Prescan,
    max_output: usize,
    wall_timeout: Duration,
) -> Result<CaptureResult> {
    let mut child = cmd.spawn().context("spawn prescan tool")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("prescan stdout missing"))?;
    let mut reader = BufReader::new(stdout).lines();

    let mut ips: Vec<String> = Vec::new();
    let mut bytes_seen = 0usize;
    let mut truncated = false;
    let mut timed_out = false;

    // Drive the read loop under the wall-clock deadline. tokio::time::timeout
    // around the whole loop lets us break out and kill the child explicitly.
    let read_loop = async {
        while let Some(line) = reader.next_line().await.context("read prescan line")? {
            bytes_seen = bytes_seen.saturating_add(line.len() + 1);
            if bytes_seen > max_output {
                crate::meprintln!(
                    "[!] prescan output exceeded {} MiB — truncating.",
                    max_output / (1024 * 1024)
                );
                truncated = true;
                break;
            }
            if let Some(ip) = parse_line(tool, &line) {
                ips.push(ip);
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    match tokio::time::timeout(wall_timeout, read_loop).await {
        Ok(res) => res?,
        Err(elapsed) => {
            tracing::trace!("prescan read loop hit wall_timeout: {elapsed}");
            timed_out = true;
        }
    }

    // On the timeout *or* output-cap truncation path the child is still
    // running (a misconfigured root scanner spewing output / SYNs at `--rate`
    // pps). Explicitly start_kill() it, then reap with wait() so it cannot
    // survive as an orphaned packet-blaster after rustsploit moves on.
    if timed_out || truncated {
        if let Err(e) = child.start_kill() {
            // An already-exited child is fine; anything else is worth a
            // breadcrumb so a failed kill of a packet-blasting scanner is not
            // silently ignored.
            tracing::debug!("prescan: start_kill on timed-out/truncated child failed: {e}");
        }
        // Reap the killed child so it doesn't linger as a zombie; the kill
        // signal makes this return promptly. kill_on_drop is also set as a
        // belt-and-braces backstop on any early-return paths above.
        if let Err(e) = child.wait().await {
            tracing::debug!("prescan: reaping killed child failed: {e}");
        }
        if timed_out {
            return Ok(CaptureResult::TimedOut);
        }
        // Truncated: return the partial live-host list we did manage to read.
        ips.sort();
        ips.dedup();
        crate::mprintln!(
            "[+] prescan: {} live host{} discovered (output truncated).",
            ips.len(),
            if ips.len() == 1 { "" } else { "s" }
        );
        return Ok(CaptureResult::Completed(ips));
    }

    // Capture stderr before waiting for exit
    let stderr_output = if let Some(mut stderr) = child.stderr.take() {
        let mut err_buf = String::new();
        use tokio::io::AsyncReadExt;
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stderr.read_to_string(&mut err_buf),
        ).await {
            Ok(Ok(n)) => tracing::trace!("Read {} bytes from prescan stderr", n),
            Ok(Err(e)) => tracing::trace!("stderr read error: {e}"),
            Err(e) => tracing::trace!("stderr read timed out: {e}"),
        }
        err_buf
    } else {
        String::new()
    };

    let status = child.wait().await.context("wait for prescan")?;
    if !status.success() {
        let stderr_msg = if stderr_output.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", stderr_output.trim())
        };
        anyhow::bail!("prescan exit status {:?}{}", status.code(), stderr_msg);
    }

    // De-dupe: masscan with multiple ports can emit the same IP twice.
    ips.sort();
    ips.dedup();
    crate::mprintln!(
        "[+] prescan: {} live host{} discovered.",
        ips.len(),
        if ips.len() == 1 { "" } else { "s" }
    );
    Ok(CaptureResult::Completed(ips))
}

fn parse_line(tool: Prescan, line: &str) -> Option<String> {
    match tool {
        Prescan::None => None,
        Prescan::Masscan => parse_masscan_grepable(line),
        Prescan::Zmap => parse_zmap_line(line),
    }
}

/// masscan -oG format: `Host: 1.2.3.4 ()    Ports: 80/open/tcp//http//`
fn parse_masscan_grepable(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with("Host:") {
        return None;
    }
    let rest = &trimmed[5..].trim_start();
    let ip_end = rest
        .find(|c: char| c.is_whitespace() || c == '(')
        .unwrap_or(rest.len());
    let ip = &rest[..ip_end];
    if ip.is_empty() {
        None
    } else {
        Some(ip.to_string())
    }
}

/// zmap `-o -` writes one IP per line (when no `--output-fields` override).
fn parse_zmap_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

