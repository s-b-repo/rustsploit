//! `tommy` — Friendly Interactive Walk-through Guide
//! ===================================================
//!
//! A new-user guide to every major rustsploit feature. Pages are flipped
//! with the same keys the user already knows from a casual menu — `d`
//! (next), `a` (previous), `q` (quit). A short hint is printed on every
//! page so the user does not need to remember.
//!
//! The pages are static `&'static str` blocks so the guide costs nothing
//! at start-up and can be embedded directly in the binary.
//!
//! Hooked into the interactive shell via the `tommy` command.

use std::io::{self, BufRead, Write};

use colored::*;

/// One page in the walk-through.
struct Page {
    title: &'static str,
    body: &'static str,
}

/// All pages in display order. Edit this list to extend the guide.
const PAGES: &[Page] = &[
    Page {
        title: "Welcome",
        body: WELCOME,
    },
    Page {
        title: "1. The interactive shell",
        body: SHELL,
    },
    Page {
        title: "2. Finding the right module",
        body: FIND,
    },
    Page {
        title: "3. Setting a target",
        body: TARGET,
    },
    Page {
        title: "4. Running a module",
        body: RUN,
    },
    Page {
        title: "5. Global options (setg)",
        body: SETG,
    },
    Page {
        title: "6. Scanners",
        body: SCANNERS,
    },
    Page {
        title: "7. Credential modules",
        body: CREDS,
    },
    Page {
        title: "8. Exploit modules",
        body: EXPLOITS,
    },
    Page {
        title: "9. OSINT modules",
        body: OSINT,
    },
    Page {
        title: "10. Plugins",
        body: PLUGINS,
    },
    Page {
        title: "11. Workspace, hosts, services, notes",
        body: WORKSPACE,
    },
    Page {
        title: "12. Credential store",
        body: CRED_STORE,
    },
    Page {
        title: "13. Loot & evidence",
        body: LOOT,
    },
    Page {
        title: "14. Background jobs",
        body: JOBS,
    },
    Page {
        title: "15. Resource scripts (makerc)",
        body: RESOURCE,
    },
    Page {
        title: "16. Spool & export",
        body: SPOOL,
    },
    Page {
        title: "17. The API + MCP server",
        body: API,
    },
    Page {
        title: "18. Building & tests",
        body: BUILD,
    },
    Page {
        title: "19. Writing your own module",
        body: WRITE,
    },
    Page {
        title: "20. Good-luck",
        body: GOODLUCK,
    },
];

/// Entry point — call from the shell when the user types `tommy`.
///
/// Blocks the calling thread on `stdin` for paging input. Returns `Ok(())`
/// on a clean exit; an error from stdin propagates back to the caller so
/// the shell can decide what to do.
pub fn run_guide() -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut buf = String::new();
    let mut idx: usize = 0;
    let total = PAGES.len();

    loop {
        clear_and_render(idx, total)?;
        buf.clear();
        let n = input.read_line(&mut buf)?;
        if n == 0 {
            // EOF — treat as quit so piped input doesn't loop forever
            println!();
            println!("{} {}", "[*]".cyan(), "End of input — exiting tommy.".dimmed());
            return Ok(());
        }
        let key = buf.trim().to_ascii_lowercase();
        match key.as_str() {
            "d" | "n" | "next" | "" => {
                if idx + 1 < total {
                    idx += 1;
                } else {
                    println!("{}", "Already on the last page — press 'a' to go back or 'q' to quit.".yellow());
                    pause(&mut input, &mut buf)?;
                }
            }
            "a" | "p" | "prev" | "back" => {
                if idx > 0 {
                    idx -= 1;
                } else {
                    println!("{}", "Already on the first page — press 'd' to move forward or 'q' to quit.".yellow());
                    pause(&mut input, &mut buf)?;
                }
            }
            "q" | "quit" | "exit" => {
                println!();
                println!(
                    "{} {}",
                    "[+]".green(),
                    "You're ready to go — run `help` any time for the full reference.".bold()
                );
                println!();
                return Ok(());
            }
            "g" | "start" | "first" => idx = 0,
            "e" | "end" | "last" => idx = total - 1,
            "h" | "?" | "help" => {
                show_help_overlay();
                pause(&mut input, &mut buf)?;
            }
            other => {
                // Allow `5` / `12` to jump directly to a page number
                if let Ok(page_num) = other.parse::<usize>() {
                    if page_num >= 1 && page_num <= total {
                        idx = page_num - 1;
                        continue;
                    }
                }
                println!(
                    "{} unknown key '{}'. press 'h' for keys.",
                    "[-]".yellow(),
                    other
                );
                pause(&mut input, &mut buf)?;
            }
        }
    }
}

fn clear_and_render(idx: usize, total: usize) -> io::Result<()> {
    let mut out = io::stdout().lock();
    // ANSI clear-screen + home cursor. Works in xterm-compatible terminals;
    // if the user's terminal swallows ANSI we still scroll cleanly because
    // we re-emit the full frame.
    write!(out, "\x1b[2J\x1b[H")?;
    out.flush()?;

    let page = &PAGES[idx];
    print_banner();
    println!();
    println!(
        "  {} {} {}{} {}",
        "Page".bold(),
        format!("{}", idx + 1).cyan().bold(),
        "of ".dimmed(),
        format!("{}", total).cyan(),
        format!("— {}", page.title).bold().underline()
    );
    println!();
    println!("{}", page.body);
    println!();
    println!("{}", "  ╭─────────────────────────────────────────────────────────────────╮".dimmed());
    println!(
        "  {}  {} prev   {} next   {} quit   {} keys   {} jump to page",
        "│".dimmed(),
        "[a]".cyan().bold(),
        "[d]".cyan().bold(),
        "[q]".cyan().bold(),
        "[h]".cyan().bold(),
        "[1-N]".cyan().bold(),
    );
    println!("{}", "  ╰─────────────────────────────────────────────────────────────────╯".dimmed());
    print!("  > ");
    io::stdout().flush()?;
    Ok(())
}

fn print_banner() {
    println!("{}", BANNER.cyan());
}

fn show_help_overlay() {
    println!();
    println!("{}", "  ┌─ Navigation keys ─────────────────────────────────────────────┐".bold());
    println!(
        "  │  {}  next page          {}  previous page                  │",
        "d / n / Enter".cyan().bold(),
        "a / p".cyan().bold()
    );
    println!(
        "  │  {}            {}  jump to start / end          │",
        "q / quit".cyan().bold(),
        "g / e".cyan().bold()
    );
    println!(
        "  │  {}        skip directly to page N (e.g. 7)          │",
        "<number>".cyan().bold()
    );
    println!("{}", "  └──────────────────────────────────────────────────────────────┘".bold());
}

fn pause<R: BufRead>(input: &mut R, buf: &mut String) -> io::Result<()> {
    print!("  {} ", "press Enter to continue...".dimmed());
    io::stdout().flush()?;
    buf.clear();
    input.read_line(buf)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ASCII art + page content
// ---------------------------------------------------------------------------

const BANNER: &str = r#"
   _________________________________________________________________
  |   .---.  .---.    .--.   _____ ___  ___ _   _   __  __ ____   |
  |   \   \/   /    /  /\  | |_   _/ _ \|  \/  | | \/  \/  /  _ \ |
  |    \      /    /  /__\ |   | || | | | |\/| | |\  /\  /| | | ||
  |    /  /\  \   /  ______|   | || |_| | |  | | | |\/|\/|| |_| ||
  |   /__/  \__\ /__/      \   |_| \___/|_|  |_| |_|    |_|\___/ |
  |          tommy — the friendly rustsploit walk-through         |
  |_______________________________________________________________|
"#;

const WELCOME: &str = r#"
   Hi! I'm tommy. I'll walk you through every feature of rustsploit so
   you can move from "just installed it" to "running real engagements"
   in a few minutes.

       .--------.
       |  >_<   |   <- tommy
       |--------|
       |________|

   I'll keep things short:

       * one screen per topic
       * a command you can copy & try at the bottom of each page
       * no surprises — every step is a read-only command unless I say so

   Press {d} (or {Enter}) to start. Press {a} to step back, {q} to quit.

   If you ever forget the keys, press {h}.
"#;

const SHELL: &str = r#"
   The interactive shell is what you see right now. Launch it any time
   with:

       $ rustsploit

   You can also run modules from the command line directly (great for
   scripting) — see `rustsploit --help`.

   Useful shortcuts inside the shell:

       help          show the full command reference
       help <topic>  man-page for a single command (e.g. `help run`)
       ?             same as help
       h             same as help
       q             quit the shell
       Ctrl-C        cancel the current prompt
       Ctrl-D        send EOF (quits)
       Tab           tab-completion for commands and module paths
       Up / Down     scroll through command history

   Try this:

       help run
"#;

const FIND: &str = r#"
   There are 800+ modules. To browse:

       modules           list every loaded module
       find <keyword>    fuzzy-match the registry

   Examples:

       find synology     -> scanners/synology_dsm_disclosure
       find mikrotik     -> exploits/routers/mikrotik/...
       find tomcat       -> exploits/frameworks/apache_tomcat/...
       find ssh          -> creds/ssh_bruteforce, exploits/ssh/...

   Once you've picked one, look at its metadata:

       info exploits/webapps/plex_unclaimed_takeover

   This shows the CVE references, author, rank, and default port.

   Try this:

       find plex
"#;

const TARGET: &str = r#"
   Targets can be a single IP, a hostname, a CIDR, or a file.

       set target 192.168.1.10
       set target example.com
       set target 10.0.0.0/24
       set target file:/path/to/ips.txt
       set target 10.0.0.1,10.0.0.2,10.0.0.3   (comma list)

   To check what's set:

       show_target            (alias: st)

   To clear it:

       clear_target           (alias: ct)

   You can also set a target port that applies to every module:

       set port 8080

   Random / sweep targets are also supported. See `help mass-scan` for
   the full story.

   Try this:

       set target 127.0.0.1
       show_target
"#;

const RUN: &str = r#"
   Three steps to launch a module:

       1.   use <module_path>     (pick what to run)
       2.   show options          (see what knobs exist)
       3.   run                   (go!)

   Example:

       use scanners/port_scanner
       show options
       set port 1-1024
       run

   Module-specific options are prompted at run-time, so you don't have
   to memorise them. Just hit Enter to accept the default.

   Aliases:

       u <path>          == use <path>
       go / exec / ra    == run
       back              clear the selected module
"#;

const SETG: &str = r#"
   `setg` is the Metasploit-style "datastore" — values that persist
   across modules:

       setg port 443
       setg concurrency 64
       setg timeout 30
       setg wordlist /usr/share/wordlists/rockyou.txt
       setg honeypot_detection y

   These apply to every module that reads the same key.

   View / clear:

       show options    (alias: so)
       unsetg port     (alias: ug)

   Common useful keys:

       port            default target port
       source_port     outgoing bind port
       concurrency     parallel scans for mass targets
       timeout         per-module timeout (seconds)
       wordlist        default brute-force wordlist
       prescan         masscan / zmap / none
       verbose         y/n
"#;

const SCANNERS: &str = r#"
   Scanners are read-only. Use them first.

   Highlights:

       scanners/port_scanner
       scanners/service_scanner
       scanners/ping_sweep
       scanners/dir_brute
       scanners/synology_dsm_disclosure  <- new!
       scanners/cobaltstrike_beacon_scanner  <- new!
       scanners/ssl_scanner
       scanners/snmp_scanner
       scanners/honeypot_scanner
       scanners/cors_reflection_scanner
       scanners/security_headers_scanner

   Pipe one into the next with `&`:

       set target 10.0.0.0/24 & use scanners/port_scanner & run
                            & use scanners/service_scanner & run

   The scheduler routes every finding into the workspace, so the next
   step (exploits / creds) inherits the hosts you discovered.
"#;

const CREDS: &str = r#"
   Cred modules brute-force / spray credentials.

       creds/ftp_bruteforce
       creds/ssh_bruteforce
       creds/telnet_bruteforce
       creds/mysql_bruteforce
       creds/postgres_bruteforce
       creds/snmp_bruteforce
       creds/vnc_bruteforce
       creds/rdp_bruteforce
       creds/imap_bruteforce / pop3 / smtp
       creds/redis_bruteforce
       creds/m365_activesync_spray
       creds/h3c_oem_kvm_bruteforce
       creds/ssh_spray            (one password, many hosts)
       creds/telnet_hose          (parallel telnet drag-net)

   Wordlists default to common SecLists paths but can be set:

       setg wordlist /usr/share/wordlists/rockyou.txt

   Every successful credential lands in the credential store (see the
   next page).
"#;

const EXPLOITS: &str = r#"
   Exploit modules try to deliver a specific CVE. They are organised by
   target type:

       exploits/webapps/...        web application CVEs
       exploits/frameworks/...     tomcat, jenkins, php, mongodb, ...
       exploits/network_infra/...  cisco, citrix, fortinet, vmware, ...
       exploits/routers/...        dlink, netgear, mikrotik, tplink, ...
       exploits/cameras/...        hikvision, abus, acti, ...
       exploits/vnc/...            libvnc / tigervnc / tightvnc / x11vnc
       exploits/honeytrap/...      Cowrie, Dionaea, HoneyTrap, SNARE
       exploits/ssh/...            CVE-2024-6387 regreSSHion, ...
       exploits/voip/...           FreePBX, MagnusBilling, ...
       exploits/payloadgens/...    payload generators
       exploits/windows/...        Windows-only CVEs
       exploits/bluetooth/...      BLE (feature-gated)

   New in your tree:

       exploits/routers/mikrotik/routeros_jailbreak_cve_2023_30799
       exploits/webapps/doverfsp_fusion_authbypass
       exploits/webapps/plex_unclaimed_takeover
       exploits/webapps/redeye_c2_unauth_project
       exploits/frameworks/metasploit_pro/setup_state_bypass

   Each module ranks itself — `Excellent`, `Great`, `Normal`, ... — so
   you can prioritise.
"#;

const OSINT: &str = r#"
   OSINT modules do passive intelligence work. No traffic to the
   target.

       osint/cert_transparency    crt.sh subdomain enumeration
       osint/cname_chain          follow CNAME redirects
       osint/jwks_inspector       grab and analyse JWKS keys

   Run them when you want to map an attack surface before sending a
   single packet to the target itself.
"#;

const PLUGINS: &str = r#"
   Plugins are third-party modules. Drop a `.rs` file into
   `src/modules/plugins/` and rebuild; the build-time registry picks
   it up automatically (no manual mod.rs editing required for the
   plugin discovery path).

   See:

       sample_plugin.rs   in src/modules/plugins/

   for a 30-line template. Most operators keep client-specific or
   non-public modules here.
"#;

const WORKSPACE: &str = r#"
   The workspace tracks hosts, services, and notes for the current
   engagement:

       workspace                  show / list workspaces
       workspace acme-pentest     create or switch
       hosts                      list tracked hosts
       hosts add 10.0.0.5
       hosts delete 10.0.0.5
       services                   list tracked services
       services add 10.0.0.5 22 ssh
       notes 10.0.0.5 "uses fail2ban"

   Modules that find new hosts automatically record them — you don't
   have to add things by hand most of the time.

   Try this:

       hosts
"#;

const CRED_STORE: &str = r#"
   When a creds module hits a working login, it lands in the cred
   store:

       creds                      list all creds
       creds search admin         filter by service/user
       creds add                  add one interactively
       creds delete <id>
       creds validate <id>        re-verify the cred works
       creds invalidate <id>      mark as stale
       creds clear                drop everything (asks first)

   Persistence is JSON on disk, scoped to the current workspace.
"#;

const LOOT: &str = r#"
   Loot is everything else: dumps, screenshots, downloaded files,
   evidence.

       loot                       list all loot
       loot add <path>            add a file as loot
       loot search <keyword>
       loot delete <id>
       loot clear

   Each loot entry stores: file path, source module, host, type, and
   a free-form description. Great for end-of-engagement reporting.
"#;

const JOBS: &str = r#"
   Run a module in the background:

       run -j

   Manage the queue:

       jobs                       list background jobs
       jobs -k <id>               kill a job
       jobs clean                 forget finished jobs

   Use this when you've started a long mass scan and want to keep
   probing other things in the foreground.
"#;

const RESOURCE: &str = r#"
   Save your commands and replay them later:

       makerc /tmp/today.rc       writes the current history

   Replay any file:

       resource /tmp/today.rc

   This makes great runbooks for repeating an engagement. Pair it with
   `setg` for portable defaults.
"#;

const SPOOL: &str = r#"
   Mirror all console output to a file:

       spool /tmp/console.log     start logging
       spool off                  stop logging

   At the end of the engagement, dump everything to a report:

       export json   /tmp/engagement.json
       export csv    /tmp/findings.csv
       export summary /tmp/report.txt
"#;

const API: &str = r#"
   rustsploit also ships:

       * a REST + WebSocket API with post-quantum encrypted transport
         see `docs/API-Server.md`

       * an MCP (Model Context Protocol) server — 38 tools exposed
         over stdio for AI-assisted pentesting
         see `docs/Module-Catalog.md` + `src/mcp/`

   The API gives full CRUD over hosts, services, credentials, loot,
   and jobs. The MCP server is how you drive rustsploit from Claude
   Code or another MCP-capable agent.
"#;

const BUILD: &str = r#"
   Quick build / test recipes:

       cargo build                                  default features
       cargo build --no-default-features            no Bluetooth
       cargo build --features bluetooth             with BLE
       cargo run                                    launch the shell
       cargo test                                   run unit tests
       cargo check                                  fast compile check

   Strict patterns audit (the project's own lint matrix):

       bash scripts/audit-bad-patterns.sh

   See `docs/BAD_PATTERNS.md` for the 133-regex grep matrix every
   module must pass.
"#;

const WRITE: &str = r#"
   Adding a module is a single file + one line in the parent mod.rs:

       1. drop yourmodule.rs into src/modules/<category>/
       2. add `pub mod yourmodule;` to the category's mod.rs
       3. inside the file:

              pub fn info() -> ModuleInfo { ... }
              pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> { ... }

              crate::register_native_module!(
                  crate::module::Category::Exploits,
                  "webapps/yourmodule",
                  native
              );

   Read `src/modules/exploits/sample_exploit.rs` for a 70-line
   template, or `docs/Module-Development.md` for the full lifecycle.

   Use `cfg_prompt_default(...)` / `cfg_prompt_port(...)` to ask the
   user for runtime values — those values flow through the scheduler
   the same way `setg` values do.
"#;

const GOODLUCK: &str = r#"
   You've made it to the end. A small recap:

       * find          discover modules
       * use           pick one
       * set / setg    configure
       * run           go
       * help <cmd>    when in doubt

   Remember:

       *  every module is read-only unless its docs say otherwise
       *  the workspace keeps track of what you find — use it
       *  if you write something useful, send a PR

   Happy hunting!

       .--------.
       |  ^_^   |   <- tommy says good-luck
       |--------|
       |________|

   Press {q} to leave the guide.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_have_unique_titles() {
        let mut titles: Vec<&str> = PAGES.iter().map(|p| p.title).collect();
        titles.sort();
        let original_len = titles.len();
        titles.dedup();
        assert_eq!(titles.len(), original_len, "page titles must be unique");
    }

    #[test]
    fn every_page_has_body() {
        for p in PAGES {
            assert!(
                !p.body.trim().is_empty(),
                "page {} has empty body",
                p.title
            );
        }
    }
}
