// OSINT (Open-Source Intelligence) modules.
//
// Reconnaissance modules that gather public information without sending
// traffic to the target itself — DNS records, certificate transparency
// logs, subdomain enumeration via public APIs, etc. These run *before*
// scanners, when you only have a domain or organisation name.
//
// Drop a `.rs` file here with `pub async fn run(target: &str) -> anyhow::Result<()>`
// and it will be auto-discovered at build time.

pub mod cert_transparency;
