# Security Policy

## Reporting a vulnerability

RustSploit is an offensive-security framework. It deliberately contains
exploit code, credential handling, and network attack surfaces — that is the
product, not a bug. Reports about "the tool does what an attacker wants it to
do" are not vulnerabilities.

A report **is** in scope when it describes a defect that lets someone do
something they should not be able to do:

| In scope | Out of scope |
| --- | --- |
| A remote code execution path in the **RustSploit host** reachable through the API, MCP server, or WebSocket surface | The exploit payloads a module sends to a *target* host |
| A bypass of the PQ-encrypted API's authentication, authorization, or tenant isolation | Modules that brute-force or exploit the operator's chosen target |
| A server-side path traversal, arbitrary file read, or arbitrary file write driven by API/MCP input | Modules that write files the operator explicitly asked for |
| SSRF in the framework's own HTTP clients that lets a *client* reach an address the framework blocks (metadata, loopback, link-local) | Modules that scan RFC1918 ranges when the operator asked for them |
| A credential, key, or token written to disk with permissions that let another local user read it | A credential the operator chose to put in a world-readable location themselves |
| A panic, unbounded allocation, or deadlock reachable from untrusted input that takes the server down | A module that hangs against a hostile *target* |

## Where to send it

Use GitHub's private vulnerability reporting for this repository
(**Security → Report a vulnerability**). Please do not open a public issue
for a vulnerability that has not been triaged.

Include:

- the affected version (or commit SHA),
- the API/MCP call or CLI command that reproduces it,
- the expected vs. actual behaviour,
- your environment (OS, Rust version, whether the `io_uring` or `bluetooth`
  features were enabled).

## What to expect

- **Acknowledgement:** within 72 hours.
- **Triage:** within 7 days — either a fix, a mitigation, or an explanation of
  why the report is out of scope.
- **Fix:** critical/high findings are prioritised for the next release. The
  release notes are generated from the commit log, and any advisory that needs
  operator action is published as a release note fragment in
  `changelogs/fragments/`.

## Operational notes for operators

- The API server prints a **one-time enrollment token** on startup. That token
  grants full access to every enrolled client. Treat it like a root password.
- The enrollment token is **single-use**. A new one is minted on every server
  start, so restarting the daemon and enrolling a new client is a routine
  operator action — and any client that has been enrolled keeps its access
  until its key is revoked.
- `POST /api/pq/revoke-key` removes a client and kills its live sessions.
  There is no separate admin role: **every enrolled client can revoke every
  other client**, so treat the set of enrolled clients as a set of peers with
  equivalent power.
- Client names are case-sensitive and are used as on-disk directory names
  under `~/.rustsploit/tenants/`. Two clients whose names differ only in case
  are two separate tenants.
- Run the API server bound to a loopback address unless you have a specific
  reason not to. It is an offensive tool with unrestricted network capability
  by design.
