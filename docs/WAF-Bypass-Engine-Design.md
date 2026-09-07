# WAF Bypass Engine — As-Built Reference

> **Status: shipped.** Designed 2026-07-01; implemented in `src/utils/waf_bypass/`
> and wired into the framework HTTP layer (`src/utils/network.rs`). The original
> architecture plan is retained below with the as-built deltas marked; the
> shipped engine goes beyond the plan (12 techniques vs the planned 8).

### Overview

A framework-level WAF bypass mode that every HTTP/HTTPS module benefits from.
When enabled via `setg waf_bypass true`, HTTP requests that come back blocked
(403/406/429/503 or a WAF block-page signature) are automatically retried
through the bypass engine — techniques run in sequence until one succeeds or
the retry budget is exhausted. Individual modules do not implement bypass
logic; the retry wrapper lives in `src/utils/network.rs` and delegates to
`crate::utils::waf_bypass::send_with_bypass(...)`.

### Configuration (`setg` options)

```
setg waf_bypass true          # Enable framework-level WAF bypass
setg waf_bypass_mode adaptive # adaptive | exhaustive | incremental (as-built; the plan's `manual` became `incremental`)
setg waf_bypass_retries 5     # Max retries per technique (default: 2)
setg waf_bypass_timeout 10    # Per-retry timeout in seconds
setg waf_bypass_techniques "get_body,encoding,method_override,chunked"  # Which techniques to try
```

`WafBypassConfig::from_global_options()` reads these keys; the retry wrapper
in `src/utils/network.rs` applies the config transparently when `waf_bypass`
is on.

### Architecture

```
┌─────────────────────────────────────────────────┐
│                 Module (any HTTP exploit)        │
│  request = build_http_request(url, payload)      │
│  response = http_client.send(request)            │
│                      │                           │
│                      ▼                           │
│  ┌──────────────────────────────────────┐        │
│  │       WAF Bypass Engine              │        │
│  │  (if setg waf_bypass = true)         │        │
│  │                                      │        │
│  │  ┌──────────────────────────────┐    │        │
│  │  │ Technique 1: GET Body Smuggle│    │        │
│  │  │ - Convert POST→GET           │    │        │
│  │  │ - Move payload to body       │    │        │
│  │  │ - Add random body padding    │    │        │
│  │  └──────────┬───────────────────┘    │        │
│  │             │ response blocked?      │        │
│  │             ▼ yes                    │        │
│  │  ┌──────────────────────────────┐    │        │
│  │  │ Technique 2: Encoding Bypass │    │        │
│  │  │ - URL-encode payload         │    │        │
│  │  │ - Double URL-encode          │    │        │
│  │  │ - Unicode normalize          │    │        │
│  │  │ - Base64 wrap                │    │        │
│  │  └──────────┬───────────────────┘    │        │
│  │             │ response blocked?      │        │
│  │             ▼ yes                    │        │
│  │  ┌──────────────────────────────┐    │        │
│  │  │ Technique 3: Method Override │    │        │
│  │  │ - X-HTTP-Method-Override     │    │        │
│  │  │ - X-HTTP-Method              │    │        │
│  │  │ - X-Method-Override          │    │        │
│  │  │ - _method=POST parameter     │    │        │
│  │  └──────────┬───────────────────┘    │        │
│  │             │ response blocked?      │        │
│  │             ▼ yes                    │        │
│  │  ┌──────────────────────────────┐    │        │
│  │  │ Technique 4: Chunked TE      │    │        │
│  │  │ - Split payload across chunks│    │        │
│  │  │ - Add chunk extensions       │    │        │
│  │  │ - Vary chunk sizes           │    │        │
│  │  └──────────┬───────────────────┘    │        │
│  │             │ response blocked?      │        │
│  │             ▼ yes                    │        │
│  │  ┌──────────────────────────────┐    │        │
│  │  │ Technique 5: Header Smuggle  │    │        │
│  │  │ - Move payload to header     │    │        │
│  │  │ - Content-Type confusion     │    │        │
│  │  │ - Accept-Encoding bypass     │    │        │
│  │  └──────────┬───────────────────┘    │        │
│  │             │ response blocked?      │        │
│  │             ▼ yes                    │        │
│  │  ┌──────────────────────────────┐    │        │
│  │  │ Technique 6: Param Pollution │    │        │
│  │  │ - Duplicate parameters       │    │        │
│  │  │ - Array notation (param[])   │    │        │
│  │  │ - JSON/XML content-type swap │    │        │
│  │  └──────────┬───────────────────┘    │        │
│  │             │                        │        │
│  │             ▼ response OK!           │        │
│  │  ┌──────────────────────────────┐    │        │
│  │  │ Return bypassed response     │    │        │
│  │  └──────────────────────────────┘    │        │
│  └──────────────────────────────────────┘        │
└─────────────────────────────────────────────────┘
```

### Bypass Techniques Catalog

#### Technique 1: GET Body Smuggling (CVE-2024-56523)
- **What**: Convert POST to GET, place payload in request body
- **Why**: Radware and some other WAFs skip body inspection on GET
- **Implementation**:
  - Change method from POST to GET
  - Keep Content-Type and Content-Length headers
  - Add random padding bytes to body
  - Resend request
- **Detection**: Response differs from 403/406/block page

#### Technique 2: Encoding Obfuscation (CVE-2024-56524)
- **What**: Encode payload to bypass pattern-matching filters
- **Variants**:
  - Single URL-encode: `'` → `%27`
  - Double URL-encode: `'` → `%2527`
  - Unicode normalize: `'` → `%u0027`
  - Base64 wrap: Wrap entire payload
  - HTML entity: `'` → `&#39;`
  - Mixed encoding: Alternate encoding per character
- **Detection**: Response contains expected app behavior (not block page)

#### Technique 3: HTTP Method Override
- **What**: Use alternative HTTP methods/headers to bypass method-based restrictions
- **Headers to try**:
  - `X-HTTP-Method-Override: POST`
  - `X-HTTP-Method: POST`
  - `X-Method-Override: POST`
- **Query params**: `?_method=POST`
- **Detection**: Response from actual endpoint (not 405)

#### Technique 4: Transfer-Encoding Chunked
- **What**: Split request body across chunks to confuse WAF parsing
- **Implementation**:
  - Add `Transfer-Encoding: chunked` header
  - Split payload into 4-8 byte chunks
  - Add chunk extensions (`;comment=bypass`)
  - Vary chunk sizes between retries
- **Detection**: Response from backend (not 411/501)

#### Technique 5: Header Smuggling
- **What**: Place attack payload in HTTP headers instead of body/URL
- **Headers**: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, `Referer`
- **Detection**: Response indicates payload was processed

#### Technique 6: Parameter Pollution
- **What**: Duplicate/split parameters to confuse parsing
- **Patterns**:
  - `?id=1&id=1' OR '1'='1`
  - `?id[]=1&id[]=1' OR '1'='1`
  - `?id=1&id=1'+OR+'1'='1`
- **Detection**: Response from backend (not parameter error)

#### Technique 7: Content-Type Confusion
- **What**: Change Content-Type to bypass format-specific filters
- **Types**: `application/json`, `text/xml`, `multipart/form-data`
- **Implementation**: Wrap payload in format-appropriate syntax
- **Detection**: Response from backend

#### Technique 8: Case / Whitespace Manipulation
- **What**: Vary case and whitespace in payload keywords
- **Patterns**: `SeLeCt`, `UNION/**/SELECT`, `or 1=1`
- **Detection**: Response from backend (not 403)

### Detection Logic (How we know if bypass worked)

The engine determines success/failure by analyzing responses:
```rust
enum BypassResult {
    /// Payload reached backend and returned expected response
    Success(reqwest::Response),
    /// WAF blocked the request (403, 406, block page detected)
    Blocked { status: u16, reason: String },
    /// Network error (timeout, connection refused)
    Error(String),
    /// Unknown — response doesn't clearly indicate block or success
    Unknown(reqwest::Response),
}

As built, detection returns a `BypassOutcome` from `engine.rs`; status-code
checks (403/406/429/503) run first, then bounded body-signature reads via the
framework's capped-read helpers (never an unbounded `text().unwrap_or_default()`
— that sample predates the BAD_PATTERNS A3 rule and is illustrative only).
Block-page signatures cover the major vendors (Radware, Cloudflare, Akamai,
Imperva, F5, ModSecurity, NAXSI, Wallarm).
```

### Integration Points

#### 1. `src/utils/network.rs` — as-built integration

The HTTP request helper checks `setg waf_bypass`; when enabled it routes
through the engine:

```rust
use crate::utils::waf_bypass;

let config = waf_bypass::WafBypassConfig::from_global_options().await;
let outcome = waf_bypass::send_with_bypass(client, method, url, headers, body, &config).await?;
```

Blocked responses (403/406/429/503 or block-page signatures) trigger the
technique loop; the first non-blocked response wins. Modules need zero
changes when `waf_bypass` is off.

#### 2. `src/utils/waf_bypass/config.rs` — as-built
```rust
pub struct WafBypassConfig { /* enabled, mode, retries, timeout_secs, techniques, … */ }
pub enum BypassMode { Adaptive, Exhaustive, Incremental }
```
`WafBypassConfig::from_global_options()` hydrates the struct from `setg` values.

#### 3. `setg` integration
```
setg waf_bypass true
setg waf_bypass_mode adaptive   # Stops after first success
setg waf_bypass_techniques get_body,encoding,method_override
```

### File structure (as-built)

```
src/utils/waf_bypass/
  mod.rs            # Module declarations + re-exports
  engine.rs         # send_with_bypass loop, BypassOutcome
  config.rs         # WafBypassConfig, BypassMode
  detection.rs      # Block detection (status codes + body signatures)
  signatures.rs     # WAF fingerprint DB (vendor -> preferred techniques)
  techniques/
    get_body.rs, encoding.rs, method_override.rs, chunked.rs,
    header_smuggle.rs, param_pollution.rs, content_type.rs,
    case_whitespace.rs,        # plan's "case_manipulation"
    origin_bypass.rs,          # beyond plan: CDN/origin routing bypass
    protocol.rs,               # beyond plan: HTTP version/protocol abuse
    websocket.rs               # beyond plan: WebSocket path bypass
```

### Module Adoption (how existing modules use it)

**Option A — Transparent (recommended)**
Modify `build_http_client()` to accept a `WafBypassConfig`. When bypass is enabled, all HTTP calls automatically go through the bypass engine. Zero module changes needed.

```rust
// In build_http_client:
pub fn build_http_client(timeout: Duration) -> Result<reqwest::Client> {
    // ... existing code ...
    // WAF bypass is transparent — the client intercepts responses
    // and retries with bypass techniques automatically
    if global_options().get_bool("waf_bypass") {
        client = client.with_bypass_engine(global_options().into());
    }
}
```

**Option B — Explicit opt-in**
Modules call `http_request_with_bypass()` instead of `client.send()`. Requires module changes but preserves control.

```rust
// In exploit module:
if ctx.options.get_or("waf_bypass", false) {
    response = crate::utils::http_request_with_bypass(
        &client, Method::POST, &url, headers, Some(body), &bypass_config
    ).await?;
} else {
    response = client.post(&url).headers(headers).body(body).send().await?;
}
```

### Detection Signatures Database

The engine includes a built-in WAF fingerprint database to identify which WAF it's dealing with and select optimal bypass techniques:

```rust
const WAF_SIGNATURES: &[(&str, &[BypassTechnique])] = &[
    ("Radware",     &[GET_BODY, ENCODING, HEADER_SMUGGLE]),  // CVE-2024-56523/56524
    ("Cloudflare",  &[ENCODING, PARAM_POLLUTION, CHUNKED]),
    ("Akamai",      &[METHOD_OVERRIDE, CASE_MANIPULATION]),
    ("Imperva",     &[GET_BODY, ENCODING]),
    ("F5 BIG-IP",   &[HEADER_SMUGGLE, CHUNKED]),
    ("ModSecurity", &[ENCODING, CASE_MANIPULATION, PARAM_POLLUTION]),
    ("Shieldsquare",&[GET_BODY, HEADER_SMUGGLE]),  // Bot detection, not WAF
];
```

### Testing

1. Unit tests for each bypass technique against mock WAF responses
2. Integration test: local nginx + ModSecurity → verify bypass works
3. Live test only against targets you are **authorized** to test — never third-party origins
4. Regression test: existing modules unchanged when `waf_bypass=false`

### Implementation status

Shipped (see file structure above): core engine, detection, signatures DB,
all 12 techniques, `network.rs` integration, and the `setg` option family.
Remaining follow-ups are tracked in [Roadmap.md](Roadmap.md).
