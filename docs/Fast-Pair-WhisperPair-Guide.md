# Fast Pair / WhisperPair Exploitation Guide (`exploits/bluetooth/wpair`)

> **Authorized testing only.** WhisperPair force-pairs Bluetooth audio
> accessories without the owner's consent and can expose the microphone. Only
> run it against devices you own or are explicitly authorized to test. The
> rustsploit project ships this as a defensive/research capability for the
> publicly disclosed **CVE-2025-36911** (KU Leuven COSIC).

## What it is

WhisperPair is a pairing-mode-bypass affecting many vendors' Google Fast Pair
firmware (Sony, Jabra, JBL, Bose, Pixel Buds, Nothing, OnePlus, Soundcore,
Marshall, …). A conforming accessory should only accept a Key-Based Pairing
request while it is *discoverable*; vulnerable firmware accepts it at any time,
so an attacker in range (~10–14 m) can silently pair, seize the
microphone/controls, and — via Find Hub — track the device.

The `wpair` module implements the full Seeker (attacker) side as an interactive
BLE sub-shell.

## How the handshake works (Paper §3.3.2)

1. The Seeker generates an ephemeral **secp256r1** keypair.
2. ECDH against the Provider's **Anti-Spoofing public key** yields shared `z`;
   the session key is `K = SHA-256(z)[0..16]`.
3. The 16-byte Key-Based Pairing request `[type=0x00][flags][provider MAC 6B][salt 8B]`
   is **AES-128-ECB** encrypted with `K`.
4. The 80-byte payload `E_K(request) || seeker_public_key[64]` is written to the
   Key-Based Pairing characteristic (`FE2C1234-…`). A vulnerable Provider
   decrypts it (proving the Seeker knew the public key) and proceeds even when
   not in pairing mode.

## Requirements

- Build with the Bluetooth feature: `cargo run --features bluetooth -- -m exploits/bluetooth/wpair`
- A local BLE controller, powered on (`bluetoothctl power on`).
- Permission to drive the radio: run as root or grant `CAP_NET_RAW` to the binary.
- `bluetoothctl` on `PATH` for the `pair` / `switch` commands.

## Detection vs. full takeover

> **You do not need a key to *detect* the bug.** `testall` / `exploit` send a
> Key-Based Pairing request (flags `0x11` = INITIATE_BONDING | EXTENDED_RESPONSE)
> and classify on whether the device **accepts the write out of pairing mode** — a
> patched device rejects it at the GATT layer (insufficient auth/encryption). When
> no Anti-Spoofing key is configured, `wpair` runs a *bypass probe* with a random
> key: it still proves the vulnerability, it just can't derive the real session
> key. The Anti-Spoofing key is only required to **complete** crypto pairing
> (session key + passkey + account key). No public PoC (Python or Android) fetches
> keys from Google — there is no public endpoint; the key is supplied or captured.

## Sourcing the Anti-Spoofing public key

For a *full takeover* the attack needs the **target model's Anti-Spoofing public
key** (detection does not — see above). Google
distributes the matching *private* key only to the manufacturer, but the
*public* key is served to every Seeker (phone) so it can pair — keyed by the
24-bit model ID. The built-in device table is the **KU Leuven COSIC WhisperPair
research dataset** (~2,900 registered models with names, manufacturer, type and
Find-Hub tracking flag — embedded from `model_ids.csv` and parsed lazily); it
carries **names, not keys**, because anti-spoofing public keys are not published
in bulk anywhere. `wpair` resolves a key in this order:

1. **Operator override (most reliable):** `setg antispoofing_key <base64>` — paste
   the key for your target once. This is the recommended path for a known device
   (e.g. your own earbuds), and works even for a SteadyState target whose advert
   carries no model ID.
2. **Seed table:** a key shipped for that model ID (rare — we ship names, not keys).
3. **Google Nearby Devices metadata API:** configure a URL template and key —
   `setg gfp_metadata_url <template>` and `setg gfp_api_key <key>`. The template
   may contain `{model_id}` (6 hex digits, upper-case) and `{api_key}`.

### Obtaining a key for your test device

- Capture the metadata fetch a real Android phone makes when first pairing the
  device (the public key is in the device metadata response), or
- Configure the metadata API and run `harvest` to pull keys for the seed models,
  or
- Supply it directly with `setg antispoofing_key <base64>`.

> The 256-bit Anti-Spoofing **private** key is not brute-forceable. "Harvesting"
> means enumerating the 24-bit model-ID space against the metadata API to collect
> **public** keys — see the `harvest` command (bounded to the seed table by
> default).

## Interactive commands

| Command | Action |
|---------|--------|
| `scan` | Discover Fast Pair devices; classifies each as `PAIRING` (3-byte model ID) or `STEADY-STATE` (account-key filter — advertising but not in pairing mode, the prime target). |
| `info` | Show discovered devices with model name, chipset, state, and Anti-Spoofing-key availability. |
| `select <MAC>` | Set the current target. |
| `exploit` | Full ECDH Key-Based Pairing exploit (force-pair) on the target, then plant a passkey + account key. |
| `testall` | Non-destructive vulnerability test on every discovered device (plain KBP, ECDH-first so a vulnerable device isn't mis-reported as patched). |
| `exploitall` | Run the full exploit on every discovered device. |
| `nonce` | Conformance test §4.3 — replays identical KBP bytes; acceptance = no nonce freshness. |
| `curve` | Conformance test §4.5 — sends an off-curve public key; acceptance = no point validation. |
| `pair` | Bond via `bluetoothctl` (pair + trust + connect). |
| `rename <name>` | Write a personalized device name (Additional Data, §3.3.5) using the session key. |
| `switch` | Audio-switching attack (§5.3.3) using the planted account key. |
| `harvest` | Fetch seed-model Anti-Spoofing keys from the configured metadata API. |
| `help` / `quit` | — |

## Global options

| Option | Example | Effect |
|--------|---------|--------|
| `target_mac` | `setg target_mac AA:BB:CC:DD:EE:FF` | Target a single device. |
| `adapter` | `setg adapter 1` | BLE adapter index (multi-controller hosts). |
| `scan_secs` | `setg scan_secs 20` | Scan window, clamped 3–300 s. |
| `model_id` | `setg model_id 0x0582FD` | Model ID when the advert doesn't carry one (SteadyState). |
| `antispoofing_key` | `setg antispoofing_key <base64>` | Provider Anti-Spoofing public key. |
| `gfp_metadata_url` | `setg gfp_metadata_url https://…/{model_id}?key={api_key}` | Metadata API URL template. |
| `gfp_api_key` | `setg gfp_api_key <key>` | Metadata API key. |

## Hardware runbook (e.g. your own earbuds)

1. `cargo run --features bluetooth -- -m exploits/bluetooth/wpair`
2. Put the earbuds in their case / out of pairing mode (to prove the *bypass* —
   they should be advertising the account-key filter, i.e. SteadyState).
3. `scan` → note the MAC and whether it shows `STEADY-STATE`.
4. `select <MAC>` then `testall` — this **detects** the bypass with no key (it
   classifies on whether the device accepts the KBP write out of pairing mode).
5. For a **full takeover**, provide the key — `setg antispoofing_key <base64>`
   (for a SteadyState target `wpair` also reads the model ID over GATT) — then
   `exploit`. It derives the session key, plants a passkey + account key, stores
   them to loot, and prints `VULNERABLE … CVE-2025-36911`; `pair` then completes
   OS-level bonding.
6. Run `nonce` and `curve` to record the conformance results.

> The protocol details are verified against the public Fast Pair spec and two
> reference PoCs (Python + Android): characteristic UUIDs (`fe2c1233`-`fe2c1238`),
> the canonical request flags (`0x11`), and the Additional-Data
> HMAC-SHA256 + Fast-Pair-AES-CTR construction. The deterministic core (ECDH,
> AES-128, the KBP/passkey/account-key/Additional-Data builders) was validated
> during development against standard test vectors (FIPS-197 AES, RFC-4231 HMAC,
> ECDH symmetry). The connect path retries with backoff and a 10 s timeout; the
> live GATT behaviour still depends on your adapter and target firmware — report
> anything that misbehaves against your hardware.

## References

- CVE-2025-36911 — <https://nvd.nist.gov/vuln/detail/CVE-2025-36911>
- WhisperPair — <https://whisperpair.eu/>
- Fast Pair Provider spec — <https://developers.google.com/nearby/fast-pair/specifications/service/provider>
