Hardened rtsp_bruteforce_advanced by validating path, username, and password wordlists before spinning up tasks, and by falling back to a safe root path when a path list is empty to avoid runtime panics.

Added identical early-exit checks and trimming for the SSH brute-force runner so it fails fast when wordlists are empty instead of silently doing nothing.

Brought the FTP brute-force helper in line with the others by trimming entries, rejecting empty wordlists, and ensuring helper utilities only return meaningful credentials.


Proxy Improvements

Refined proxy loading to validate schemes/hosts/ports, capture parse errors, and expose optional connectivity testing via utils::load_proxies_from_file and utils::test_proxies, keeping only working entries when requested.

Enhanced shell commands: proxy_load now prompts for a path when omitted, reports skipped entries, offers a recommended “test proxies” prompt, and added a dedicated proxy_test command plus reusable prompt helpers.

Implemented interactive proxy-test workflow that gathers URL/timeouts/concurrency, filters failing proxies, and auto-disables proxy mode when none survive.


Shell UX Refresh
Reworked command parsing to support ergonomic aliases (help/h/?, modules/ls/m, find/f1, proxy_load/pl, etc.) and keep everything case-insensitive and whitespace tolerant.

Added a richer, colorized help palette that lists shortcuts and usage tips so “f1 ssh” style workflows are obvious.

Introduced helpers (split_command, resolve_command) to drive the new UX without changing existing behavior, plus guarded prompt utilities already in place.


README Refresh

Rebuilt the README into a professional GitHub-ready document with a TOC, feature highlights, module catalog summary, quick start commands, shell walkthrough (including the new shortcuts), CLI usage, proxy workflow, module discovery flow, and contributing/credits notes.

README Suite Updated

README.md already reflects the full feature set; no further changes needed.
docs/readme.md rewritten into a comprehensive developer guide covering architecture, module discovery, shell internals, proxy system, authoring practices, and roadmap items.
lists/readme.md expanded to document shipped wordlists, usage guidelines, and contribution notes so operators know how data files tie into modules.

Pingsweep.rs 

improved and reworked



