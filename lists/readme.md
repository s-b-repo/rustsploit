# 📚 Rustsploit Data Files

This directory contains reference lists and helper payloads consumed by modules under `src/modules/**`. Keep this README up to date whenever a new list is added so operators understand the expected format and typical usage.

---

## Available Files

| File | Used By | Description |
|------|---------|-------------|
| `rtsp-paths.txt` | `creds/generic/rtsp_bruteforce_advanced.rs` | Candidate RTSP paths to brute force when enumerating stream URLs (e.g., `/live.sdp`, `/Streaming/channels/101`). One entry per line; comments can be added with `#` at the start of a line. |
| `rtsphead.txt` | `creds/generic/rtsp_bruteforce_advanced.rs` | Optional RTSP header templates. When the user enables “advanced headers,” the module loads this file and injects each header line into outbound requests. Keep headers in `Key: Value` form. |

---

## Contributing Lists

1. **Naming:** Use lowercase and hyphens (`my-new-list.txt`) to remain compatible across platforms.
2. **Format:** Prefer plain UTF-8 text. Comment lines should start with `#` or `//` so loaders can skip them.
3. **Documentation:** Update this README with a row describing the file, the consuming module, and expected contents.
4. **Usage in modules:** Reference lists with relative paths or prompt the user for the filename. Most modules expect the user to supply the path (allowing custom lists), but shipping defaults in this directory helps bootstrap new users.
5. **Attribution:** If a list leverages community sources (e.g., SecLists), note that in the table and ensure licenses permit redistribution.

---

## Ideas for Future Lists

- `ftp-default-creds.txt` for anonymous login checks
- `telnet-banners.txt` to fingerprint devices before brute forcing
- `http-admin-panels.txt` for web interface discovery scanners
- Vendor-specific RTSP or ONVIF endpoint lists

Pull requests welcome—please include both the data file and an entry here. !*** End Patch
