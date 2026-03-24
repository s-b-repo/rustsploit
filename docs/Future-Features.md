# Future Features Roadmap

Rustsploit is under active development. Below are some of the major features planned for upcoming releases.

## 1. 3rd-Party Plugin System
We plan to introduce a `plugins/` directory to allow users to drop in custom, pre-compiled modules or scripts without modifying the core Rustsploit source code. 
- **Goal:** Enable a vibrant community ecosystem of custom exploits and scanners.
- **Implementation:** Likely utilizing  library loading (`.rs) 

## 2. Instant Configuration Loading
Currently, modules are configured interactively or via API JSON payloads. We plan to add support for instantly loading configuration profiles from disk.
- **Goal:** Allow users to save their favorite scan parameters (wordlists, threads, timeouts) to a `.toml` or `.yaml` file and load them instantly.
- **Usage Idea:** `run exploits/tomcat_rce --config profiles/aggressive.toml` or `set config profiles/aggressive.toml` in the shell.

## 3. Dynamic Source Port Modification
While we currently support advanced networking like IP spoofing in specific flood modules, we plan to bring dynamic source port control to the framework level.
- **Goal:** Allow scanners and exploit modules to bind to specific source ports (e.g., source port 53) to bypass poorly configured firewalls that trust traffic originating from privileged ports.
- **Implementation:** Extending the global configuration and socket helpers to accept an optional `bind_port` parameter.

---

*If you'd like to contribute to any of these features, please check out the [Contributing Guide](Contributing.md) and open a pull request!*
