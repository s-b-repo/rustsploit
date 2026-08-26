// Third-party and framework-bridge plugin modules.
// Place .rs files here with `pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome>`.
// They will be auto-discovered at build time via `register_native_module!`.
//
// Framework translators:
//   - msf_translator: Metasploit .rb → RustSploit native
//   - (future) empire_translator, cobaltstrike_translator, nuclei_translator
//
// WARNING: Third-party plugins are NOT reviewed or endorsed by the RustSploit project.

pub mod api_health_check;
pub mod arcticfox_bridge;
pub mod msf_translator;
pub mod sample_plugin;
