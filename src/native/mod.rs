pub mod rdp;
pub mod payload_engine;
pub mod obfuscator_engine;

// Vendored native libraries — maintained in-tree replacements for unmaintained crates.
pub mod hex;
pub mod url_encoding;
pub mod async_tls;

// Shared low-level FFI helpers (raw sockets, ...).
pub mod network;

// Shared raw-packet DoS infrastructure (FastRng, Internet checksum).
pub mod dos_utils;
