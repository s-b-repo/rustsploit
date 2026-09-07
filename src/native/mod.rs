pub mod obfuscator_engine;
pub mod payload_engine;
pub mod rdp;

// Vendored native libraries — maintained in-tree replacements for unmaintained crates.
pub mod async_tls;
pub mod hex;
pub mod url_encoding;

// Shared low-level FFI helpers (raw sockets, ...).
pub mod network;

// Protocol I/O primitives (fd isolation, errno).
pub mod io;

// Shared raw-packet DoS infrastructure (FastRng, Internet checksum).
pub mod dos_utils;

// Shared IPv4 header construction for the raw-packet DoS modules.
pub mod ip_packet;
