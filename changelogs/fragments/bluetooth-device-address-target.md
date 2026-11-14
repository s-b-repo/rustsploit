# Bluetooth modules: a device address is a target

Bluetooth modules drive the **local** radio — they address a peer by MAC
address (`AA:BB:CC:DD:EE:FF`), not over IP. The framework now knows this:

- **A device address is a valid target.** `set target AA:BB:CC:DD:EE:FF`,
  `run -t AA:BB:CC:DD:EE:FF` and the API/WS/MCP transports all accept it
  again. It used to be rejected with *"Invalid IPv6 address format"* (five
  colons made the target parser claim it for IPv6), so the documented
  per-run Bluetooth targeting was unreachable and `setg target_mac` was the
  only working path. `blueforge`'s `run <module> <MAC>` dispatch was broken
  for the same reason.
- **`run` no longer asks a Bluetooth module for an IP address.** It offers a
  device address instead, and no longer invents a "localhost (127.0.0.1)"
  target for a module that never opens a socket.
- **A mass target is refused, not swept.** `0.0.0.0` (the operator's alias
  for the full-internet sweep) used to start a 3.6-billion-host sweep — with
  the "will probe public hosts across the whole Internet" advisory — for a
  module that only talks to the local radio. It now fails with a message that
  explains what to do instead.
Modules declare this with the new target kind:

```rust
crate::register_native_module!(Category::Exploits, "bluetooth/wpair", native, interactive, radio);
crate::register_native_module!(Category::Exploits, "bluetooth/bluffs", native, local);
```

`find` now tags those modules (`[radio]` / `[local]`) so the difference is
visible in a module listing.

Two smaller fixes came out of the same session:

- The `wpair` and `blueforge` consoles now end their session when stdin
  closes. They used to read an empty line forever and re-print the help
  millions of times, which filled the terminal (and the disk) on a piped or
  closed stdin.
- A stopped BlueZ is now reported with the fix — *"the BlueZ service is not
  reachable. Start it with `sudo systemctl enable --now bluetooth`"* — instead
  of a bare *"Unit dbus-org.bluez.service not found"*.
