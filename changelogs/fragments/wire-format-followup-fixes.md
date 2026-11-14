# Wire-format correctness fixes

Follow-up fixes to the v0.5.x Bluetooth and framework-import work:

- **OBEX PUT frames the final body chunk correctly.** `put_file` sent the last
  fragment as a bare End-of-Body id followed by raw bytes, with no 2-byte length
  prefix — a spec-compliant OBEX server would mis-frame the upload. End-of-Body
  (`0x49`) is a length-prefixed byte-sequence header like Body (IrOBEX §2.1) and
  is now framed the same way.
- **HCI Inquiry Result decodes Class-of-Device correctly.** The standard
  (non-extended) Inquiry Result event read the 3-octet Class_of_Device
  big-endian; it is little-endian on the wire, so device classes were reported
  byte-reversed. (The Extended Inquiry Result path was fixed in the same pass.)
- **Metasploit template import.** The `DefaultOptions` RPORT reader now handles a
  brace-wrapped value (`{ 'RPORT' => 8080 }`), and `RHOST`/`RHOSTS` no longer
  produce a duplicate `target` option (the shorter name matched the longer one
  as a prefix).
