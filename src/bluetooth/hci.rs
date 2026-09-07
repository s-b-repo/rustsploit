//! Raw HCI socket access (Linux, root/CAP_NET_RAW required).
//!
//! Drives the local controller directly over `AF_BLUETOOTH`/`BTPROTO_HCI`:
//! classic inquiry, connection creation, remote name, and — central to the
//! KNOB probe — `HCI_Read_Encryption_Key_Size` on an ACL handle. Commands and
//! events are codec-verified; malformed controller replies surface as errors,
//! never panics.

use std::os::unix::io::RawFd;
use std::time::Duration;

use anyhow::{Result, anyhow};
use libc::{c_int, c_void, poll, pollfd};

const BTPROTO_HCI: c_int = 1;
const BTPROTO_L2CAP: c_int = 0;
/// `HCI_CHANNEL_RAW` (shared with BlueZ).
pub const HCI_CHANNEL_RAW: u16 = 0;
/// `HCI_CHANNEL_USER` (exclusive controller takeover; BlueZ must release it).
pub const HCI_CHANNEL_USER: u16 = 1;

const HCI_COMMAND_PKT: u8 = 0x01;
const HCI_EVENT_PKT: u8 = 0x04;

// Opcodes: OGF << 10 | OCF.
const OGF_LINK_CTL: u16 = 0x01;
const OGF_INFO_PARAM: u16 = 0x04;
const OGF_STATUS_PARAM: u16 = 0x05;
const HCI_OP_INQUIRY: u16 = (OGF_LINK_CTL << 10) | 0x0001;
const HCI_OP_INQUIRY_CANCEL: u16 = (OGF_LINK_CTL << 10) | 0x0002;
const HCI_OP_CREATE_CONN: u16 = (OGF_LINK_CTL << 10) | 0x0005;
const HCI_OP_DISCONNECT: u16 = (OGF_LINK_CTL << 10) | 0x0006;
const HCI_OP_REMOTE_NAME_REQ: u16 = (OGF_LINK_CTL << 10) | 0x0019;
const HCI_OP_PIN_CODE_REPLY: u16 = (OGF_LINK_CTL << 10) | 0x000D;
const HCI_OP_AUTH_REQUESTED: u16 = (OGF_LINK_CTL << 10) | 0x0011;
const HCI_OP_IO_CAPABILITY_REPLY: u16 = (OGF_LINK_CTL << 10) | 0x002B;
const HCI_OP_USER_CONFIRM_REPLY: u16 = (OGF_LINK_CTL << 10) | 0x002C;
const HCI_OP_USER_PASSKEY_REPLY: u16 = (OGF_LINK_CTL << 10) | 0x002E;
const HCI_OP_READ_LOCAL_VERSION: u16 = (OGF_INFO_PARAM << 10) | 0x0001;
const HCI_OP_READ_ENC_KEY_SIZE: u16 = (OGF_STATUS_PARAM << 10) | 0x0008;

// LE controller opcodes (OGF 0x08).
const OGF_LE_CTL: u16 = 0x08;
const HCI_OP_LE_SET_ADV_PARAMS: u16 = (OGF_LE_CTL << 10) | 0x0006;
const HCI_OP_LE_SET_ADV_DATA: u16 = (OGF_LE_CTL << 10) | 0x0008;
const HCI_OP_LE_SET_ADV_ENABLE: u16 = (OGF_LE_CTL << 10) | 0x000A;
const HCI_OP_LE_SET_SCAN_RSP_DATA: u16 = (OGF_LE_CTL << 10) | 0x0009;

// Events.
const EVT_INQUIRY_RESULT: u8 = 0x02;
const EVT_CONN_COMPLETE: u8 = 0x03;
const EVT_REMOTE_NAME_REQ_COMPLETE: u8 = 0x07;
const EVT_PIN_CODE_REQ: u8 = 0x16;
const EVT_LINK_KEY_NOTIFY: u8 = 0x18;
const EVT_IO_CAP_REQ: u8 = 0x31;
const EVT_USER_CONFIRM_REQ: u8 = 0x33;
const EVT_AUTH_COMPLETE: u8 = 0x36;
const EVT_CMD_COMPLETE: u8 = 0x0E;
const EVT_CMD_STATUS: u8 = 0x0F;
const EVT_INQUIRY_COMPLETE: u8 = 0x01;
const EVT_INQUIRY_RESULT_WITH_RSSI: u8 = 0x22;
const EVT_EXT_INQUIRY_RESULT: u8 = 0x2F;

/// Bluetooth address (6 bytes, little-endian on the wire).
pub type BdAddr = [u8; 6];

/// An ACL connection handle + peer.
#[derive(Debug, Clone)]
pub struct AclConnection {
    pub handle: u16,
    pub bdaddr: BdAddr,
    pub encryption_key_size: Option<u8>,
}

/// A raw HCI socket bound to one controller.
pub struct HciSocket {
    fd: RawFd,
}

impl HciSocket {
    /// Open controller `dev_id` on the given channel. `HCI_CHANNEL_USER`
    /// requires BlueZ to have released the controller (`rfkill`/stop bluetooth
    /// service or use `btmgmt`), otherwise bind fails with EBUSY.
    pub fn open(dev_id: u16, channel: u16) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTPROTO_HCI,
            )
        };
        if fd < 0 {
            return Err(anyhow!(
                "opening raw HCI socket failed (need root or CAP_NET_RAW): {}",
                std::io::Error::last_os_error()
            ));
        }
        // sockaddr_hci { family: AF_BLUETOOTH, dev, channel }
        let mut sa = [0u8; 6];
        sa[0] = libc::AF_BLUETOOTH as u8;
        sa[1] = 0;
        sa[2..4].copy_from_slice(&dev_id.to_le_bytes());
        sa[4..6].copy_from_slice(&channel.to_le_bytes());
        let rc = unsafe {
            libc::bind(
                fd,
                sa.as_ptr() as *const libc::sockaddr,
                sa.len() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(anyhow!(
                "binding HCI socket to dev {dev_id} channel {channel} failed: {err} \
                 (channel USER requires BlueZ to release the controller)"
            ));
        }
        Ok(Self { fd })
    }

    /// Send an HCI command and return the payload of the matching
    /// `Command Complete`/`Command Status` event.
    pub fn command(&mut self, opcode: u16, params: &[u8], timeout: Duration) -> Result<HciEvent> {
        let mut pkt = Vec::with_capacity(3 + params.len());
        pkt.push(HCI_COMMAND_PKT);
        pkt.push((opcode & 0xFF) as u8);
        pkt.push((opcode >> 8) as u8);
        pkt.push(params.len() as u8);
        pkt.extend_from_slice(params);
        self.write_all(&pkt)?;

        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| anyhow!("HCI event timeout waiting for opcode 0x{opcode:04X}"))?;
            let ev = self.read_event(remaining)?;
            if let Some(evt) = self::matches_command(&ev, opcode) {
                return Ok(evt);
            }
        }
    }

    /// Read the next event packet, bounded by `timeout`.
    pub fn read_event(&mut self, timeout: Duration) -> Result<HciEvent> {
        // Peek the packet type first; events are `type(1) code(1) len(1) body`,
        // ACL data is `type(1) handle(2) len(1) data` and is skipped.
        let mut ptype = [0u8; 1];
        self.read_exact_bounded(&mut ptype, timeout)?;
        if ptype[0] != HCI_EVENT_PKT {
            let mut acl_hdr = [0u8; 3];
            self.read_exact_bounded(&mut acl_hdr, timeout)?;
            let mut sink = vec![0u8; acl_hdr[2] as usize];
            self.read_exact_bounded(&mut sink, timeout)?;
            return self.read_event(timeout);
        }
        let mut header = [0u8; 2];
        self.read_exact_bounded(&mut header, timeout)?;
        let mut body = vec![0u8; header[1] as usize];
        self.read_exact_bounded(&mut body, timeout)?;
        Ok(HciEvent {
            code: header[0],
            params: body,
        })
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let mut written = 0usize;
        while written < buf.len() {
            let n = unsafe {
                libc::write(
                    self.fd,
                    buf[written..].as_ptr() as *const c_void,
                    buf.len() - written,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow!("writing HCI command: {err}"));
            }
            written += n as usize;
        }
        Ok(())
    }

    fn read_exact_bounded(&mut self, buf: &mut [u8], timeout: Duration) -> Result<()> {
        let mut got = 0usize;
        while got < buf.len() {
            let mut pfd = pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let millis = timeout.as_millis() as c_int;
            let rc = unsafe { poll(&mut pfd as *mut pollfd, 1, millis.max(0)) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow!("polling HCI socket: {err}"));
            }
            if rc == 0 {
                return Err(anyhow!("HCI read timeout"));
            }
            let n =
                unsafe { libc::read(self.fd, buf[got..].as_ptr() as *mut c_void, buf.len() - got) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow!("reading HCI socket: {err}"));
            }
            if n == 0 {
                return Err(anyhow!("HCI socket closed"));
            }
            got += n as usize;
        }
        Ok(())
    }

    /// Run a Classic inquiry and collect discovered devices.
    pub fn inquiry(&mut self, duration_secs: u8, max_responses: u8) -> Result<Vec<InquiryResult>> {
        let mut params = [0u8; 5];
        params[0] = LAP_GIAC[0];
        params[1] = LAP_GIAC[1];
        params[2] = LAP_GIAC[2];
        params[3] = duration_secs;
        params[4] = max_responses;
        self.command(HCI_OP_INQUIRY, &params, Duration::from_secs(1))?;
        // Inquiry results stream as events until Inquiry Complete.
        let mut found = Vec::new();
        let deadline =
            std::time::Instant::now() + Duration::from_secs(u64::from(duration_secs) * 3 + 5);
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| anyhow!("inquiry did not complete"))?;
            let ev = self.read_event(remaining)?;
            match ev.code {
                EVT_INQUIRY_RESULT => {
                    if let Some(r) = parse_inquiry_result(&ev.params, 14) {
                        found.push(r);
                    }
                }
                EVT_INQUIRY_RESULT_WITH_RSSI => {
                    if let Some(r) = parse_inquiry_result(&ev.params, 15) {
                        found.push(r);
                    }
                }
                EVT_EXT_INQUIRY_RESULT => {
                    if let Some(r) = parse_ext_inquiry_result(&ev.params) {
                        found.push(r);
                    }
                }
                EVT_INQUIRY_COMPLETE => return Ok(found),
                _ => continue,
            }
            if found.len() >= max_responses as usize {
                if let Err(e) = self.command(HCI_OP_INQUIRY_CANCEL, &[], Duration::from_secs(2)) {
                    tracing::debug!("inquiry cancel failed: {e:#}");
                }
                return Ok(found);
            }
        }
    }

    /// Establish a Classic ACL connection (page timeout ~5s).
    pub fn create_connection(
        &mut self,
        bdaddr: &BdAddr,
        packet_type: u16,
    ) -> Result<AclConnection> {
        // Connection_Request params: bdaddr(6) packet_type(2) pscan_rep(1)
        // pscan_mode(1) clock_offset(2) allow_role_switch(1) = 13 bytes.
        let mut params = [0u8; 13];
        for (i, b) in bdaddr.iter().enumerate() {
            params[i] = *b;
        }
        params[6] = packet_type as u8;
        params[7] = (packet_type >> 8) as u8;
        // pscan modes 0, clock offset 0, allow role switch 1.
        params[12] = 0x01;
        // Command Status arrives first, then Connection Complete.
        self.command(HCI_OP_CREATE_CONN, &params, Duration::from_secs(2))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| anyhow!("connection establishment timed out"))?;
            let ev = self.read_event(remaining)?;
            if ev.code == EVT_CONN_COMPLETE && ev.params.len() >= 13 {
                let status = ev.params[0];
                if status != 0 {
                    anyhow::bail!(
                        "connection failed with HCI status 0x{status:02X} ({})",
                        hci_status_name(status)
                    );
                }
                let handle = u16::from_le_bytes([ev.params[1], ev.params[2]]);
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&ev.params[3..9]);
                return Ok(AclConnection {
                    handle,
                    bdaddr: addr,
                    encryption_key_size: None,
                });
            }
        }
    }

    /// Disconnect an ACL handle.
    pub fn disconnect(&mut self, handle: u16) -> Result<()> {
        let mut params = [0u8; 3];
        params[0..2].copy_from_slice(&handle.to_le_bytes());
        params[2] = 0x13; // Remote User Terminated Connection
        self.command(HCI_OP_DISCONNECT, &params, Duration::from_secs(3))
            .map(|_| ())
    }

    /// `HCI_Read_Encryption_Key_Size(handle)` — the KNOB probe primitive.
    /// Returns the negotiated link key entropy in bytes (1..=16).
    pub fn read_encryption_key_size(&mut self, handle: u16) -> Result<u8> {
        let mut params = [0u8; 2];
        params.copy_from_slice(&handle.to_le_bytes());
        let ev = self.command(HCI_OP_READ_ENC_KEY_SIZE, &params, Duration::from_secs(3))?;
        // Return params: status(1) | handle(2) | key_size(1).
        if ev.params.len() < 4 {
            return Err(anyhow!("short Read_Encryption_Key_Size response"));
        }
        let status = ev.params[0];
        if status != 0 {
            anyhow::bail!(
                "Read_Encryption_Key_Size failed with status 0x{status:02X} ({})",
                hci_status_name(status)
            );
        }
        Ok(ev.params[3])
    }

    /// Request the friendly remote name of a Classic device.
    pub fn remote_name(&mut self, bdaddr: &BdAddr) -> Result<String> {
        let mut params = [0u8; 10];
        for (i, b) in bdaddr.iter().enumerate() {
            params[i] = *b;
        }
        params[6] = 0x01; // page_scan_repetition_mode = R1
        self.command(HCI_OP_REMOTE_NAME_REQ, &params, Duration::from_secs(2))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| anyhow!("remote name request timed out"))?;
            let ev = self.read_event(remaining)?;
            if ev.code == EVT_REMOTE_NAME_REQ_COMPLETE && ev.params.len() >= 250 {
                let status = ev.params[0];
                if status != 0 {
                    anyhow::bail!("remote name failed: status 0x{status:02X}");
                }
                let raw = &ev.params[6..246];
                let len = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                return Ok(String::from_utf8_lossy(&raw[..len]).to_string());
            }
        }
    }

    /// Local controller version info (for inventory / capability checks).
    pub fn read_local_version(&mut self) -> Result<(u16, u16, u16)> {
        let ev = self.command(HCI_OP_READ_LOCAL_VERSION, &[], Duration::from_secs(3))?;
        // status(1) hci_ver(1) hci_rev(2) lmp_ver(1) manufacturer(2) lmp_subver(2)
        if ev.params.len() < 9 {
            return Err(anyhow!("short Read_Local_Version response"));
        }
        let lmp_ver = ev.params[4];
        let manufacturer = u16::from_le_bytes([ev.params[5], ev.params[6]]);
        let lmp_subver = u16::from_le_bytes([ev.params[7], ev.params[8]]);
        Ok((u16::from(lmp_ver), manufacturer, lmp_subver))
    }

    /// Read the next event whose code is one of `codes` (others are skipped),
    /// bounded by `timeout`.
    pub fn wait_for_event(&mut self, codes: &[u8], timeout: Duration) -> Result<HciEvent> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| anyhow!("timed out waiting for HCI events {codes:02X?}"))?;
            let ev = self.read_event(remaining)?;
            if codes.contains(&ev.code) {
                return Ok(ev);
            }
        }
    }

    /// Reply to a `PIN_Code_Request` with a legacy PIN (ASCII, ≤16 bytes).
    /// Returns once the command has been accepted (link key arrives via
    /// `Link_Key_Notification`, surfaced through [`Self::wait_for_event`]).
    pub fn pin_code_reply(&mut self, bdaddr: &BdAddr, pin: &str) -> Result<()> {
        let pin_bytes = pin.as_bytes();
        if pin_bytes.len() > 16 {
            anyhow::bail!("legacy PIN longer than 16 bytes");
        }
        let mut params = [0u8; 23];
        for (i, b) in bdaddr.iter().enumerate() {
            params[i] = *b;
        }
        params[6] = pin_bytes.len() as u8;
        params[7..7 + pin_bytes.len()].copy_from_slice(pin_bytes);
        self.command(HCI_OP_PIN_CODE_REPLY, &params, Duration::from_secs(3))
            .map(|_| ())
    }

    /// Reply to an `IO_Capability_Request`. Capabilities: 0 display-only,
    /// 1 display-yes-no, 2 keyboard-only, 3 no-input-no-output.
    pub fn io_capability_reply(&mut self, bdaddr: &BdAddr, capability: u8) -> Result<()> {
        let mut params = [0u8; 9];
        for (i, b) in bdaddr.iter().enumerate() {
            params[i] = *b;
        }
        params[6] = capability;
        params[7] = 0x00; // OOB data not present
        params[8] = 0x00; // MITM protection off — the downgrade lever
        self.command(HCI_OP_IO_CAPABILITY_REPLY, &params, Duration::from_secs(3))
            .map(|_| ())
    }

    /// Reply to a `User_Confirmation_Request` (numeric comparison) with "yes".
    pub fn user_confirm_reply(&mut self, bdaddr: &BdAddr) -> Result<()> {
        let mut params = [0u8; 6];
        for (i, b) in bdaddr.iter().enumerate() {
            params[i] = *b;
        }
        self.command(HCI_OP_USER_CONFIRM_REPLY, &params, Duration::from_secs(3))
            .map(|_| ())
    }

    /// Reply to a `User_Passkey_Request` with a 6-digit passkey.
    pub fn passkey_reply(&mut self, bdaddr: &BdAddr, passkey: u32) -> Result<()> {
        let mut params = [0u8; 10];
        for (i, b) in bdaddr.iter().enumerate() {
            params[i] = *b;
        }
        params[6..10].copy_from_slice(&passkey.to_le_bytes());
        self.command(HCI_OP_USER_PASSKEY_REPLY, &params, Duration::from_secs(3))
            .map(|_| ())
    }

    /// `HCI_Authentication_Requested` on an open ACL handle.
    pub fn authentication_requested(&mut self, handle: u16) -> Result<()> {
        let mut params = [0u8; 2];
        params.copy_from_slice(&handle.to_le_bytes());
        self.command(HCI_OP_AUTH_REQUESTED, &params, Duration::from_secs(2))
            .map(|_| ())
    }

    /// Parse a `Link_Key_Notification` event → (bdaddr, key, link_key_type).
    pub fn parse_link_key_notification(ev: &HciEvent) -> Result<(BdAddr, [u8; 16], u8)> {
        if ev.code != EVT_LINK_KEY_NOTIFY || ev.params.len() < 23 {
            return Err(anyhow!("not a Link_Key_Notification event"));
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&ev.params[0..6]);
        let mut key = [0u8; 16];
        key.copy_from_slice(&ev.params[6..22]);
        Ok((addr, key, ev.params[22]))
    }

    /// True when the event is `Authentication_Complete` with the given status.
    pub fn is_auth_complete(ev: &HciEvent) -> Option<u8> {
        (ev.code == EVT_AUTH_COMPLETE && !ev.params.is_empty()).then_some(ev.params[0])
    }

    /// Parse `Encryption_Change` (event 0x08) → (handle, enabled, key_size,
    /// encryption_mode). The legacy 0x08 event returns
    /// `(handle, 0/1=disabled/enabled, 0)` — the `encryption_mode` field is
    /// only present in the v2 variant (event 0x59), which we surface below.
    /// Mode 0x00 = E0 (legacy stream cipher), 0x01 = AES-CCM. Devices that
    /// grant AES-CCM where the initiator asked for E0 expose the
    /// CVE-2022-25836/-25837 downgrade surface.
    pub fn parse_encryption_change(ev: &HciEvent) -> Option<(u16, bool, u8, u8)> {
        if ev.code != 0x08 || ev.params.len() < 4 {
            return None;
        }
        let handle = u16::from_le_bytes([ev.params[1], ev.params[2]]);
        Some((handle, ev.params[0] == 0x01, ev.params[3], 0xFF))
    }

    /// Parse `Encryption_Change_v2` (event 0x59) → (handle, enabled, key_size,
    /// encryption_mode). Returns `None` for any other event.
    pub fn parse_encryption_change_v2(ev: &HciEvent) -> Option<(u16, bool, u8, u8)> {
        if ev.code != 0x59 || ev.params.len() < 5 {
            return None;
        }
        let handle = u16::from_le_bytes([ev.params[1], ev.params[2]]);
        Some((handle, ev.params[0] == 0x01, ev.params[3], ev.params[4]))
    }

    /// True when the event is a `PIN_Code_Request` for `bdaddr`.
    pub fn is_pin_code_req(ev: &HciEvent, bdaddr: &BdAddr) -> bool {
        ev.code == EVT_PIN_CODE_REQ && ev.params.len() >= 6 && ev.params[0..6] == *bdaddr
    }

    /// True when the event is an `IO_Capability_Request` for `bdaddr`.
    pub fn is_io_cap_req(ev: &HciEvent, bdaddr: &BdAddr) -> bool {
        ev.code == EVT_IO_CAP_REQ && ev.params.len() >= 6 && ev.params[0..6] == *bdaddr
    }

    /// True when the event is a `User_Confirmation_Request` for `bdaddr`.
    pub fn is_user_confirm_req(ev: &HciEvent, bdaddr: &BdAddr) -> bool {
        ev.code == EVT_USER_CONFIRM_REQ && ev.params.len() >= 6 && ev.params[0..6] == *bdaddr
    }

    /// Start non-connectable LE advertising with `adv_data` (≤31 bytes of AD
    /// structures) on a dedicated user-channel socket. Returns once the
    /// controller confirms advertising is enabled.
    pub fn le_advertise(dev_id: u16, adv_data: &[u8], interval_ms: u16) -> Result<HciSocket> {
        let mut sock = HciSocket::open(dev_id, HCI_CHANNEL_USER)?;
        // LE_SET_ADV_PARAMS: min(2) max(2) type(1)=0x03 non-connectable
        // own_addr(1)=0 public filter(1)=0x00 all.
        let interval = (interval_ms * 16 / 10).clamp(0x20, 0xFF);
        let mut params = [0u8; 15];
        params[0] = interval as u8;
        params[1] = (interval >> 8) as u8;
        params[2] = interval as u8;
        params[3] = (interval >> 8) as u8;
        params[4] = 0x03; // ADV_NONCONN_IND — beacon
        sock.command(HCI_OP_LE_SET_ADV_PARAMS, &params, Duration::from_secs(2))?;
        // Advertising data (must be ≤31 bytes).
        if adv_data.len() > 31 {
            anyhow::bail!(
                "advertising data too long: {} bytes (max 31)",
                adv_data.len()
            );
        }
        let mut data = [0u8; 31];
        data[..adv_data.len()].copy_from_slice(adv_data);
        let mut data_cmd = vec![adv_data.len() as u8];
        data_cmd.extend_from_slice(&data);
        sock.command(HCI_OP_LE_SET_ADV_DATA, &data_cmd, Duration::from_secs(2))?;
        // Scan response: empty.
        let mut empty = vec![0u8; 32];
        empty[0] = 0;
        sock.command(HCI_OP_LE_SET_SCAN_RSP_DATA, &empty, Duration::from_secs(2))?;
        // Enable.
        sock.command(HCI_OP_LE_SET_ADV_ENABLE, &[0x01], Duration::from_secs(2))?;
        Ok(sock)
    }

    /// Stop LE advertising on a user-channel socket.
    pub fn le_advertise_stop(&mut self) -> Result<()> {
        self.command(HCI_OP_LE_SET_ADV_ENABLE, &[0x00], Duration::from_secs(2))
            .map(|_| ())
    }

    /// Parse an `LE_Connection_Complete` extended event (0x3E, subevent 0x01)
    /// → (handle, bdaddr). Returns `None` for other events.
    pub fn parse_le_conn_complete(ev: &HciEvent) -> Option<(u16, BdAddr)> {
        if ev.code != 0x3E || ev.params.len() < 19 || ev.params[0] != 0x01 {
            return None;
        }
        let sub_status = ev.params[1];
        if sub_status != 0 {
            return None;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&ev.params[7..13]);
        let handle = u16::from_le_bytes([ev.params[13], ev.params[14]]);
        Some((handle, addr))
    }
}

impl Drop for HciSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// General/Unlimited Inquiry Access Code (GIAC).
const LAP_GIAC: [u8; 3] = [0x33, 0x8B, 0x9E];

/// One device found by a classic inquiry.
#[derive(Debug, Clone)]
pub struct InquiryResult {
    pub bdaddr: BdAddr,
    pub class_of_device: u32,
    pub rssi: Option<i8>,
    pub clock_offset: Option<u16>,
}

fn parse_inquiry_result(params: &[u8], stride: usize) -> Option<InquiryResult> {
    if params.is_empty() {
        return None;
    }
    let off = 1usize;
    while off + stride <= params.len() {
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&params[off..off + 6]);
        let cod = ((params[off + 9] as u32) << 16)
            | ((params[off + 10] as u32) << 8)
            | (params[off + 11] as u32);
        let rssi = if stride >= 15 {
            Some(params[off + 14] as i8)
        } else {
            None
        };
        return Some(InquiryResult {
            bdaddr: addr,
            class_of_device: cod,
            rssi,
            clock_offset: Some(u16::from_le_bytes([params[off + 12], params[off + 13]])),
        });
    }
    None
}

fn parse_ext_inquiry_result(params: &[u8]) -> Option<InquiryResult> {
    // num(1) bdaddr(6) pscan(3) cod(3) clock(2) rssi(1) eir(240)
    if params.len() < 16 {
        return None;
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[1..7]);
    let cod = ((params[9] as u32) << 16) | ((params[10] as u32) << 8) | (params[11] as u32);
    Some(InquiryResult {
        bdaddr: addr,
        class_of_device: cod,
        rssi: Some(params[12] as i8),
        clock_offset: Some(u16::from_le_bytes([params[7], params[8]])),
    })
}

/// A decoded HCI event.
#[derive(Debug, Clone)]
pub struct HciEvent {
    pub code: u8,
    pub params: Vec<u8>,
}

fn matches_command(ev: &HciEvent, opcode: u16) -> Option<HciEvent> {
    match ev.code {
        EVT_CMD_COMPLETE if ev.params.len() >= 4 => {
            let ev_opcode = u16::from_le_bytes([ev.params[1], ev.params[2]]);
            (ev_opcode == opcode).then(|| ev.clone())
        }
        EVT_CMD_STATUS if ev.params.len() >= 4 => {
            let ev_opcode = u16::from_le_bytes([ev.params[2], ev.params[3]]);
            (ev_opcode == opcode).then(|| ev.clone())
        }
        _ => None,
    }
}

/// A connected L2CAP channel (Basic Mode) to a remote device.
pub struct L2capChannel {
    fd: RawFd,
}

impl L2capChannel {
    /// Connect an L2CAP Basic Mode channel to `bdaddr` (display order) on
    /// `psm`. Requires root/CAP_NET_RAW.
    pub fn connect(bdaddr_display: &str, psm: u16) -> Result<Self> {
        let addr = crate::bluetooth::parse_mac(bdaddr_display)?;
        // sockaddr_l2 wants the address LSB-first.
        let mut reverse = addr;
        reverse.reverse();
        let fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                BTPROTO_L2CAP,
            )
        };
        if fd < 0 {
            return Err(anyhow!(
                "opening L2CAP socket failed (need root or CAP_NET_RAW): {}",
                std::io::Error::last_os_error()
            ));
        }
        // sockaddr_l2: family(2) psm(2, big-endian) bdaddr(6) cid(2) bdaddr_type(1)
        let mut sa = [0u8; 15];
        sa[0] = libc::AF_BLUETOOTH as u8;
        sa[2] = (psm >> 8) as u8;
        sa[3] = (psm & 0xFF) as u8;
        for (i, b) in reverse.iter().enumerate() {
            sa[4 + i] = *b;
        }
        let rc =
            unsafe { libc::connect(fd, sa.as_ptr() as *const libc::sockaddr, sa.len() as u32) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(anyhow!(
                "L2CAP connect to {bdaddr_display} PSM 0x{psm:04X}: {err}"
            ));
        }
        Ok(Self { fd })
    }

    /// Send one L2CAP Basic Mode frame (raw SDU — the kernel adds the CID
    /// header for connection-oriented channels).
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        let n = unsafe { libc::write(self.fd, data.as_ptr() as *const c_void, data.len()) };
        if n < 0 {
            return Err(anyhow!(
                "writing L2CAP frame: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(n as usize)
    }

    /// Receive up to `buf.len()` bytes with a timeout.
    pub fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        let mut pfd = pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { poll(&mut pfd as *mut pollfd, 1, timeout.as_millis() as c_int) };
        if rc < 0 {
            return Err(anyhow!(
                "polling L2CAP socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        if rc == 0 {
            return Ok(0);
        }
        let n = unsafe { libc::read(self.fd, buf.as_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            return Err(anyhow!(
                "reading L2CAP socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(n as usize)
    }
}

impl Drop for L2capChannel {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl std::fmt::Debug for L2capChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L2capChannel")
            .field("fd", &self.fd)
            .finish()
    }
}

/// Build LE advertising data (AD structures) from flags + service data +
/// manufacturer data. Returns ≤31 bytes or an error.
pub fn build_adv_data(
    flags: u8,
    service_data: Option<(u16, &[u8])>,
    manufacturer: Option<(u16, &[u8])>,
    local_name: Option<&str>,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(31);
    // Flags AD structure: len=2, type=0x01.
    out.extend_from_slice(&[0x02, 0x01, flags]);
    if let Some((uuid, data)) = service_data {
        // Service Data - 16-bit UUID: type 0x16, UUID little-endian.
        if data.len() > 29 {
            anyhow::bail!("service data too long for one advert");
        }
        out.push(2 + data.len() as u8);
        out.push(0x16);
        out.extend_from_slice(&uuid.to_le_bytes());
        out.extend_from_slice(data);
    }
    if let Some((company, data)) = manufacturer {
        if data.len() > 29 {
            anyhow::bail!("manufacturer data too long for one advert");
        }
        out.push(2 + 2 + data.len() as u8);
        out.push(0xFF);
        out.extend_from_slice(&company.to_le_bytes());
        out.extend_from_slice(data);
    }
    if let Some(name) = local_name {
        let bytes = name.as_bytes();
        if bytes.len() > 29 {
            anyhow::bail!("local name too long for one advert");
        }
        out.push(1 + bytes.len() as u8);
        out.push(0x09);
        out.extend_from_slice(bytes);
    }
    if out.len() > 31 {
        anyhow::bail!("advertising data exceeds 31 bytes: {}", out.len());
    }
    Ok(out)
}

/// Map common HCI error codes to names (subset used by this framework).
pub fn hci_status_name(status: u8) -> &'static str {
    match status {
        0x00 => "success",
        0x01 => "unknown command",
        0x02 => "unknown connection id",
        0x03 => "hardware failure",
        0x04 => "page timeout",
        0x05 => "authentication failure",
        0x06 => "PIN or key missing",
        0x07 => "memory capacity exceeded",
        0x08 => "connection timeout",
        0x0C => "command disallowed",
        0x11 => "unsupported feature",
        0x12 => "invalid parameters",
        0x16 => "connection terminated by local host",
        0x13 => "remote user terminated connection",
        0x22 => "ACL connection exists",
        0x25 => "encryption mode not acceptable",
        _ => "error",
    }
}

/// Format a `BdAddr` in MSB-first display order (`AA:BB:CC:DD:EE:FF`).
pub fn bdaddr_to_string(addr: &BdAddr) -> String {
    // HCI carries addresses LSB-first (reverse of display order).
    let mut rev = *addr;
    rev.reverse();
    crate::bluetooth::mac_to_string(&rev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bdaddr_display_order() {
        // On the wire: 0x65 0x56 0xC8 ... (LSB first) → display 98:5F...
        let wire = [0x65u8, 0x56, 0xC8, 0x11, 0x22, 0x33];
        let s = bdaddr_to_string(&wire);
        assert_eq!(s, "33:22:11:C8:56:65");
    }

    #[test]
    fn inquiry_ext_parse() {
        let mut params = vec![1u8];
        params.extend_from_slice(&[0x65, 0x56, 0xC8, 0x11, 0x22, 0x33]);
        params.extend_from_slice(&[0x01, 0x00, 0x00]); // pscan
        params.extend_from_slice(&[0x04, 0x02, 0x0C]); // cod: phone
        params.extend_from_slice(&[0x34, 0x12]); // clock
        params.push(0xE4); // rssi -28
        let r = parse_ext_inquiry_result(&params).expect("parse");
        assert_eq!(bdaddr_to_string(&r.bdaddr), "33:22:11:C8:56:65");
        assert_eq!(r.class_of_device, 0x0C0204);
        assert_eq!(r.rssi, Some(-28));
    }
}
