//! Hands-Free Profile (HFP 1.8) AT-command client over `RfcommSession`.
//!
//! The peer is typically an in-car head unit or a headset. Server channel
//! numbers are SDP-discovered, but HFP AGs conventionally land on `0x04` or
//! `0x05`. Commands are line-terminated CRLF-free on send; responses are
//! CRLF-terminated. The implementation reads one line at a time, treating
//! `OK\r\n` and `ERROR\r\n` as terminal responses.

use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Mutex;

use super::rfcomm::RfcommSession;

pub const DEFAULT_HFP_CHANNEL: u8 = 0x05;

pub struct HfpClient {
    rfcomm: Mutex<RfcommSession>,
}

impl HfpClient {
    pub async fn connect(bdaddr: &str, rfcomm_channel: u8) -> Result<Self> {
        let rfcomm = RfcommSession::connect(bdaddr, rfcomm_channel).await?;
        Ok(Self {
            rfcomm: Mutex::new(rfcomm),
        })
    }

    pub async fn send_at(&mut self, cmd: &str) -> Result<String> {
        let mut rfcomm = self.rfcomm.lock().await;
        let line = format!("{cmd}\r");
        rfcomm.send(line.as_bytes()).await?;
        let mut all = String::new();
        let mut buf = [0u8; 256];
        let timeout = Duration::from_secs(3);
        loop {
            let n = rfcomm.recv(&mut buf, timeout).await?;
            if n == 0 {
                if all.is_empty() {
                    return Err(anyhow!("HFP: response timed out"));
                }
                break;
            }
            all.push_str(std::str::from_utf8(&buf[..n]).map_err(|e| anyhow!("HFP utf8: {e}"))?);
            if has_terminal_response(&all) {
                break;
            }
        }
        Ok(all)
    }

    pub async fn set_speaker_gain(&mut self, level: u8) -> Result<()> {
        let level = level.min(15);
        let resp = self.send_at(&format!("AT+VGS={level}")).await?;
        if !resp.contains("OK") {
            anyhow::bail!("HFP VGS not OK: {resp}");
        }
        Ok(())
    }

    pub async fn set_mic_gain(&mut self, level: u8) -> Result<()> {
        let level = level.min(15);
        let resp = self.send_at(&format!("AT+VGM={level}")).await?;
        if !resp.contains("OK") {
            anyhow::bail!("HFP VGM not OK: {resp}");
        }
        Ok(())
    }

    pub async fn dial(&mut self, number: &str) -> Result<()> {
        let resp = self.send_at(&format!("ATD{number};")).await?;
        if !resp.contains("OK") && !resp.contains("+CIEV") {
            anyhow::bail!("HFP dial not OK: {resp}");
        }
        Ok(())
    }

    pub async fn answer(&mut self) -> Result<()> {
        let resp = self.send_at("ATA").await?;
        if !resp.contains("OK") {
            anyhow::bail!("HFP ATA not OK: {resp}");
        }
        Ok(())
    }

    pub async fn hangup(&mut self) -> Result<()> {
        let resp = self.send_at("AT+CHUP").await?;
        if !resp.contains("OK") {
            anyhow::bail!("HFP CHUP not OK: {resp}");
        }
        Ok(())
    }

    pub async fn send_dtmf(&mut self, digit: char) -> Result<()> {
        if !digit.is_ascii_digit() && digit != '*' && digit != '#' {
            anyhow::bail!("HFP VTS: '{digit}' is not a DTMF digit");
        }
        let resp = self.send_at(&format!("AT+VTS={digit}")).await?;
        if !resp.contains("OK") {
            anyhow::bail!("HFP VTS not OK: {resp}");
        }
        Ok(())
    }

    pub async fn disconnect(self) -> Result<()> {
        let mut rfcomm = self.rfcomm.lock().await;
        rfcomm.close().await
    }
}

fn has_terminal_response(buf: &str) -> bool {
    buf.contains("\r\nOK\r\n")
        || buf.contains("\r\nERROR\r\n")
        || buf.contains("\nOK\r\n")
        || buf.contains("\nERROR\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_detection() {
        assert!(has_terminal_response("\r\nOK\r\n"));
        assert!(has_terminal_response("\r\nERROR\r\n"));
        assert!(!has_terminal_response("+CIEV: 1,0\r\n"));
        assert!(has_terminal_response("+CIEV: 1,0\r\nOK\r\n"));
    }

    #[test]
    fn dtmf_validation() {
        assert!(!('a').is_ascii_digit());
        assert!('*'.is_ascii());
        assert!('#'.is_ascii());
    }
}
