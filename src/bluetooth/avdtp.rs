//! AVDTP 1.3 (Audio/Video Distribution Transport Protocol) signaling codec
//! + transport helpers over L2CAP PSM 0x0019.
//!
//! Signaling message layout:
//!
//! | field               | size | notes                                          |
//! |---------------------|------|------------------------------------------------|
//! | transaction label   | 4b   | per-connection id                              |
//! | packet type         | 2b   | 0=Command 1=Accept 2=Reject 3=Reserved         |
//! | signal id           | 6b   | see [`signal`] constants                       |
//! | payload             | var  | per-signal parameters (see spec)               |
//!
//! The byte layout is: `(label << 4) | (packet_type << 2) | (signal_id >> 4)`
//! then a second byte `(signal_id << 4) | …`. AVDTP does NOT use big-endian
//! for the header; the 16-bit value `(label | pkt | sigid)` is laid out
//! left-to-right MSB-first.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Mutex;
use tokio::task;

use super::hci::L2capChannel;
use super::lmp::{PSM_AVDTP, PSM_AVDTP_MEDIA};

pub mod signal {
    pub const DISCOVER: u8 = 0x01;
    pub const GET_CAPABILITIES: u8 = 0x02;
    pub const SET_CONFIGURATION: u8 = 0x03;
    pub const GET_CONFIGURATION: u8 = 0x04;
    pub const RECONFIGURE: u8 = 0x05;
    pub const OPEN: u8 = 0x06;
    pub const START: u8 = 0x07;
    pub const CLOSE: u8 = 0x08;
    pub const SUSPEND: u8 = 0x09;
    pub const ABORT: u8 = 0x0A;
    pub const SECURITY_CONTROL: u8 = 0x0B;
    pub const GET_ALL_CAPABILITIES: u8 = 0x0C;
    pub const DELAY_REPORT: u8 = 0x0D;
}

pub mod pkt {
    pub const COMMAND: u8 = 0;
    pub const ACCEPT: u8 = 1;
    pub const REJECT: u8 = 2;
}

pub mod capability {
    pub const MEDIA_TRANSPORT: u8 = 0x01;
    pub const MEDIA_CODEC: u8 = 0x02;
    pub const CONTENT_PROTECTION: u8 = 0x03;
    pub const HEADER_COMPRESSION: u8 = 0x04;
    pub const MULTIPLEXING_FRAGMENT: u8 = 0x05;
    pub const REED_SOLOMON: u8 = 0x06;
    pub const CONTENT_PROTECTION_EXT: u8 = 0x07;
}

pub mod media_type {
    pub const AUDIO: u8 = 0x00;
    pub const VIDEO: u8 = 0x01;
}

pub mod codec {
    pub const SBC: u8 = 0x00;
    pub const MPEG_1_2_AUDIO: u8 = 0x01;
    pub const MPEG_2_4_AAC: u8 = 0x02;
    pub const ATRAC_FAMILY: u8 = 0x04;
    pub const VENDOR: u8 = 0xFF;
}

pub const AVDTP_ERROR_BAD_STATE: u8 = 0x31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbcCodecInfo {
    pub sampling_freq_bitmap: u8,
    pub channel_mode_bitmap: u8,
    pub block_length_bitmap: u8,
    pub subbands_bitmap: u8,
    pub allocation_bitmap: u8,
    pub min_bitpool: u8,
    pub max_bitpool: u8,
}

impl SbcCodecInfo {
    pub const SAMPLING_16K: u8 = 0x01;
    pub const SAMPLING_32K: u8 = 0x02;
    pub const SAMPLING_44_1K: u8 = 0x04;
    pub const SAMPLING_48K: u8 = 0x08;
    pub const CHANNEL_MONO: u8 = 0x01;
    pub const CHANNEL_JOINT_STEREO: u8 = 0x02;
    pub const CHANNEL_STEREO: u8 = 0x04;
    pub const CHANNEL_DUAL: u8 = 0x08;
    pub const BLOCK_4: u8 = 0x01;
    pub const BLOCK_8: u8 = 0x02;
    pub const BLOCK_12: u8 = 0x04;
    pub const BLOCK_16: u8 = 0x08;
    pub const SUBBANDS_4: u8 = 0x01;
    pub const SUBBANDS_8: u8 = 0x02;
    pub const ALLOC_SNR: u8 = 0x01;
    pub const ALLOC_LOUDNESS: u8 = 0x02;

    pub fn default_sink() -> Self {
        Self {
            sampling_freq_bitmap: 0x0F,
            channel_mode_bitmap: 0x0F,
            block_length_bitmap: 0x0F,
            subbands_bitmap: 0x03,
            allocation_bitmap: 0x03,
            min_bitpool: 2,
            max_bitpool: 53,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.sampling_freq_bitmap,
            self.channel_mode_bitmap,
            self.block_length_bitmap,
            self.subbands_bitmap,
            self.allocation_bitmap,
            self.min_bitpool,
            self.max_bitpool,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 7 {
            return Err(anyhow!("SBC codec info too short: {} bytes", bytes.len()));
        }
        Ok(Self {
            sampling_freq_bitmap: bytes[0],
            channel_mode_bitmap: bytes[1],
            block_length_bitmap: bytes[2],
            subbands_bitmap: bytes[3],
            allocation_bitmap: bytes[4],
            min_bitpool: bytes[5],
            max_bitpool: bytes[6],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvdtpCapability {
    MediaTransport,
    MediaCodecSbc(SbcCodecInfo),
    MediaCodecMpeg12Audio { layer: u8, sampling_bitmap: u8, channels_bitmap: u8, bitrate: u16, mode: u8 },
    MediaCodecUnknown { codec_type: u8, media_type: u8, bytes: Vec<u8> },
    ContentProtection { cp_type: u16, bytes: Vec<u8> },
    HeaderCompression { recovery: bool },
    MultiplexingFragment,
    ReedSolomon,
}

impl AvdtpCapability {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            AvdtpCapability::MediaTransport => vec![capability::MEDIA_TRANSPORT, 0x00],
            AvdtpCapability::MediaCodecSbc(info) => {
                let mut v = vec![capability::MEDIA_CODEC, 6, media_type::AUDIO, codec::SBC];
                v.extend_from_slice(&info.encode());
                v
            }
            AvdtpCapability::MediaCodecMpeg12Audio {
                layer,
                sampling_bitmap,
                channels_bitmap,
                bitrate,
                mode,
            } => {
                let mut v = vec![
                    capability::MEDIA_CODEC,
                    6,
                    media_type::AUDIO,
                    codec::MPEG_1_2_AUDIO,
                    *layer,
                    *sampling_bitmap,
                    *channels_bitmap,
                    (bitrate >> 8) as u8,
                    (bitrate & 0xFF) as u8,
                ];
                v.push(*mode);
                v
            }
            AvdtpCapability::MediaCodecUnknown {
                codec_type,
                media_type,
                bytes,
            } => {
                let mut v = vec![capability::MEDIA_CODEC, (bytes.len() + 2) as u8, *media_type, *codec_type];
                v.extend_from_slice(bytes);
                v
            }
            AvdtpCapability::ContentProtection { cp_type, bytes } => {
                let mut v = vec![
                    capability::CONTENT_PROTECTION,
                    (bytes.len() + 2) as u8,
                    (cp_type >> 8) as u8,
                    (cp_type & 0xFF) as u8,
                ];
                v.extend_from_slice(bytes);
                v
            }
            AvdtpCapability::HeaderCompression { recovery } => {
                vec![capability::HEADER_COMPRESSION, 1, *recovery as u8]
            }
            AvdtpCapability::MultiplexingFragment => vec![capability::MULTIPLEXING_FRAGMENT, 0],
            AvdtpCapability::ReedSolomon => vec![capability::REED_SOLOMON, 0],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvdtpEndpoint {
    pub seid: u8,
    pub in_use: bool,
    pub media_type: u8,
    pub codec_type: u8,
}

fn hdr_byte(label: u8, pkt: u8, sig: u8) -> u8 {
    ((label & 0x0F) << 4) | ((pkt & 0x03) << 2) | ((sig >> 4) & 0x03)
}

fn hdr_byte2(sig: u8) -> u8 {
    (sig & 0x0F) << 4
}

pub fn build_command(label: u8, sig: u8, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + params.len());
    out.push(hdr_byte(label, pkt::COMMAND, sig));
    out.push(hdr_byte2(sig));
    out.extend_from_slice(params);
    out
}

#[derive(Debug, Clone)]
pub struct AvdtpSignal {
    pub label: u8,
    pub pkt: u8,
    pub signal_id: u8,
    pub payload: Vec<u8>,
}

pub fn parse_signal(data: &[u8]) -> Result<AvdtpSignal> {
    if data.len() < 2 {
        return Err(anyhow!("AVDTP signal too short: {} bytes", data.len()));
    }
    let label = (data[0] >> 4) & 0x0F;
    let pkt = (data[0] >> 2) & 0x03;
    let sig_high = (data[0] & 0x03) << 4;
    let sig_low = data[1] >> 4;
    let sig = sig_high | sig_low;
    Ok(AvdtpSignal {
        label,
        pkt,
        signal_id: sig,
        payload: data[2..].to_vec(),
    })
}

pub fn parse_capabilities(payload: &[u8]) -> Result<Vec<AvdtpCapability>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        let cap = payload[i];
        let len = *payload.get(i + 1).ok_or_else(|| anyhow!("AVDTP cap truncated"))? as usize;
        let body = payload
            .get(i + 2..i + 2 + len)
            .ok_or_else(|| anyhow!("AVDTP cap body truncated"))?;
        match cap {
            capability::MEDIA_TRANSPORT => out.push(AvdtpCapability::MediaTransport),
            capability::MEDIA_CODEC => {
                if body.len() < 2 {
                    return Err(anyhow!("AVDTP media codec body too short"));
                }
                let mt = body[0];
                let ct = body[1];
                let specific = &body[2..];
                match (mt, ct) {
                    (media_type::AUDIO, codec::SBC) => {
                        out.push(AvdtpCapability::MediaCodecSbc(SbcCodecInfo::decode(specific)?));
                    }
                    (media_type::AUDIO, codec::MPEG_1_2_AUDIO) => {
                        if specific.len() < 6 {
                            return Err(anyhow!("AVDTP MPEG-1/2 body too short"));
                        }
                        let layer = specific[0];
                        let sampling_bitmap = specific[1];
                        let channels_bitmap = specific[2];
                        let bitrate = u16::from_be_bytes([specific[3], specific[4]]);
                        let mode = specific[5];
                        out.push(AvdtpCapability::MediaCodecMpeg12Audio {
                            layer,
                            sampling_bitmap,
                            channels_bitmap,
                            bitrate,
                            mode,
                        });
                    }
                    _ => out.push(AvdtpCapability::MediaCodecUnknown {
                        codec_type: ct,
                        media_type: mt,
                        bytes: specific.to_vec(),
                    }),
                }
            }
            capability::CONTENT_PROTECTION => {
                if body.len() < 2 {
                    return Err(anyhow!("AVDTP content protection body too short"));
                }
                let cp_type = u16::from_be_bytes([body[0], body[1]]);
                out.push(AvdtpCapability::ContentProtection {
                    cp_type,
                    bytes: body[2..].to_vec(),
                });
            }
            capability::HEADER_COMPRESSION => {
                let recovery = body.first().is_some_and(|b| *b != 0);
                out.push(AvdtpCapability::HeaderCompression { recovery });
            }
            capability::MULTIPLEXING_FRAGMENT => out.push(AvdtpCapability::MultiplexingFragment),
            capability::REED_SOLOMON => out.push(AvdtpCapability::ReedSolomon),
            other => {
                tracing::debug!("AVDTP: unknown capability 0x{other:02X}");
            }
        }
        i += 2 + len;
    }
    Ok(out)
}

pub async fn discover(channel: Arc<Mutex<L2capChannel>>) -> Result<Vec<AvdtpEndpoint>> {
    let req = build_command(1, signal::DISCOVER, &[]);
    send_signal(channel.clone(), &req).await?;
    let mut buf = [0u8; 512];
    let n = recv_signal_blocking(channel.clone(), &mut buf, Duration::from_secs(5)).await?;
    let sig = parse_signal(&buf[..n])?;
    if sig.pkt != pkt::ACCEPT || sig.signal_id != signal::DISCOVER {
        anyhow::bail!(
            "AVDTP Discover: expected Accept+Discover, got pkt={} sig=0x{:02X}",
            sig.pkt,
            sig.signal_id
        );
    }
    let mut endpoints = Vec::new();
    let mut i = 0usize;
    while i + 1 < sig.payload.len() {
        let seid = (sig.payload[i] >> 2) & 0x3F;
        let in_use = (sig.payload[i] & 0x02) != 0;
        let media_type = (sig.payload[i + 1] >> 4) & 0x03;
        let codec_type = sig.payload[i + 1] & 0x0F;
        endpoints.push(AvdtpEndpoint {
            seid,
            in_use,
            media_type,
            codec_type,
        });
        i += 2;
    }
    Ok(endpoints)
}

pub async fn get_capabilities(channel: Arc<Mutex<L2capChannel>>, seid: u8) -> Result<Vec<AvdtpCapability>> {
    let mut params = vec![0u8; 2];
    params[0] = 0x00;
    params[1] = (seid << 2) | 0x02;
    let req = build_command(2, signal::GET_CAPABILITIES, &params);
    send_signal(channel.clone(), &req).await?;
    let mut buf = [0u8; 512];
    let n = recv_signal_blocking(channel.clone(), &mut buf, Duration::from_secs(5)).await?;
    let sig = parse_signal(&buf[..n])?;
    if sig.pkt != pkt::ACCEPT {
        anyhow::bail!("AVDTP GetCapabilities: not Accept (pkt={})", sig.pkt);
    }
    parse_capabilities(&sig.payload)
}

pub async fn set_configuration(
    channel: Arc<Mutex<L2capChannel>>,
    acp_seid: u8,
    int_seid: u8,
    caps: &[AvdtpCapability],
) -> Result<()> {
    let mut params = Vec::new();
    params.push((acp_seid << 2) | 0x02);
    params.push((int_seid << 2) | 0x02);
    for c in caps {
        params.extend_from_slice(&c.encode());
    }
    let req = build_command(3, signal::SET_CONFIGURATION, &params);
    send_signal(channel.clone(), &req).await?;
    let mut buf = [0u8; 256];
    let n = recv_signal_blocking(channel.clone(), &mut buf, Duration::from_secs(5)).await?;
    let sig = parse_signal(&buf[..n])?;
    if sig.pkt != pkt::ACCEPT {
        anyhow::bail!(
            "AVDTP SetConfiguration: not Accept (pkt={}, sig=0x{:02X})",
            sig.pkt,
            sig.signal_id
        );
    }
    Ok(())
}

pub async fn open_stream(channel: Arc<Mutex<L2capChannel>>, acp_seid: u8) -> Result<()> {
    let params = vec![(acp_seid << 2) | 0x02];
    let req = build_command(4, signal::OPEN, &params);
    send_signal(channel.clone(), &req).await?;
    let mut buf = [0u8; 32];
    let n = recv_signal_blocking(channel.clone(), &mut buf, Duration::from_secs(5)).await?;
    let sig = parse_signal(&buf[..n])?;
    if sig.pkt != pkt::ACCEPT {
        anyhow::bail!("AVDTP Open: not Accept (pkt={})", sig.pkt);
    }
    Ok(())
}

pub async fn start_stream(channel: Arc<Mutex<L2capChannel>>, acp_seid: u8) -> Result<()> {
    let params = vec![(acp_seid << 2) | 0x02];
    let req = build_command(5, signal::START, &params);
    send_signal(channel.clone(), &req).await?;
    let mut buf = [0u8; 32];
    let n = recv_signal_blocking(channel.clone(), &mut buf, Duration::from_secs(5)).await?;
    let sig = parse_signal(&buf[..n])?;
    if sig.pkt != pkt::ACCEPT {
        anyhow::bail!("AVDTP Start: not Accept (pkt={})", sig.pkt);
    }
    Ok(())
}

pub async fn get_media_l2cap(bdaddr: &str) -> Result<L2capChannel> {
    let owned = bdaddr.to_string();
    task::spawn_blocking(move || -> Result<L2capChannel> {
        L2capChannel::connect(&owned, PSM_AVDTP_MEDIA)
    })
    .await
    .map_err(|e| anyhow!("AVDTP media L2CAP task: {e}"))?
}

async fn send_signal(channel: Arc<Mutex<L2capChannel>>, sig: &[u8]) -> Result<()> {
    let channel = channel.clone();
    let payload = sig.to_vec();
    task::spawn_blocking(move || -> Result<()> {
        let guard = channel.blocking_lock();
        let mut ch = guard;
        let mut off = 0usize;
        while off < payload.len() {
            let n = ch.send(&payload[off..])?;
            off += n;
        }
        Ok(())
    })
    .await
    .map_err(|e| anyhow!("AVDTP send signal task: {e}"))?
}

async fn recv_signal_blocking(
    channel: Arc<Mutex<L2capChannel>>,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<usize> {
    let channel = channel.clone();
    let buf_owned: Vec<u8> = buf.to_vec();
    let (data, n) = task::spawn_blocking(move || -> Result<(Vec<u8>, usize)> {
        let guard = channel.blocking_lock();
        let mut ch = guard;
        let mut tmp = buf_owned;
        let got = ch.recv(&mut tmp, timeout)?;
        Ok((tmp[..got].to_vec(), got))
    })
    .await
    .map_err(|e| anyhow!("AVDTP recv signal task: {e}"))??;
    let copy = n.min(buf.len());
    buf[..copy].copy_from_slice(&data[..copy]);
    Ok(copy)
}

pub async fn connect_signaling(bdaddr: &str) -> Result<Arc<Mutex<L2capChannel>>> {
    let owned = bdaddr.to_string();
    let channel = task::spawn_blocking(move || -> Result<L2capChannel> {
        L2capChannel::connect(&owned, PSM_AVDTP)
    })
    .await
    .map_err(|e| anyhow!("AVDTP signaling L2CAP task: {e}"))??;
    Ok(Arc::new(Mutex::new(channel)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_byte_layout() {
        // label=1, pkt=COMMAND(0), sig=DISCOVER(0x01)
        let b = build_command(1, signal::DISCOVER, &[]);
        assert_eq!(b[0], 0x10);
        assert_eq!(b[1], 0x10);
    }

    #[test]
    fn sbc_roundtrip() {
        let info = SbcCodecInfo::default_sink();
        let encoded = info.encode();
        let back = SbcCodecInfo::decode(&encoded).expect("decode");
        assert_eq!(info, back);
    }

    #[test]
    fn discover_response_parses_two_endpoints() {
        // Accept, sig=DISCOVER, two endpoints: SEID=1 audio SBC, SEID=2 video.
        let mut pkt = vec![0x10, 0x10];
        // Endpoint 1: SEID=1 (bits 7..2) | in_use=0 | rsp=1 → 0x06
        pkt.push(0x06);
        // media_type=audio (0) | codec=SBC (0) → 0x00
        pkt.push(0x00);
        // Endpoint 2: SEID=2 → 0x0A
        pkt.push(0x0A);
        // media_type=video (1<<4)=0x10 | codec=SBC (0) → 0x10
        pkt.push(0x10);
        let s = parse_signal(&pkt).expect("parse signal");
        assert_eq!(s.pkt, pkt::ACCEPT);
        assert_eq!(s.signal_id, signal::DISCOVER);
        let endpoints = {
            let mut es = Vec::new();
            let mut i = 0;
            while i + 1 < s.payload.len() {
                let seid = (s.payload[i] >> 2) & 0x3F;
                let in_use = (s.payload[i] & 0x02) != 0;
                let mt = (s.payload[i + 1] >> 4) & 0x03;
                let ct = s.payload[i + 1] & 0x0F;
                es.push(AvdtpEndpoint {
                    seid,
                    in_use,
                    media_type: mt,
                    codec_type: ct,
                });
                i += 2;
            }
            es
        };
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].seid, 1);
        assert_eq!(endpoints[1].seid, 2);
        assert_eq!(endpoints[1].media_type, media_type::VIDEO);
    }

    #[test]
    fn media_codec_sbc_roundtrip() {
        let info = SbcCodecInfo::default_sink();
        let cap = AvdtpCapability::MediaCodecSbc(info.clone());
        let enc = cap.encode();
        let parsed = parse_capabilities(&enc).expect("parse");
        assert_eq!(parsed.len(), 1);
        match &parsed[0] {
            AvdtpCapability::MediaCodecSbc(i) => assert_eq!(*i, info),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
