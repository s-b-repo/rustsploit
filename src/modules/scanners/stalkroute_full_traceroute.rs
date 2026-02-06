use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use std::io::Write;
use pnet_packet::icmp::{self, echo_request, echo_reply, IcmpTypes};
use pnet_packet::udp::{self, MutableUdpPacket};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpPacket;
use std::sync::Arc;

use rand::Rng;
use rand::distr::Alphanumeric;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};



use tokio::time::{Instant, Duration};
use tokio::task;

use socket2::{Domain, Protocol, Socket, Type};

use colored::*;

use anyhow::{Result, Context, anyhow, bail};

use std::mem::MaybeUninit;

const IPV4_FLAG_DF: u16 = 2;


const USE_RANDOM_OS_SIG: bool = true;
const SPOOF_SRC_IP_CONFIG: Option<&str> = None;
const JITTER_RANGE: (f32, f32) = (0.2, 1.1);
const MAX_TTL: u8 = 30;
const PROBE_COUNT: usize = 3;
const DECOY_PROB: f64 = 0.35;

#[derive(Debug, Clone)]
struct OsSignatureParams {
    id: u16,
    tos: u8,
    df_flag: bool,
}

fn generate_os_signature() -> OsSignatureParams {
    let mut rng = rand::rng();
    if !USE_RANDOM_OS_SIG {
        return OsSignatureParams {
            id: rng.random(),
            tos: 0,
            df_flag: false,
        };
    }

    let sigs = [
        OsSignatureParams { id: rng.random_range(0x4000..=0xffff), tos: 0, df_flag: true },
        OsSignatureParams { id: rng.random(), tos: 0, df_flag: false },
        OsSignatureParams { id: rng.random(), tos: 0, df_flag: true },
        OsSignatureParams { id: rng.random(), tos: 0x10, df_flag: false },
    ];
    sigs[rng.random_range(0..sigs.len())].clone()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ProbeProtocolType {
    Icmp,
    Udp,
    Tcp,
}

impl ProbeProtocolType {
    fn to_ip_next_header_protocol(&self) -> pnet_packet::ip::IpNextHeaderProtocol {
        match self {
            ProbeProtocolType::Icmp => IpNextHeaderProtocols::Icmp,
            ProbeProtocolType::Udp => IpNextHeaderProtocols::Udp,
            ProbeProtocolType::Tcp => IpNextHeaderProtocols::Tcp,
        }
    }

    fn to_string_lc(&self) -> String {
        match self {
            ProbeProtocolType::Icmp => "icmp".to_string(),
            ProbeProtocolType::Udp => "udp".to_string(),
            ProbeProtocolType::Tcp => "tcp".to_string(),
        }
    }
}

#[derive(Debug)]
struct ReceivedIcmpInfo {
    icmp_type: u8,
    description: String,
}

#[derive(Debug)]
struct ProbeSingleResponse {
    source_ip: Ipv4Addr,
    rtt_ms: f32,
    icmp_info: ReceivedIcmpInfo,
    probe_protocol_used: String,
}

fn craft_probe_packet(
    dst_ip: Ipv4Addr,
    current_ttl: u8,
    src_ip_override: Option<Ipv4Addr>,
    icmp_id_val: u16,
    icmp_seq_val: u16,
) -> Result<(Vec<u8>, ProbeProtocolType, OsSignatureParams)> {
    const IPV4_HEADER_LEN: usize = 20;

    let mut rng = rand::rng();
    let sig = generate_os_signature();

    let mut protocol_type = ProbeProtocolType::Icmp;
    if rng.random_bool(DECOY_PROB) {
        protocol_type = if rng.random_bool(0.5) {
            ProbeProtocolType::Udp
        } else {
            ProbeProtocolType::Tcp
        };
    }

    let payload_size = rng.random_range(24..=56);
    let payload: Vec<u8> = rng.clone()
        .sample_iter(&Alphanumeric)
        .take(payload_size)
        .map(|c| c as u8)
        .collect();

    let (transport_header_len, transport_packet_data) = match protocol_type {
        ProbeProtocolType::Icmp => {
            let mut buf = vec![0u8; 8 + payload.len()];
            let mut pkt = echo_request::MutableEchoRequestPacket::new(&mut buf).ok_or_else(|| anyhow!("Failed to create EchoRequest"))?;
            pkt.set_icmp_type(IcmpTypes::EchoRequest);
            pkt.set_icmp_code(echo_request::IcmpCodes::NoCode);
            pkt.set_identifier(icmp_id_val);
            pkt.set_sequence_number(icmp_seq_val);
            pkt.set_payload(&payload);
            let view = IcmpPacket::new(pkt.packet()).ok_or_else(|| anyhow!("Failed to create ICMP view"))?;
            pkt.set_checksum(icmp::checksum(&view));
            (buf.len(), buf)
        }
        ProbeProtocolType::Udp => {
            let mut buf = vec![0u8; 8 + payload.len()];
            let mut pkt = MutableUdpPacket::new(&mut buf).ok_or_else(|| anyhow!("Failed to create UDP packet"))?;
            pkt.set_source(rng.random_range(33434..=65535));
            pkt.set_destination(rng.random_range(33434..=65535));
            pkt.set_length((8 + payload.len()) as u16);
            pkt.set_payload(&payload);
            let src = src_ip_override.unwrap_or(Ipv4Addr::new(0,0,0,0));
            pkt.set_checksum(udp::ipv4_checksum(&pkt.to_immutable(), &src, &dst_ip));
            (buf.len(), buf)
        }
        ProbeProtocolType::Tcp => {
            let mut buf = vec![0u8; 20 + payload.len()];
            let mut pkt = MutableTcpPacket::new(&mut buf).ok_or_else(|| anyhow!("Failed to create TCP packet"))?;
            pkt.set_source(rng.random_range(33434..=65535));
            pkt.set_destination(rng.random_range(33434..=65535));
            pkt.set_sequence(rng.random());
            pkt.set_acknowledgement(0);
            pkt.set_data_offset(5);
            pkt.set_flags(TcpFlags::SYN);
            pkt.set_window(rng.random_range(1024..=65535));
            pkt.set_urgent_ptr(0);
            pkt.set_payload(&payload);
            let src = src_ip_override.unwrap_or(Ipv4Addr::new(0,0,0,0));
            pkt.set_checksum(tcp::ipv4_checksum(&pkt.to_immutable(), &src, &dst_ip));
            (buf.len(), buf)
        }
    };

    let total_len = (IPV4_HEADER_LEN + transport_header_len) as u16;
    let mut ip_buf = vec![0u8; total_len as usize];

    let src_ip = src_ip_override
        .or_else(|| SPOOF_SRC_IP_CONFIG.map(str::parse).transpose().ok().flatten())
        .unwrap_or(Ipv4Addr::new(0,0,0,0));

    {
        let mut ip = MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| anyhow!("Failed to create IPv4 packet"))?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len);
        ip.set_identification(sig.id);
        ip.set_ttl(current_ttl);
        ip.set_next_level_protocol(protocol_type.to_ip_next_header_protocol());
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_dscp(sig.tos >> 2);
        ip.set_ecn(sig.tos & 0x03);
        let mut flags = 0;
        if sig.df_flag {
            flags |= IPV4_FLAG_DF;
        }
        ip.set_flags(flags.try_into().unwrap_or(0));
        ip.set_payload(&transport_packet_data);
        ip.set_checksum(ipv4::checksum(&ip.to_immutable()));
    }

    Ok((ip_buf, protocol_type, sig))
}




async fn send_and_receive_one(
    target_final_dst_ip: Ipv4Addr,
    probe_packet_bytes: &[u8],
    probe_protocol: ProbeProtocolType,
    probe_ip_id: u16,
    probe_icmp_echo_id: u16,
    probe_icmp_echo_seq: u16,
    timeout: Duration,
) -> Result<Option<ProbeSingleResponse>> {
    let sender_socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_RAW)),
    )
    .context("Failed to create sender raw socket")?;
    sender_socket
        .set_header_included_v4(true)
        .context("Failed to set IP_HDRINCL on sender socket")?;

    let receiver_socket = Arc::new(
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .context("Failed to create receiver raw socket for ICMP")?,
    );
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .context("Failed to set read timeout on receiver socket")?;

    let dst_addr = SocketAddr::new(IpAddr::V4(target_final_dst_ip), 0);
    sender_socket
        .send_to(probe_packet_bytes, &dst_addr.into())
        .context("Failed to send raw IP packet")?;

    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout {
            return Ok(None);
        }

        let sock_clone = receiver_socket.try_clone().context("Socket clone failed")?;
        let recv = task::spawn_blocking(move || -> Result<Option<(Vec<u8>, SocketAddr)>, std::io::Error> {
            let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
            match sock_clone.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    // Safe conversion: we know len is valid and within buf bounds
                    if len > buf.len() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid buffer length"));
                    }
                    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };
                    let sock_addr = addr.as_socket().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "convert"))?;
                    Ok(Some((slice.to_vec(), sock_addr)))
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
        .context("Blocking task for recv_from failed")?;

        if let Some((data, sa)) = recv? {
            let rtt = start.elapsed().as_secs_f32() * 1000.0;
            let responder = if let IpAddr::V4(ip) = sa.ip() { ip } else { continue; };

            if let Some(ip_pkt) = ipv4::Ipv4Packet::new(&data) {
                if ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                    if let Some(icmp_pkt) = icmp::IcmpPacket::new(ip_pkt.payload()) {
                        let icmp_type = icmp_pkt.get_icmp_type();
                        let _ = icmp_pkt.get_icmp_code();
                        let mut matched = false;

                        if icmp_type == IcmpTypes::TimeExceeded || icmp_type == IcmpTypes::DestinationUnreachable {
                            if let Some(inner) = ipv4::Ipv4Packet::new(icmp_pkt.payload()) {
                                if inner.get_destination() == target_final_dst_ip && inner.get_identification() == probe_ip_id {
                                    let proto = inner.get_next_level_protocol();
                                    match probe_protocol {
                                        ProbeProtocolType::Icmp => {
                                            if proto == IpNextHeaderProtocols::Icmp {
                                                if let Some(echo_req) = echo_request::EchoRequestPacket::new(inner.payload()) {
                                                    if echo_req.get_icmp_type() == IcmpTypes::EchoRequest
                                                        && echo_req.get_identifier() == probe_icmp_echo_id
                                                        && echo_req.get_sequence_number() == probe_icmp_echo_seq
                                                    {
                                                        matched = true;
                                                    }
                                                }
                                            }
                                        }
                                        ProbeProtocolType::Udp | ProbeProtocolType::Tcp => {
                                            if proto == probe_protocol.to_ip_next_header_protocol() {
                                                matched = true;
                                            }
                                        }
                                    }
                                }
                            }
                        } else if icmp_type == IcmpTypes::EchoReply && probe_protocol == ProbeProtocolType::Icmp {
                            if let Some(reply) = echo_reply::EchoReplyPacket::new(icmp_pkt.packet()) {
                                if reply.get_identifier() == probe_icmp_echo_id
                                    && reply.get_sequence_number() == probe_icmp_echo_seq
                                    && responder == target_final_dst_ip
                                {
                                    matched = true;
                                }
                            }
                        }

                        if matched {
                            let desc = match icmp_type {
                                IcmpTypes::EchoReply => "echo-reply".to_string(),
                                IcmpTypes::DestinationUnreachable => "unreachable".to_string(),
                                IcmpTypes::TimeExceeded => "time-exceeded".to_string(),
                                _ => format!("type {}", icmp_type.0),
                            };
                            return Ok(Some(ProbeSingleResponse {
                                source_ip: responder,
                                rtt_ms: rtt,
                                icmp_info: ReceivedIcmpInfo { icmp_type: icmp_type.0, description: desc },
                                probe_protocol_used: probe_protocol.to_string_lc(),
                            }));
                        }
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn execute_traceroute(target_name: &str) -> Result<()> {
    println!("{}", format!("[+] Traceroute to {} (max {} hops)", target_name, MAX_TTL).cyan());

    let resolved_ips = tokio::net::lookup_host(format!("{}:0", target_name))
        .await
        .with_context(|| format!("Could not resolve target: {}", target_name))?;

    let mut target_ipv4: Option<Ipv4Addr> = None;
    for sock_addr in resolved_ips {
        if let IpAddr::V4(ipv4) = sock_addr.ip() {
            target_ipv4 = Some(ipv4);
            break;
        }
    }

    let dst_ip = match target_ipv4 {
        Some(ip) => ip,
        None => bail!("Could not resolve {} to an IPv4 address", target_name),
    };

    println!("{}", format!("[*] Resolved {} to {}", target_name, dst_ip).green());

    let src_ip_override_opt: Option<Ipv4Addr> = SPOOF_SRC_IP_CONFIG.and_then(|s| s.parse().ok());


    for ttl_val in 1..=MAX_TTL {
        let line_prefix = format!("[TTL={:2}] ", ttl_val).yellow().to_string();
        let mut ttl_responded = false;

        for _probe_idx in 0..PROBE_COUNT {
            // Scope RNG to avoid holding it across await
            let (icmp_probe_id, packet_bytes, protocol_used, os_sig_params) = {
                let mut rng = rand::rng();
                let icmp_probe_id = rng.random_range(33434..=65535);
                let icmp_probe_seq = ttl_val as u16;

                let (packet_bytes, protocol_used, os_sig_params) = craft_probe_packet(
                    dst_ip,
                    ttl_val,
                    src_ip_override_opt,
                    icmp_probe_id,
                    icmp_probe_seq,
                )?;
                (icmp_probe_id, packet_bytes, protocol_used, os_sig_params)
            };

            let _t0 = Instant::now();
            let response = send_and_receive_one(
                dst_ip,
                &packet_bytes,
                protocol_used,
                os_sig_params.id,
                icmp_probe_id,
                ttl_val as u16,
                Duration::from_secs(2),
            ).await?;

            if let Some(res) = response {
                ttl_responded = true;
                let rtt_str = format!("{:.1}ms", res.rtt_ms);

                print!("{}{:<16} ", line_prefix, res.source_ip.to_string().bright_white());
                print!("{} ", res.icmp_info.description);
                println!("({}) {}", res.probe_protocol_used.dimmed(), rtt_str);

                if res.source_ip == dst_ip {
                    if res.icmp_info.icmp_type == IcmpTypes::EchoReply.0 ||
                        (res.icmp_info.icmp_type == IcmpTypes::DestinationUnreachable.0 && res.source_ip == dst_ip) {
                        println!("{}", format!("[+] Target reached: {}", res.source_ip).green());
                        return Ok(());
                    }
                }
            }

            let jitter_duration = {
                let mut rng = rand::rng(); // New RNG for jitter
                rng.random_range(JITTER_RANGE.0..JITTER_RANGE.1)
            };
            tokio::time::sleep(Duration::from_secs_f32(jitter_duration)).await;
        }

        if !ttl_responded {
            println!("{}{}", line_prefix, "BLOCKED / FILTERED".red().bold());
        }
    }

    Ok(())
}

pub async fn run(target: &str) -> Result<()> {
    let mut user_input = String::new();
    print!("Are you running this as sudo? (yes/no): ");
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    std::io::stdin()
        .read_line(&mut user_input)
        .context("Failed to read input")?;

    if user_input.trim().to_lowercase() == "yes" {
        // Safe wrapper for geteuid - it's a simple system call that cannot fail
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            println!("don't lie");
            std::process::exit(1);
        }
    } else if user_input.trim().to_lowercase() == "no" {
        println!("Please run this script as sudo.");
        std::process::exit(1);
    } else {
        println!("Invalid input. Exiting.");
        std::process::exit(1);
    }

    println!("by suicidalteddy");
    println!("github.com/s-b-repo");
    println!("medium.com/@suicdalteddy/about");

    if target.is_empty() {
        bail!("No target provided.");
    }

    execute_traceroute(target).await.map_err(|e| {
        eprintln!("{}", format!("[-] Error: {}", e).red());
        e
    })
}
