use std::path::Path;

use anyhow::{Context, Result};
use quick_xml::Reader;
use quick_xml::events::Event;

pub async fn import_nmap_xml(path: &Path) -> Result<(usize, usize)> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read nmap XML '{}'", path.display()))?;

    let mut reader = Reader::from_str(&content);
    reader.config_mut().trim_text(true);

    let mut hosts = 0usize;
    let mut services = 0usize;
    let mut buf = Vec::new();
    let mut current_host: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"address" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"addr" {
                            if let Ok(ip) = String::from_utf8(attr.value.to_vec()) {
                                current_host = Some(ip);
                            }
                        }
                    }
                }
                b"port" => {
                    if let Some(ref host) = current_host {
                        let mut port: u16 = 0;
                        let mut protocol = String::new();
                        let mut service_name = String::new();
                        let mut version: Option<String> = None;

                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"portid" => {
                                    if let Ok(s) = String::from_utf8(attr.value.to_vec()) {
                                        port = match s.parse() {
                                            Ok(p) => p,
                                            Err(e) => {
                                                tracing::trace!("unparseable port: {} ({})", s, e);
                                                0
                                            }
                                        };
                                    }
                                }
                                b"protocol" => {
                                    if let Ok(s) = String::from_utf8(attr.value.to_vec()) {
                                        protocol = s;
                                    }
                                }
                                _ => {}
                            }
                        }

                        loop {
                            match reader.read_event_into(&mut buf) {
                                Ok(Event::Start(ref inner))
                                    if inner.name().as_ref() == b"service" =>
                                {
                                    for attr in inner.attributes().flatten() {
                                        match attr.key.as_ref() {
                                            b"name" => {
                                                if let Ok(s) =
                                                    String::from_utf8(attr.value.to_vec())
                                                {
                                                    service_name = s;
                                                }
                                            }
                                            b"product" => {
                                                if let Ok(s) =
                                                    String::from_utf8(attr.value.to_vec())
                                                {
                                                    if !s.is_empty() {
                                                        version = Some(s.clone());
                                                    }
                                                }
                                            }
                                            b"version" => {
                                                if let Ok(s) =
                                                    String::from_utf8(attr.value.to_vec())
                                                {
                                                    if !s.is_empty() {
                                                        match version {
                                                            Some(ref mut v) => {
                                                                v.push(' ');
                                                                v.push_str(&s);
                                                            }
                                                            None => version = Some(s),
                                                        }
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                Ok(Event::End(ref e)) if e.name().as_ref() == b"port" => {
                                    break;
                                }
                                Ok(Event::Eof) => break,
                                Err(e) => {
                                    tracing::trace!("XML parse skip: {}", e);
                                    break;
                                }
                                _ => {}
                            }
                        }

                        if port > 0 && !protocol.is_empty() {
                            crate::workspace::track_service(
                                host,
                                port,
                                &protocol,
                                &service_name,
                                version.as_deref(),
                            )
                            .await;
                            services += 1;
                        }
                    }
                }
                b"hostnames" => {
                    if let Some(ref host) = current_host {
                        crate::workspace::track_host(host, None, None).await;
                        hosts += 1;
                    }
                }
                _ => {}
            },
            Ok(Event::End(ref e)) if e.name().as_ref() == b"host" => {
                if current_host.take().is_some() && hosts == 0 {
                    hosts = 1;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                anyhow::bail!(
                    "XML parse error at position {}: {}",
                    reader.buffer_position(),
                    e
                );
            }
            _ => {}
        }
        buf.clear();
    }

    if hosts == 0 && !current_host.is_none() {
        let host = current_host.take().unwrap_or_default();
        crate::workspace::track_host(&host, None, None).await;
        hosts = 1;
    }

    Ok((hosts, services))
}
