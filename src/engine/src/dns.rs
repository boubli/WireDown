// wd-engine — DNS sinkhole.
//
// Binds udp/53. Each incoming query is parsed. If the queried name
// matches the blocklist (built from the file at startup), we synthesise
// an A response pointing at sinkhole_ip and emit a Dns/Threat event.
// Otherwise the query is forwarded to upstream_dns and the answer is
// relayed back to the client (stateless transparent proxy).

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::event::{now_ts, DnsEvent, Event, ThreatEvent};

pub async fn run(
    blocklist_path: PathBuf,
    sinkhole_ip: String,
    tx: mpsc::Sender<Event>,
) -> Result<()> {
    let blocklist = load_blocklist(&blocklist_path).await;
    log::info!(
        "DNS blocklist loaded: {} entries from {:?}",
        blocklist.len(),
        blocklist_path
    );

    let bind = "0.0.0.0:53";
    let server = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind {bind} (need CAP_NET_BIND_SERVICE)"))?;
    log::info!("DNS sinkhole listening on udp/53");

    let upstream: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let sinkhole_ipv4: Ipv4Addr = if sinkhole_ip.is_empty() {
        // Convention: when not set, sinkhole to ourselves on the LAN.
        // The platform adapter will rewrite this with the real LAN IP.
        Ipv4Addr::new(0, 0, 0, 0)
    } else {
        sinkhole_ip.parse().unwrap_or(Ipv4Addr::new(0, 0, 0, 0))
    };

    let mut buf = vec![0u8; 1500];
    loop {
        let (len, peer) = match server.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => { log::warn!("recv_from: {e}"); continue; }
        };
        let qbytes = &buf[..len];

        let (qname, qtype_str) = match parse_question(qbytes) {
            Some(v) => v,
            None => continue,
        };

        let blocked = blocklist.contains(qname.to_ascii_lowercase().trim_end_matches('.'));

        if blocked {
            // Build A-record response pointing at sinkhole_ipv4.
            if let Some(resp) = build_a_response(qbytes, sinkhole_ipv4) {
                let _ = server.send_to(&resp, peer).await;
            }
            let _ = tx.try_send(Event::Dns(DnsEvent {
                ts: now_ts(),
                client_ip: peer.ip().to_string(),
                query: qname.clone(),
                qtype: qtype_str.clone(),
                sinkholed: true,
                upstream: false,
            }));
            let _ = tx.try_send(Event::Threat(ThreatEvent {
                ts: now_ts(),
                src_ip: peer.ip().to_string(),
                mac: String::new(),
                signal: "dns_sinkhole_hit".into(),
                weight: 40,
                detail: qname,
            }));
        } else {
            // Forward upstream (one-shot UDP relay).
            let relay = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => continue,
            };
            if relay.send_to(qbytes, upstream).await.is_err() { continue; }
            let mut rbuf = vec![0u8; 1500];
            let rlen = match tokio::time::timeout(
                std::time::Duration::from_millis(900),
                relay.recv_from(&mut rbuf),
            ).await {
                Ok(Ok((n, _))) => n,
                _ => continue,
            };
            let _ = server.send_to(&rbuf[..rlen], peer).await;
            let _ = tx.try_send(Event::Dns(DnsEvent {
                ts: now_ts(),
                client_ip: peer.ip().to_string(),
                query: qname,
                qtype: qtype_str,
                sinkholed: false,
                upstream: true,
            }));
        }
    }
}

async fn load_blocklist(path: &PathBuf) -> HashSet<String> {
    let mut set = HashSet::with_capacity(64_000);
    if let Ok(content) = tokio::fs::read_to_string(path).await {
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            // Allow "0.0.0.0 evil.com" or just "evil.com".
            let host = line.split_whitespace().last().unwrap_or("");
            if host.is_empty() { continue; }
            set.insert(host.to_ascii_lowercase());
        }
    } else {
        // Tiny built-in seed so the engine has SOMETHING to do on a virgin install.
        for &dom in &[
            "evil.com", "malware.test", "c2.attacker.net",
            "exfil.io", "beacon.malware.xyz",
        ] {
            set.insert(dom.to_string());
        }
    }
    set
}

fn parse_question(buf: &[u8]) -> Option<(String, String)> {
    if buf.len() < 12 { return None; }
    let mut i = 12;
    let mut name = String::new();
    while i < buf.len() {
        let lbl = buf[i] as usize;
        if lbl == 0 { i += 1; break; }
        if (lbl & 0xC0) == 0xC0 { return None; } // refuse compressed Qname
        i += 1;
        if i + lbl > buf.len() { return None; }
        if !name.is_empty() { name.push('.'); }
        name.push_str(&String::from_utf8_lossy(&buf[i..i + lbl]));
        i += lbl;
    }
    if i + 4 > buf.len() { return None; }
    let qtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
    let qtype_str = match qtype {
        1 => "A", 28 => "AAAA", 5 => "CNAME", 15 => "MX",
        16 => "TXT", 2 => "NS", 12 => "PTR", _ => "OTHER",
    }.to_string();
    Some((name, qtype_str))
}

fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 { return None; }
    let mut resp = Vec::with_capacity(query.len() + 16);
    // Header: copy txn id, set flags=0x8180, qdcount=1, ancount=1.
    resp.extend_from_slice(&query[0..2]);
    resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);

    // Append the original question section verbatim.
    let mut i = 12;
    while i < query.len() {
        let lbl = query[i] as usize;
        if lbl == 0 { i += 1; break; }
        if (lbl & 0xC0) == 0xC0 { return None; }
        i += 1 + lbl;
        if i > query.len() { return None; }
    }
    if i + 4 > query.len() { return None; }
    resp.extend_from_slice(&query[12..i + 4]);   // qname + qtype + qclass

    // Answer: pointer to qname at offset 12, type A, class IN, ttl 60, rdlen 4, IP.
    resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
    resp.extend_from_slice(&ip.octets());
    Some(resp)
}
