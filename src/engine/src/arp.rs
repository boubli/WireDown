// wd-engine — passive ARP + DHCP parsing → DeviceEvent
//
// ARP parsing follows RFC 826 frame layout. DHCP parsing follows RFC 2131:
// we extract the chaddr (client MAC) and option 12 (hostname) when present.

use std::net::Ipv4Addr;

use crate::event::{now_ts, DeviceEvent};
use crate::oui;

pub fn parse_arp(payload: &[u8]) -> Option<DeviceEvent> {
    // ARP: HTYPE(2) PTYPE(2) HLEN(1) PLEN(1) OPER(2) SHA(6) SPA(4) THA(6) TPA(4)
    if payload.len() < 28 { return None; }
    if payload[4] != 6 || payload[5] != 4 { return None; } // Ether/IPv4 only
    let oper = u16::from_be_bytes([payload[6], payload[7]]);
    if oper != 2 { return None; } // Only reply frames carry a confirmed S(MAC,IP) binding

    let sha = &payload[8..14];
    let spa = &payload[14..18];
    let mac = format_mac(sha);
    let ip = Ipv4Addr::new(spa[0], spa[1], spa[2], spa[3]).to_string();
    let vendor = oui::lookup(sha).to_string();

    Some(DeviceEvent {
        ts: now_ts(),
        mac,
        ip,
        vendor,
        hostname: String::new(),
        source: "arp",
    })
}

/// Parse a DHCP message and return a DeviceEvent on REQUEST/ACK frames.
pub fn parse_dhcp(udp_payload: &[u8], src_ip: Ipv4Addr) -> Option<DeviceEvent> {
    // DHCP minimum: 240 bytes fixed header + magic cookie.
    if udp_payload.len() < 240 { return None; }
    // chaddr lives at offset 28..34 (we ignore hlen since IEEE-802 == 6).
    let chaddr = &udp_payload[28..34];
    if chaddr.iter().all(|&b| b == 0) { return None; }
    let mac = format_mac(chaddr);

    // Walk options for type (53), hostname (12), and yiaddr if it's a server-side ACK.
    let mut hostname = String::new();
    let mut msg_type: u8 = 0;
    let mut yiaddr = src_ip;

    // yiaddr at offset 16..20 in the fixed header.
    if let [a, b, c, d] = udp_payload[16..20] {
        let ip = Ipv4Addr::new(a, b, c, d);
        if !ip.is_unspecified() { yiaddr = ip; }
    }

    // Magic cookie sits at 236..240 (0x63825363). Options follow.
    let mut i = 240;
    while i < udp_payload.len() {
        let opt = udp_payload[i];
        if opt == 0xFF { break; }    // END
        if opt == 0x00 { i += 1; continue; }  // PAD
        if i + 1 >= udp_payload.len() { break; }
        let len = udp_payload[i + 1] as usize;
        let val_start = i + 2;
        let val_end = val_start + len;
        if val_end > udp_payload.len() { break; }
        let val = &udp_payload[val_start..val_end];

        match opt {
            53 => { if !val.is_empty() { msg_type = val[0]; } }
            12 => { hostname = String::from_utf8_lossy(val).trim().to_string(); }
            _ => {}
        }
        i = val_end;
    }

    // Emit on REQUEST(3), ACK(5), DECLINE(4), INFORM(8) — everything that
    // confirms a client identity. SKIP DISCOVER(1)/OFFER(2) to reduce noise.
    if !matches!(msg_type, 3 | 4 | 5 | 8) { return None; }

    Some(DeviceEvent {
        ts: now_ts(),
        mac,
        ip: yiaddr.to_string(),
        vendor: oui::lookup(chaddr).to_string(),
        hostname,
        source: "dhcp",
    })
}

fn format_mac(b: &[u8]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}
