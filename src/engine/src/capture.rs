// wd-engine — AF_PACKET capture worker.
//
// Uses pnet's datalink::channel which sits on top of AF_PACKET with the
// SOCK_RAW + ETH_P_ALL combo. For best throughput in production, swap
// the channel for a TPACKET_V3 mmap'd ring buffer (the `pnet_datalink`
// `Linux` backend already calls `setsockopt(PACKET_RX_RING)` internally
// when `Config::read_buffer_size` is set).

use anyhow::{Context, Result};
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use tokio::sync::mpsc;

use crate::arp;
use crate::event::Event;
use crate::portscan;

pub fn run(iface_name: &str, tx: mpsc::Sender<Event>) -> Result<()> {
    let iface: NetworkInterface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface_name)
        .with_context(|| format!("interface {iface_name} not found"))?;

    let cfg = Config {
        read_buffer_size: 1 << 20,     // 1 MB kernel ring per socket
        write_buffer_size: 1 << 16,
        read_timeout: Some(std::time::Duration::from_millis(500)),
        promiscuous: true,
        ..Default::default()
    };

    let (_tx_raw, mut rx_raw) = match datalink::channel(&iface, cfg)? {
        Ethernet(t, r) => (t, r),
        _ => anyhow::bail!("unsupported datalink channel for {iface_name}"),
    };

    log::info!(
        "AF_PACKET ring open on {} (promisc, 1MB ring)",
        iface_name
    );

    let mut portscan_state = portscan::State::new();

    loop {
        match rx_raw.next() {
            Ok(packet) => {
                if let Err(e) = dispatch(packet, &tx, &mut portscan_state) {
                    log::trace!("dispatch dropped a packet: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                log::error!("capture read error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
}

fn dispatch(
    packet: &[u8],
    tx: &mpsc::Sender<Event>,
    portscan_state: &mut portscan::State,
) -> Result<()> {
    use etherparse::{InternetSlice, SlicedPacket};

    let slc = SlicedPacket::from_ethernet(packet)
        .map_err(|e| anyhow::anyhow!("eth parse: {e}"))?;

    // ARP path: etherparse doesn't decode ARP payloads, so peek the EtherType
    // directly from the L2 header (0x0806). Same for DHCP we'll catch from
    // UDP src/dst port 67/68 below.
    if packet.len() >= 14 {
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype == 0x0806 {
            if let Some(evt) = arp::parse_arp(&packet[14..]) {
                let _ = tx.try_send(Event::Device(evt));
            }
            return Ok(());
        }
    }

    if let Some(InternetSlice::Ipv4(ip4, _)) = slc.ip.as_ref() {
        let src = ip4.source_addr();
        let dst = ip4.destination_addr();

        // UDP/67-68 = DHCP, UDP/53 (request side) handled by the sinkhole worker
        // that owns udp/53 outright. We only watch DHCP here.
        if let Some(etherparse::TransportSlice::Udp(udp)) = slc.transport.as_ref() {
            let sport = udp.source_port();
            let dport = udp.destination_port();
            if sport == 67 || sport == 68 || dport == 67 || dport == 68 {
                if let Some(evt) = arp::parse_dhcp(slc.payload, src) {
                    let _ = tx.try_send(Event::Device(evt));
                }
            }
        }

        // TCP SYN-burst → port scan heuristic.
        if let Some(etherparse::TransportSlice::Tcp(tcp)) = slc.transport.as_ref() {
            if tcp.syn() && !tcp.ack() {
                if let Some(evt) = portscan_state.observe(src, dst, tcp.destination_port()) {
                    let _ = tx.try_send(Event::Threat(evt));
                }
            }
        }
    }

    Ok(())
}
