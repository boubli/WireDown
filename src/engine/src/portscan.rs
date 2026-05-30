// wd-engine — SYN-burst port scan heuristic.
//
// Lightweight ring of (src_ip → set of dst_ports seen in last 10s). When
// the set crosses PORT_BURST_THRESHOLD, we emit a Threat event.

use ahash::AHashMap;
use ahash::AHashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::event::{now_ts, ThreatEvent};

const WINDOW: Duration = Duration::from_secs(10);
const PORT_BURST_THRESHOLD: usize = 12;

pub struct State {
    by_src: AHashMap<Ipv4Addr, (Instant, AHashSet<u16>)>,
}

impl State {
    pub fn new() -> Self { Self { by_src: AHashMap::new() } }

    pub fn observe(&mut self, src: Ipv4Addr, _dst: Ipv4Addr, dport: u16) -> Option<ThreatEvent> {
        let now = Instant::now();
        let entry = self.by_src.entry(src).or_insert_with(|| (now, AHashSet::new()));
        if now.duration_since(entry.0) > WINDOW {
            entry.0 = now;
            entry.1.clear();
        }
        entry.1.insert(dport);

        if entry.1.len() >= PORT_BURST_THRESHOLD {
            let detail = format!(
                "SYN burst: {} distinct dst ports in {:?}",
                entry.1.len(), WINDOW
            );
            entry.1.clear();
            return Some(ThreatEvent {
                ts: now_ts(),
                src_ip: src.to_string(),
                mac: String::new(),
                signal: "port_scan_flood".into(),
                weight: 60,
                detail,
            });
        }
        None
    }
}
