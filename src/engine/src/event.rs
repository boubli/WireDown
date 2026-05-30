// wd-engine — NDJSON event types and the UDS bridge writer.
//
// Every event becomes ONE line of JSON terminated by `\n`. The Python
// control plane (backend/wd_engine_bridge.py) reads with .readline()
// and dispatches by `kind`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Device(DeviceEvent),
    Threat(ThreatEvent),
    Dns(DnsEvent),
    Stat(StatEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEvent {
    pub ts:       f64,
    pub mac:      String,
    pub ip:       String,
    pub vendor:   String,
    pub hostname: String,
    pub source:   &'static str,   // "arp" | "dhcp"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub ts:      f64,
    pub src_ip:  String,
    pub mac:     String,
    pub signal:  String,          // matches Python ThreatEngine signal types
    pub weight:  u32,             // suggested score weight
    pub detail:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub ts:         f64,
    pub client_ip:  String,
    pub query:      String,
    pub qtype:      String,
    pub sinkholed:  bool,
    pub upstream:   bool,          // forwarded to upstream resolver?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatEvent {
    pub ts:         f64,
    pub pkts_in:    u64,
    pub bytes_in:   u64,
    pub dns_qps:    f32,
}

pub fn now_ts() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
