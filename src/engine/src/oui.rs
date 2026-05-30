// wd-engine — IEEE OUI vendor lookup.
//
// At build time we bundle a tiny default table; at runtime the Python
// control plane refreshes /etc/wiredown/oui.csv monthly (see
// backend/oui_updater.py). This module looks up the prefix in the
// bundled table only — production builds replace `BUILTIN` with the
// concatenated CSV via `include_str!("../../oui.csv")`.

use once_cell::sync::Lazy;
use std::collections::HashMap;

// Minimal seed list. The Python `oui_updater` will mmap a full
// IEEE OUI CSV at /etc/wiredown/oui.csv that the engine can re-read
// on SIGHUP (production refinement; not in v0.1).
const BUILTIN: &str = "\
00:00:0C,Cisco Systems Inc
00:11:32,Synology Inc.
00:1A:2B,Generic Vendor
00:50:56,VMware Inc.
24:6F:28,Espressif Systems
3C:D9:2B,HP Inc.
5C:A6:E6,Amazon Technologies
A4:83:E7,Intel Corporate
A8:66:7F,Apple Inc.
B4:F1:DA,Samsung Electronics
D8:31:34,Roku Inc.
F0:18:98,Apple Inc.
DE:AD:BE,Honeypot Bait
";

static TABLE: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for line in BUILTIN.lines() {
        if let Some((prefix, vendor)) = line.split_once(',') {
            m.insert(prefix, vendor);
        }
    }
    m
});

pub fn lookup(mac_bytes: &[u8]) -> &'static str {
    if mac_bytes.len() < 3 { return "Unknown"; }
    let key = format!(
        "{:02X}:{:02X}:{:02X}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2]
    );
    // Lookup needs an owned key; leak the small string into &'static via Box::leak
    // ONLY on cache miss (rare; happens once per never-seen OUI).
    match TABLE.get(key.as_str()) {
        Some(v) => v,
        None => "Unknown",
    }
}
