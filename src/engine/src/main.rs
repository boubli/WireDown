// WireDown wd-engine — entrypoint
//
// Boots the four data-plane workers (capture, dns sinkhole, arp/dhcp parser,
// portscan heuristic) and the UDS bridge that streams NDJSON events to the
// Python control plane.

mod arp;
mod bridge;
mod capture;
mod dns;
mod event;
mod oui;
mod portscan;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Parser, Debug, Clone)]
#[command(name = "wd-engine", version, about = "WireDown data-plane daemon")]
struct Args {
    /// Bridge or LAN interface to tap (promiscuous AF_PACKET).
    #[arg(long, default_value = "br0")]
    iface: String,

    /// Unix-Domain-Socket path for the Python control-plane bridge.
    #[arg(long, default_value = "/run/wiredown.sock")]
    uds: PathBuf,

    /// Upstream resolver for non-blocked DNS queries.
    #[arg(long, default_value = "1.1.1.1")]
    upstream_dns: String,

    /// Blocklist file, one domain per line.
    #[arg(long, default_value = "/etc/wiredown/blocklist.txt")]
    blocklist: PathBuf,

    /// IP returned in `A` answers for sinkholed queries (auto-detect if empty).
    #[arg(long, default_value = "")]
    sinkhole_ip: String,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Compact env_logger init — humantime timestamps, single line per event.
    std::env::set_var("RUST_LOG", &args.log_level);
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .format_target(false)
        .init();

    log::info!("wd-engine starting | iface={} uds={:?}", args.iface, args.uds);

    // Event bus: capacity 4096 = ~1 MB at worst-case event sizes; back-pressure
    // bridge_writer if Python control-plane is slow.
    let (tx, rx) = mpsc::channel::<event::Event>(4096);

    // Spawn workers.
    let cap_tx = tx.clone();
    let cap_iface = args.iface.clone();
    let cap_handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = capture::run(&cap_iface, cap_tx) {
            log::error!("capture worker exited: {e:?}");
        }
    });

    let dns_tx = tx.clone();
    let dns_args = args.clone();
    tokio::spawn(async move {
        if let Err(e) = dns::run(dns_args.blocklist, dns_args.sinkhole_ip, dns_tx).await {
            log::error!("dns sinkhole exited: {e:?}");
        }
    });

    let bridge_uds = args.uds.clone();
    let bridge_handle = tokio::spawn(async move {
        if let Err(e) = bridge::serve_uds(bridge_uds, rx).await {
            log::error!("bridge exited: {e:?}");
        }
    });

    // Graceful shutdown on SIGTERM.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => log::info!("SIGINT received; shutting down"),
        _ = cap_handle => log::warn!("capture worker finished"),
        _ = bridge_handle => log::warn!("bridge worker finished"),
    }
    Ok(())
}
