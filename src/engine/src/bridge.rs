// wd-engine — UDS bridge to the Python control plane.
//
// Accepts a single subscriber at a time on /run/wiredown.sock. Each event
// from the in-process mpsc channel is serialised to NDJSON and written.
// If no subscriber is connected, events are dropped (the Python side
// re-syncs on reconnect by reading the live device_registry over REST).

use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::event::Event;

pub async fn serve_uds(path: PathBuf, mut rx: mpsc::Receiver<Event>) -> Result<()> {
    // Remove stale socket from previous boot.
    let _ = tokio::fs::remove_file(&path).await;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind UDS {:?}", path))?;
    // World-writable so the Python control plane (different uid in some
    // deployments) can connect.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).await;
    }

    log::info!("UDS bridge listening on {:?}", path);

    let mut current: Option<UnixStream> = None;

    loop {
        tokio::select! {
            // New subscriber. Replace any prior one (single-consumer design).
            Ok((stream, _)) = listener.accept() => {
                log::info!("control-plane subscriber connected");
                current = Some(stream);
            }

            // Drain the event channel.
            Some(evt) = rx.recv() => {
                if let Some(stream) = current.as_mut() {
                    match serde_json::to_vec(&evt) {
                        Ok(mut line) => {
                            line.push(b'\n');
                            if let Err(e) = stream.write_all(&line).await {
                                log::warn!("subscriber write failed: {e}; dropping subscriber");
                                current = None;
                            }
                        }
                        Err(e) => log::error!("serialise event failed: {e}"),
                    }
                }
                // No subscriber → event is silently dropped (lossy stream).
            }
        }
    }
}
