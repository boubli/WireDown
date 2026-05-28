"""
WireDown Honeypot — Port Scan Detector
========================================
Opens lightweight TCP listeners on common service ports.  Each listener
sends a realistic service banner then closes the connection.  When a
single source IP connects to more than 5 distinct ports within a
10-second window the registered callback is fired.
"""

import logging
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("wiredown.port_scan_detector")

# ---------------------------------------------------------------------------
# Service banners
# ---------------------------------------------------------------------------

def _ftp_banner() -> bytes:
    return b"220 ProFTPD 1.3.8 Server ready.\r\n"


def _telnet_banner() -> bytes:
    # IAC DO SUPPRESS-GO-AHEAD, IAC WILL ECHO — standard Telnet negotiation
    return bytes([
        0xFF, 0xFD, 0x03,   # IAC DO SUPPRESS-GO-AHEAD
        0xFF, 0xFB, 0x01,   # IAC WILL ECHO
        0xFF, 0xFB, 0x03,   # IAC WILL SUPPRESS-GO-AHEAD
    ]) + b"\r\nLogin: "


def _smtp_banner() -> bytes:
    return b"220 mail.honeypot.local ESMTP Postfix (Ubuntu)\r\n"


def _http_banner() -> bytes:
    body = (
        b"<html><head><title>Welcome</title></head>"
        b"<body><h1>It works!</h1></body></html>"
    )
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.54 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


def _https_banner() -> bytes:
    # TLS 1.2 Alert: Handshake Failure (level=fatal, desc=40)
    # Enough to look like a real TLS service that the scanner can fingerprint
    return bytes([
        0x15,              # ContentType: Alert
        0x03, 0x03,        # TLS 1.2
        0x00, 0x02,        # Length
        0x02, 0x28,        # fatal / handshake_failure
    ])


def _smb_banner() -> bytes:
    # Minimal SMBv1 negotiation error response (just enough to look real)
    header = b"\x00\x00\x00\x25"                        # NetBIOS length
    header += b"\xFFSMB"                                 # SMB magic
    header += b"\x72"                                    # Negotiate command
    header += b"\x00\x00\x00\x00"                        # Status: OK
    header += b"\x98"                                    # Flags
    header += b"\x01\x20"                                # Flags2
    header += b"\x00" * 24                               # Padding / fields
    return header


def _mysql_banner() -> bytes:
    # MySQL 8.0 initial handshake (simplified but structurally valid)
    server_version = b"8.0.36-0ubuntu0.22.04.1\x00"
    # Packet header: length (3 bytes LE) + sequence id (1 byte)
    payload = b"\x0a"  # protocol version 10
    payload += server_version
    payload += struct.pack("<I", 12345)  # connection id
    payload += b"abcdefgh"               # auth-plugin-data part 1
    payload += b"\x00"                   # filler
    payload += struct.pack("<H", 0xFFFF) # capability flags lower
    payload += b"\x21"                   # charset utf8
    payload += struct.pack("<H", 0x0002) # status flags
    payload += struct.pack("<H", 0x8000) # capability flags upper
    payload += b"\x15"                   # auth plugin data length
    payload += b"\x00" * 10             # reserved
    payload += b"ijklmnopqrst\x00"      # auth-plugin-data part 2
    payload += b"mysql_native_password\x00"
    pkt_len = struct.pack("<I", len(payload))[:3]
    return pkt_len + b"\x00" + payload


def _rdp_banner() -> bytes:
    # X.224 Connection Confirm (RDP)
    return bytes([
        0x03, 0x00, 0x00, 0x13,   # TPKT header
        0x0E,                      # X.224 length
        0xD0,                      # Connection Confirm
        0x00, 0x00,                # DST ref
        0x00, 0x00,                # SRC ref
        0x00,                      # Class 0
        0x02, 0x00, 0x08, 0x00,   # RDP Neg Response
        0x01, 0x00, 0x00, 0x00,   # SSL required
    ])


def _postgres_banner() -> bytes:
    # PostgreSQL AuthenticationOk-style message (type 'R')
    # Then a ReadyForQuery message to look like a real server
    auth_ok = b"R" + struct.pack("!I", 8) + struct.pack("!I", 0)
    ready = b"Z" + struct.pack("!I", 5) + b"I"
    return auth_ok + ready


def _http_proxy_banner() -> bytes:
    body = b"<html><body><h1>Squid Proxy</h1></body></html>"
    return (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Server: squid/5.7\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


def _https_alt_banner() -> bytes:
    return _https_banner()  # same TLS alert


# Port → (service name, banner factory)
PORT_MAP: Dict[int, Tuple[str, Callable[[], bytes]]] = {
    21:   ("FTP",        _ftp_banner),
    23:   ("Telnet",     _telnet_banner),
    25:   ("SMTP",       _smtp_banner),
    80:   ("HTTP",       _http_banner),
    443:  ("HTTPS",      _https_banner),
    445:  ("SMB",        _smb_banner),
    3306: ("MySQL",      _mysql_banner),
    3389: ("RDP",        _rdp_banner),
    5432: ("PostgreSQL", _postgres_banner),
    8080: ("HTTP-Proxy", _http_proxy_banner),
    8443: ("HTTPS-Alt",  _https_alt_banner),
}

# Scan-detection thresholds
SCAN_PORT_THRESHOLD = 5     # distinct ports
SCAN_TIME_WINDOW    = 10.0  # seconds


class PortScanDetector:
    """
    Opens honeypot listeners on well-known ports and detects port scanning.

    Parameters
    ----------
    callback : callable
        ``callback(ip, ports_hit, timespan)`` invoked when a scan is detected.
    host : str
        Bind address for all listeners (default ``0.0.0.0``).
    """

    def __init__(self, callback: Callable[..., Any],
                 host: str = "0.0.0.0") -> None:
        self._callback = callback
        self._host = host
        self._lock = threading.Lock()
        self._running = False

        # ip → list of (port, timestamp)
        self._connections: Dict[str, List[Tuple[int, float]]] = {}
        # full connection log
        self._log: List[Dict[str, Any]] = []
        # set of IPs already reported (to avoid duplicate callbacks)
        self._reported: Set[str] = set()

        self._server_sockets: List[socket.socket] = []
        self._threads: List[threading.Thread] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Bind to all configured ports and start accepting connections."""
        if self._running:
            return
        self._running = True

        for port, (service, _banner_fn) in PORT_MAP.items():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.settimeout(1.0)
                srv.bind((self._host, port))
                srv.listen(5)
                self._server_sockets.append(srv)

                t = threading.Thread(
                    target=self._accept_loop,
                    args=(srv, port, service, _banner_fn),
                    daemon=True,
                    name=f"portscan-{port}",
                )
                t.start()
                self._threads.append(t)
                logger.info("Listening on %s:%d (%s)", self._host, port, service)
            except OSError as exc:
                logger.error("Cannot bind %s:%d (%s): %s",
                             self._host, port, service, exc)

    def stop(self) -> None:
        """Shut down all listeners gracefully."""
        self._running = False
        for srv in self._server_sockets:
            try:
                srv.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=3)
        self._server_sockets.clear()
        self._threads.clear()
        logger.info("PortScanDetector stopped")

    def get_connections(self) -> List[Dict[str, Any]]:
        """Return a copy of the recent connection log."""
        with self._lock:
            return list(self._log)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _accept_loop(self, srv: socket.socket, port: int,
                     service: str, banner_fn: Callable[[], bytes]) -> None:
        """Accept connections on *srv*, send banner, record the hit."""
        while self._running:
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            client_ip = addr[0]
            t = threading.Thread(
                target=self._handle_client,
                args=(client, client_ip, port, service, banner_fn),
                daemon=True,
            )
            t.start()

    def _handle_client(self, client: socket.socket, ip: str, port: int,
                       service: str, banner_fn: Callable[[], bytes]) -> None:
        """Send banner, close socket, record connection."""
        now = time.time()
        try:
            client.settimeout(3)
            banner = banner_fn()
            client.sendall(banner)
            # Try to read a small amount (captures any scanner payload)
            try:
                client.recv(1024)
            except (socket.timeout, OSError):
                pass
        except OSError as exc:
            logger.debug("Send error on port %d to %s: %s", port, ip, exc)
        finally:
            try:
                client.close()
            except OSError:
                pass

        logger.info("Connection from %s on port %d (%s)", ip, port, service)

        with self._lock:
            # Record in connection log
            entry = {
                "ip": ip,
                "port": port,
                "service": service,
                "timestamp": now,
            }
            self._log.append(entry)
            # Keep log bounded at 10 000 entries
            if len(self._log) > 10_000:
                self._log = self._log[-5_000:]

            # Track per-IP hits
            hits = self._connections.setdefault(ip, [])
            hits.append((port, now))

            # Prune old hits outside the time window
            cutoff = now - SCAN_TIME_WINDOW
            hits[:] = [(p, t) for p, t in hits if t >= cutoff]

            # Evaluate scan detection
            distinct_ports = {p for p, _ in hits}
            if (len(distinct_ports) >= SCAN_PORT_THRESHOLD
                    and ip not in self._reported):
                timestamps = [t for _, t in hits]
                timespan = max(timestamps) - min(timestamps)
                self._reported.add(ip)
                logger.warning(
                    "Port scan detected from %s — %d ports in %.1fs",
                    ip, len(distinct_ports), timespan,
                )
                # Fire callback outside the lock to avoid deadlocks
                threading.Thread(
                    target=self._fire_callback,
                    args=(ip, sorted(distinct_ports), timespan),
                    daemon=True,
                ).start()

    def _fire_callback(self, ip: str, ports: List[int],
                       timespan: float) -> None:
        try:
            self._callback(ip, ports, timespan)
        except Exception:
            logger.exception("Error in port-scan callback for %s", ip)
