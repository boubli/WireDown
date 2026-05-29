# UDP DNS sinkhole with entropy-based tunnel detection

import logging
import math
import socket
import struct
import threading
import time
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("wiredown.dns_sinkhole")


DNS_HEADER_LEN  = 12
QTYPE_A         = 1
QCLASS_IN       = 1
DNS_RESPONSE_FLAGS = 0x8180  # QR=1, AA=1, RD=1, RA=1, RCODE=0 (no error)


ENTROPY_THRESHOLD   = 3.5
SUBDOMAIN_MIN_LEN   = 20


class DNSSinkhole:

    def __init__(
        self,
        sinkhole_ip: str = "127.0.0.1",
        port: int = 5353,
        on_tunnel_detected: Optional[Callable[..., Any]] = None,
        host: str = "0.0.0.0",
    ) -> None:
        self._sinkhole_ip = sinkhole_ip
        self._port = port
        self._host = host
        self._on_tunnel = on_tunnel_detected
        self._lock = threading.Lock()
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._query_log: List[Dict[str, Any]] = []
        logger.info(
            "DNS sinkhole is now active, redirecting traffic to %s on port %d",
            sinkhole_ip, port,
        )



    def start(self) -> None:
        if self._running:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self._host, self._port))
        self._running = True
        self._thread = threading.Thread(
            target=self._serve_loop, daemon=True, name="dns-sinkhole",
        )
        self._thread.start()
        logger.info("The sinkhole is listening for queries on %s:%d", self._host, self._port)

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("DNS sinkhole has been shut down gracefully")

    def get_query_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._query_log)



    @staticmethod
    def _parse_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
        labels: List[str] = []
        jumped = False
        original_offset = offset
        max_jumps = 20  # safety net against malformed packets
        jumps = 0

        while True:
            if offset >= len(data):
                break
            length = data[offset]


            if (length & 0xC0) == 0xC0:
                if not jumped:
                    original_offset = offset + 2
                pointer = struct.unpack("!H", data[offset:offset + 2])[0]
                offset = pointer & 0x3FFF
                jumped = True
                jumps += 1
                if jumps > max_jumps:
                    break
                continue

            if length == 0:
                offset += 1
                break

            offset += 1
            label = data[offset:offset + length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length

        if jumped:
            offset = original_offset

        return ".".join(labels), offset

    def _build_response(self, query: bytes, domain: str) -> bytes:

        txn_id = query[:2]
        flags = struct.pack("!H", DNS_RESPONSE_FLAGS)
        qd_count = struct.pack("!H", 1)  # 1 question
        an_count = struct.pack("!H", 1)  # 1 answer
        ns_count = struct.pack("!H", 0)
        ar_count = struct.pack("!H", 0)
        header = txn_id + flags + qd_count + an_count + ns_count + ar_count


        _, qname_end = self._parse_domain_name(query, DNS_HEADER_LEN)
        question = query[DNS_HEADER_LEN:qname_end + 4]  # name + qtype(2) + qclass(2)


        answer = struct.pack("!H", 0xC00C)
        answer += struct.pack("!H", QTYPE_A)      # Type A
        answer += struct.pack("!H", QCLASS_IN)     # Class IN
        answer += struct.pack("!I", 60)             # TTL 60 seconds
        ip_bytes = socket.inet_aton(self._sinkhole_ip)
        answer += struct.pack("!H", len(ip_bytes))  # RDLENGTH
        answer += ip_bytes                           # RDATA

        return header + question + answer



    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _extract_subdomain(domain: str) -> str:
        parts = domain.rstrip(".").split(".")
        if len(parts) <= 2:
            return domain
        return ".".join(parts[:-2])

    def _check_tunnel(self, client_ip: str, domain: str) -> Optional[float]:
        subdomain = self._extract_subdomain(domain)
        if len(subdomain) <= SUBDOMAIN_MIN_LEN:
            return None
        entropy = self._shannon_entropy(subdomain)
        if entropy > ENTROPY_THRESHOLD:
            return entropy
        return None



    def _serve_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break

            client_ip = addr[0]
            now = time.time()

            try:
                domain, qtype = self._process_query(data, addr)
            except Exception as exc:
                logger.debug("Received an invalid or malformed packet from %s: %s", client_ip, exc)
                continue


            qtype_str = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX",
                         2: "NS", 12: "PTR", 6: "SOA", 16: "TXT",
                         33: "SRV", 255: "ANY"}.get(qtype, str(qtype))


            entry = {
                "client_ip": client_ip,
                "domain": domain,
                "timestamp": now,
                "query_type": qtype_str,
            }

            with self._lock:
                self._query_log.append(entry)

                if len(self._query_log) > 10_000:
                    self._query_log = self._query_log[-5_000:]

            logger.info("Processed query from %s: %s [%s]", client_ip, domain, qtype_str)


            entropy = self._check_tunnel(client_ip, domain)
            if entropy is not None:
                logger.warning(
                    "Alert: Unusual query pattern from %s. Possible tunnel detected at %s (Entropy: %.2f)",
                    client_ip, domain, entropy,
                )
                entry["tunnel_detected"] = True
                entry["entropy"] = entropy
                if self._on_tunnel is not None:
                    threading.Thread(
                        target=self._fire_tunnel_callback,
                        args=(client_ip, domain, entropy),
                        daemon=True,
                    ).start()

    def _process_query(self, data: bytes,
                       addr: Tuple[str, int]) -> Tuple[str, int]:
        if len(data) < DNS_HEADER_LEN + 5:
            raise ValueError("Packet too short")


        domain, offset = self._parse_domain_name(data, DNS_HEADER_LEN)
        qtype, _qclass = struct.unpack("!HH", data[offset:offset + 4])


        response = self._build_response(data, domain)
        try:
            self._sock.sendto(response, addr)
        except OSError as exc:
            logger.debug("Failed to send DNS response to %s: %s", addr[0], exc)

        return domain, qtype

    def _fire_tunnel_callback(self, client_ip: str, domain: str,
                              entropy: float) -> None:
        try:
            self._on_tunnel(client_ip, domain, entropy)
        except Exception:
            logger.exception("Error in DNS tunnel callback for %s", client_ip)
