"""
# xz backdoor detector (CVE-2024-3094)
# Hooks into FakeSSH to catch XZ exploit probes.
#
# Checks:
# 1. RSA cert algorithms
# 2. RSA modulus entropy (payloads look weird)
# 3. Timing (Ed448 takes time)
# 4. Command history
"""

import logging
import math
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Optional

log = logging.getLogger("wiredown.xz_detector")

# Severity levels (TODO: Maybe just use an enum instead of strings?)
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Indicator Types
INDICATOR_CERT_KEX = "cert_based_kex_algorithm"
INDICATOR_RSA_MODULUS_SIZE = "oversized_rsa_modulus"
INDICATOR_RSA_ENTROPY_ANOMALY = "rsa_modulus_entropy_anomaly"
INDICATOR_PREAUTH_TIMING = "preauth_timing_anomaly"
INDICATOR_LIBLZMA_RECON = "liblzma_reconnaissance"
INDICATOR_NOTIFY_SOCKET = "notify_socket_probe"
INDICATOR_XZ_VERSION_CHECK = "xz_version_check"
INDICATOR_SSHD_LDD = "sshd_ldd_inspection"
INDICATOR_LIBLZMA_STRINGS = "liblzma_strings_analysis"
INDICATOR_LIBLZMA_ACCESS = "liblzma_direct_access"
INDICATOR_COMBINED_RECON = "combined_reconnaissance_pattern"

# Probing commands
XZ_RECON_COMMANDS = {
    "ldd /usr/sbin/sshd": INDICATOR_SSHD_LDD,
    "ldd $(which sshd)": INDICATOR_SSHD_LDD,
    "strings /usr/lib/liblzma": INDICATOR_LIBLZMA_STRINGS,
    "strings /usr/lib/x86_64-linux-gnu/liblzma": INDICATOR_LIBLZMA_STRINGS,
    "xz --version": INDICATOR_XZ_VERSION_CHECK,
    "xz -V": INDICATOR_XZ_VERSION_CHECK,
    "dpkg -l | grep xz": INDICATOR_XZ_VERSION_CHECK,
    "dpkg -l | grep liblzma": INDICATOR_XZ_VERSION_CHECK,
    "apt list --installed | grep xz": INDICATOR_XZ_VERSION_CHECK,
    "rpm -qa | grep xz": INDICATOR_XZ_VERSION_CHECK,
    "echo $NOTIFY_SOCKET": INDICATOR_NOTIFY_SOCKET,
    "echo $notify_socket": INDICATOR_NOTIFY_SOCKET,
    "env | grep NOTIFY": INDICATOR_NOTIFY_SOCKET,
    "env | grep notify": INDICATOR_NOTIFY_SOCKET,
    "printenv NOTIFY_SOCKET": INDICATOR_NOTIFY_SOCKET,
    "cat /usr/lib/liblzma.so.5": INDICATOR_LIBLZMA_ACCESS,
    "cat /usr/lib/liblzma.so.5.6.1": INDICATOR_LIBLZMA_ACCESS,
    "ls -la /usr/lib/liblzma*": INDICATOR_LIBLZMA_ACCESS,
    "ls -la /usr/lib/x86_64-linux-gnu/liblzma*": INDICATOR_LIBLZMA_ACCESS,
    "file /usr/lib/liblzma.so.5": INDICATOR_LIBLZMA_ACCESS,
    "md5sum /usr/lib/liblzma.so.5": INDICATOR_LIBLZMA_ACCESS,
    "sha256sum /usr/lib/liblzma.so.5": INDICATOR_LIBLZMA_ACCESS,
    "hexdump -C /usr/lib/liblzma.so.5": INDICATOR_LIBLZMA_ACCESS,
    "objdump -d /usr/lib/liblzma.so.5": INDICATOR_LIBLZMA_ACCESS,
    "readelf -a /usr/lib/liblzma.so.5": INDICATOR_LIBLZMA_ACCESS,
}

# Backdoor specific kex algos
BACKDOOR_KEX_INDICATORS = [
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
]

# Timing limits (ms)
BASELINE_HANDSHAKE_MS = 50.0
TIMING_ANOMALY_MIN_MS = 10.0
TIMING_ANOMALY_MAX_MS = 50.0


class Indicator:
    """A single CVE-2024-3094 indicator of compromise."""

    def __init__(
        self,
        client_ip: str,
        indicator_type: str,
        details: str,
        severity: str,
        raw_data: Optional[dict] = None,
    ):
        self.client_ip = client_ip
        self.indicator_type = indicator_type
        self.details = details
        self.severity = severity
        self.raw_data = raw_data or {}
        self.timestamp = datetime.now(timezone.utc)
        self.id = f"{indicator_type}_{client_ip}_{self.timestamp.timestamp()}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "client_ip": self.client_ip,
            "indicator_type": self.indicator_type,
            "details": self.details,
            "severity": self.severity,
            "raw_data": self.raw_data,
            "timestamp": self.timestamp.isoformat(),
        }


class XZBackdoorDetector:
    """
    XZ Utils backdoor detector.
    """

    def __init__(
        self,
        on_exploit_detected: Optional[Callable] = None,
        timing_baseline_ms: float = BASELINE_HANDSHAKE_MS,
    ):
        self.on_exploit_detected = on_exploit_detected or (lambda ip, t, d, s: None)
        self.timing_baseline_ms = timing_baseline_ms

        self._lock = threading.Lock()
        self._indicators: dict[str, list[Indicator]] = defaultdict(list)
        self._command_history: dict[str, list[str]] = defaultdict(list)
        self._timing_samples: dict[str, list[float]] = defaultdict(list)

    def analyze_ssh_handshake(
        self,
        client_ip: str,
        banner_data: str,
        key_exchange_data: bytes,
    ) -> list[Indicator]:
        found: list[Indicator] = []

        # Check kex algos
        try:
            kex_str = key_exchange_data.decode("utf-8", errors="replace")
        except Exception:
            kex_str = ""

        for algo in BACKDOOR_KEX_INDICATORS:
            if algo in kex_str:
                indicator = Indicator(
                    client_ip=client_ip,
                    indicator_type=INDICATOR_CERT_KEX,
                    details=(
                        f"Client offered cert-based algorithm '{algo}' in key exchange. "
                        f"This is the certificate validation path exploited by CVE-2024-3094. "
                        f"The XZ backdoor intercepts RSA certificate verification via "
                        f"rsa-sha2-*-cert-v01 to inject attacker commands."
                    ),
                    severity=SEVERITY_MEDIUM,
                    raw_data={"algorithm": algo, "banner": banner_data},
                )
                found.append(indicator)
                log.warning(
                    "CVE-2024-3094 indicator: %s offered cert kex algo '%s'",
                    client_ip, algo,
                )

        # Check RSA size
        rsa_modulus_bytes = self._extract_rsa_modulus(key_exchange_data)
        if rsa_modulus_bytes:
            modulus_bits = len(rsa_modulus_bytes) * 8
            if modulus_bits >= 4096:
                # XZ payload hides in the upper bytes of oversized RSA modulus
                has_structure = self._check_modulus_structure(rsa_modulus_bytes)
                severity = SEVERITY_HIGH if has_structure else SEVERITY_MEDIUM

                indicator = Indicator(
                    client_ip=client_ip,
                    indicator_type=INDICATOR_RSA_MODULUS_SIZE,
                    details=(
                        f"RSA public key modulus is {modulus_bits} bits "
                        f"({'with suspicious structure' if has_structure else 'oversized but no clear structure'}). "
                        f"CVE-2024-3094 embeds Ed448-signed command payloads in the upper bytes "
                        f"of an RSA-4096 certificate's N value."
                    ),
                    severity=severity,
                    raw_data={
                        "modulus_bits": modulus_bits,
                        "has_structure": has_structure,
                    },
                )
                found.append(indicator)
                log.warning(
                    "CVE-2024-3094 indicator: %s RSA modulus %d bits (structure=%s)",
                    client_ip, modulus_bits, has_structure,
                )

            # Check entropy
            entropy_result = self._analyze_modulus_entropy(rsa_modulus_bytes)
            if entropy_result["anomalous"]:
                indicator = Indicator(
                    client_ip=client_ip,
                    indicator_type=INDICATOR_RSA_ENTROPY_ANOMALY,
                    details=(
                        f"RSA modulus entropy anomaly detected. "
                        f"Overall entropy: {entropy_result['overall_entropy']:.4f} bits/byte, "
                        f"Upper-quarter entropy: {entropy_result['upper_entropy']:.4f} bits/byte, "
                        f"Lower-quarter entropy: {entropy_result['lower_entropy']:.4f} bits/byte. "
                        f"Deviation: {entropy_result['deviation']:.4f}. "
                        f"Legitimate RSA keys have near-uniform randomness (~7.99 bits/byte). "
                        f"The CVE-2024-3094 payload creates detectable entropy dips in the "
                        f"upper byte positions of the modulus."
                    ),
                    severity=SEVERITY_HIGH,
                    raw_data=entropy_result,
                )
                found.append(indicator)
                log.warning(
                    "CVE-2024-3094 indicator: %s RSA modulus entropy anomaly "
                    "(overall=%.4f, upper=%.4f, lower=%.4f)",
                    client_ip,
                    entropy_result["overall_entropy"],
                    entropy_result["upper_entropy"],
                    entropy_result["lower_entropy"],
                )

        # Store indicators
        with self._lock:
            self._indicators[client_ip].extend(found)

        # Fire callbacks
        for ind in found:
            self._fire_detection(ind)

        return found

    def analyze_pre_auth_timing(
        self,
        client_ip: str,
        handshake_duration_ms: float,
    ) -> Optional[Indicator]:
        # Ed448 signature verification adds ~10-50ms latency.
        with self._lock:
            self._timing_samples[client_ip].append(handshake_duration_ms)

        delta = handshake_duration_ms - self.timing_baseline_ms

        if TIMING_ANOMALY_MIN_MS <= delta <= TIMING_ANOMALY_MAX_MS:
            with self._lock:
                samples = list(self._timing_samples[client_ip])

            # Calculate statistics
            avg_delta = sum(s - self.timing_baseline_ms for s in samples) / len(samples)
            consistent = all(
                TIMING_ANOMALY_MIN_MS * 0.5 <= (s - self.timing_baseline_ms) <= TIMING_ANOMALY_MAX_MS * 1.5
                for s in samples
            )

            # Flag if consistent across samples
            if len(samples) >= 3 and consistent:
                severity = SEVERITY_HIGH
            elif len(samples) >= 2:
                severity = SEVERITY_MEDIUM
            else:
                severity = SEVERITY_LOW

            indicator = Indicator(
                client_ip=client_ip,
                indicator_type=INDICATOR_PREAUTH_TIMING,
                details=(
                    f"Pre-auth handshake took {handshake_duration_ms:.2f}ms "
                    f"(+{delta:.2f}ms above {self.timing_baseline_ms:.0f}ms baseline). "
                    f"CVE-2024-3094 Ed448 verification adds 10-50ms latency. "
                    f"Samples from this IP: {len(samples)}, avg delta: {avg_delta:.2f}ms, "
                    f"consistent pattern: {consistent}."
                ),
                severity=severity,
                raw_data={
                    "handshake_ms": handshake_duration_ms,
                    "delta_ms": round(delta, 2),
                    "baseline_ms": self.timing_baseline_ms,
                    "sample_count": len(samples),
                    "avg_delta_ms": round(avg_delta, 2),
                    "consistent": consistent,
                },
            )

            with self._lock:
                self._indicators[client_ip].append(indicator)

            self._fire_detection(indicator)
            log.warning(
                "CVE-2024-3094 timing anomaly: %s handshake=%0.2fms delta=%0.2fms",
                client_ip, handshake_duration_ms, delta,
            )
            return indicator

        return None

    def analyze_post_auth_behavior(
        self,
        client_ip: str,
        commands: list[str],
    ) -> list[Indicator]:
        # Tracking command history to catch recon patterns.
        found: list[Indicator] = []

        with self._lock:
            self._command_history[client_ip].extend(commands)
            full_history = list(self._command_history[client_ip])

        for cmd in commands:
            cmd_stripped = cmd.strip()
            cmd_lower = cmd_stripped.lower()

            matched_type = None
            matched_cmd = None

            # Check against known reconnaissance commands
            for pattern, itype in XZ_RECON_COMMANDS.items():
                if pattern.lower() in cmd_lower or cmd_lower.startswith(pattern.lower().split()[0]) and any(
                    kw in cmd_lower for kw in pattern.lower().split()[1:]
                ):
                    matched_type = itype
                    matched_cmd = pattern
                    break

            # Additional fuzzy matching for partial commands
            if not matched_type:
                if "liblzma" in cmd_lower:
                    matched_type = INDICATOR_LIBLZMA_RECON
                    matched_cmd = cmd_stripped
                elif "ldd" in cmd_lower and "sshd" in cmd_lower:
                    matched_type = INDICATOR_SSHD_LDD
                    matched_cmd = cmd_stripped
                elif ("xz" in cmd_lower and ("version" in cmd_lower or "-V" in cmd)):
                    matched_type = INDICATOR_XZ_VERSION_CHECK
                    matched_cmd = cmd_stripped
                elif "notify_socket" in cmd_lower or "NOTIFY_SOCKET" in cmd:
                    matched_type = INDICATOR_NOTIFY_SOCKET
                    matched_cmd = cmd_stripped

            if matched_type:
                # Determine severity based on the type and accumulation
                severity = self._compute_command_severity(matched_type, client_ip, full_history)

                indicator = Indicator(
                    client_ip=client_ip,
                    indicator_type=matched_type,
                    details=(
                        f"Post-auth command '{cmd_stripped}' matches CVE-2024-3094 "
                        f"reconnaissance pattern (matched: '{matched_cmd}'). "
                        f"Total suspicious commands from this IP: "
                        f"{sum(1 for c in full_history if any(p.lower() in c.lower() for p in XZ_RECON_COMMANDS))}."
                    ),
                    severity=severity,
                    raw_data={
                        "command": cmd_stripped,
                        "matched_pattern": matched_cmd,
                        "total_commands_from_ip": len(full_history),
                    },
                )
                found.append(indicator)
                log.warning(
                    "CVE-2024-3094 recon: %s ran '%s' (type=%s, severity=%s)",
                    client_ip, cmd_stripped, matched_type, severity,
                )

        # Check for multiple facets
        # Escalating if IP checks multiple things
        if found:
            unique_types = set()
            with self._lock:
                for ind in self._indicators[client_ip]:
                    unique_types.add(ind.indicator_type)
            for ind in found:
                unique_types.add(ind.indicator_type)

            recon_types = {
                INDICATOR_SSHD_LDD, INDICATOR_LIBLZMA_STRINGS,
                INDICATOR_XZ_VERSION_CHECK, INDICATOR_NOTIFY_SOCKET,
                INDICATOR_LIBLZMA_ACCESS, INDICATOR_LIBLZMA_RECON,
            }
            overlap = unique_types & recon_types
            if len(overlap) >= 3:
                combined = Indicator(
                    client_ip=client_ip,
                    indicator_type=INDICATOR_COMBINED_RECON,
                    details=(
                        f"Client {client_ip} has triggered {len(overlap)} distinct "
                        f"CVE-2024-3094 reconnaissance categories: "
                        f"{', '.join(sorted(overlap))}. "
                        f"This strongly suggests targeted exploitation of the XZ backdoor."
                    ),
                    severity=SEVERITY_CRITICAL,
                    raw_data={
                        "categories": sorted(overlap),
                        "category_count": len(overlap),
                    },
                )
                found.append(combined)
                log.critical(
                    "CVE-2024-3094 CRITICAL: %s triggered %d recon categories: %s",
                    client_ip, len(overlap), ", ".join(sorted(overlap)),
                )

        # Store all found indicators
        with self._lock:
            self._indicators[client_ip].extend(found)

        # Fire callbacks
        for ind in found:
            self._fire_detection(ind)

        return found

    # Indicator Retrieval

    def get_indicators(self, client_ip: Optional[str] = None) -> list[dict]:
        """
        Return all CVE-2024-3094 indicators of compromise.

        Parameters
        ----------
        client_ip : str, optional
            If provided, return only indicators for this IP.
            Otherwise, return all indicators across all IPs.

        Returns
        -------
        list[dict]
            List of indicator dictionaries.
        """
        with self._lock:
            if client_ip:
                return [ind.to_dict() for ind in self._indicators.get(client_ip, [])]
            all_indicators = []
            for ip_indicators in self._indicators.values():
                all_indicators.extend(ind.to_dict() for ind in ip_indicators)
            return sorted(all_indicators, key=lambda x: x["timestamp"], reverse=True)

    def get_client_risk_score(self, client_ip: str) -> dict:
        """
        Compute a risk score for a client based on accumulated indicators.

        Returns a dict with score (0-100), severity label, and breakdown.
        """
        with self._lock:
            indicators = list(self._indicators.get(client_ip, []))

        if not indicators:
            return {"score": 0, "severity": "none", "indicator_count": 0, "breakdown": {}}

        severity_weights = {
            SEVERITY_LOW: 5,
            SEVERITY_MEDIUM: 15,
            SEVERITY_HIGH: 30,
            SEVERITY_CRITICAL: 50,
        }

        score = 0
        breakdown: dict[str, int] = defaultdict(int)
        for ind in indicators:
            weight = severity_weights.get(ind.severity, 5)
            score += weight
            breakdown[ind.indicator_type] += 1

        score = min(score, 100)

        if score >= 80:
            overall_severity = SEVERITY_CRITICAL
        elif score >= 50:
            overall_severity = SEVERITY_HIGH
        elif score >= 25:
            overall_severity = SEVERITY_MEDIUM
        else:
            overall_severity = SEVERITY_LOW

        return {
            "score": score,
            "severity": overall_severity,
            "indicator_count": len(indicators),
            "breakdown": dict(breakdown),
        }

    def get_all_client_scores(self) -> dict[str, dict]:
        """Return risk scores for all tracked clients."""
        with self._lock:
            ips = list(self._indicators.keys())
        return {ip: self.get_client_risk_score(ip) for ip in ips}

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of a byte sequence.

        Returns entropy in bits per byte (0.0 to 8.0).
        Perfectly random data → ~8.0
        All identical bytes → 0.0

        Parameters
        ----------
        data : bytes
            The byte sequence to analyze.

        Returns
        -------
        float
            Shannon entropy in bits per byte.
        """
        if not data:
            return 0.0

        length = len(data)
        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _extract_rsa_modulus(self, key_exchange_data: bytes) -> Optional[bytes]:
        # Trying to pull the RSA modulus. If it fails, whatever.
        if not key_exchange_data or len(key_exchange_data) < 20:
            return None

        marker = b"ssh-rsa"
        pos = key_exchange_data.find(marker)
        if pos < 0:
            return None

        try:
            # After the key-type string, read the exponent
            offset = pos + len(marker)
            if offset + 4 > len(key_exchange_data):
                return None

            # Read exponent length
            e_len = int.from_bytes(key_exchange_data[offset:offset + 4], "big")
            offset += 4
            if offset + e_len > len(key_exchange_data):
                return None

            # Skip exponent
            offset += e_len

            # Read modulus length
            if offset + 4 > len(key_exchange_data):
                return None
            n_len = int.from_bytes(key_exchange_data[offset:offset + 4], "big")
            offset += 4

            if n_len < 32 or n_len > 1024:
                return None
            if offset + n_len > len(key_exchange_data):
                return None

            return key_exchange_data[offset:offset + n_len]
        except Exception:
            return None

    def _check_modulus_structure(self, modulus: bytes) -> bool:
        # Looking for Ed448 embedded signs. The padding causes weird patterns.
        if len(modulus) < 512:
            return False

        # Upper quarter low entropy check
        upper_quarter = modulus[:len(modulus) // 4]
        upper_entropy = self.shannon_entropy(upper_quarter)
        if upper_entropy < 7.0:
            return True

        # Repeated 4-byte patterns
        chunk_size = 4
        upper_32 = modulus[:32]
        chunks = [upper_32[i:i + chunk_size] for i in range(0, len(upper_32), chunk_size)]
        unique_chunks = set(chunks)
        if len(unique_chunks) < len(chunks) * 0.6:
            return True

        # Zero-byte padding runs
        zero_runs = 0
        current_run = 0
        for byte in modulus[:128]:
            if byte == 0:
                current_run += 1
                if current_run >= 4:
                    zero_runs += 1
            else:
                current_run = 0
        if zero_runs >= 2:
            return True

        # Entropy variance (real keys don't vary this much)
        block_size = 64
        entropies = []
        for i in range(0, min(len(modulus), 512), block_size):
            block = modulus[i:i + block_size]
            if len(block) == block_size:
                entropies.append(self.shannon_entropy(block))

        if len(entropies) >= 4:
            avg_entropy = sum(entropies) / len(entropies)
            variance = sum((e - avg_entropy) ** 2 for e in entropies) / len(entropies)
            if variance > 0.5:
                return True

        return False

    def _analyze_modulus_entropy(self, modulus: bytes) -> dict:
        overall = self.shannon_entropy(modulus)
        mid = len(modulus) // 2
        quarter = len(modulus) // 4

        upper_half = modulus[:mid]
        lower_half = modulus[mid:]
        upper_quarter = modulus[:quarter]
        lower_quarter = modulus[-quarter:]

        upper_entropy = self.shannon_entropy(upper_quarter)
        lower_entropy = self.shannon_entropy(lower_quarter)
        upper_half_entropy = self.shannon_entropy(upper_half)
        lower_half_entropy = self.shannon_entropy(lower_half)

        deviation = abs(upper_entropy - lower_entropy)
        half_deviation = abs(upper_half_entropy - lower_half_entropy)

        anomalous = (
            deviation > 0.3 or
            half_deviation > 0.2 or
            upper_entropy < 7.5 or
            overall < 7.8
        )

        return {
            "overall_entropy": round(overall, 4),
            "upper_entropy": round(upper_entropy, 4),
            "lower_entropy": round(lower_entropy, 4),
            "upper_half_entropy": round(upper_half_entropy, 4),
            "lower_half_entropy": round(lower_half_entropy, 4),
            "deviation": round(deviation, 4),
            "half_deviation": round(half_deviation, 4),
            "anomalous": anomalous,
        }

    def _compute_command_severity(
        self,
        indicator_type: str,
        client_ip: str,
        command_history: list[str],
    ) -> str:
        with self._lock:
            existing = self._indicators.get(client_ip, [])
            existing_types = {ind.indicator_type for ind in existing}

        # Direct exploit indicators are always high
        if indicator_type in (INDICATOR_LIBLZMA_ACCESS, INDICATOR_LIBLZMA_STRINGS):
            if existing_types & {INDICATOR_CERT_KEX, INDICATOR_PREAUTH_TIMING, INDICATOR_RSA_ENTROPY_ANOMALY}:
                return SEVERITY_CRITICAL
            return SEVERITY_HIGH

        # sshd ldd check is medium-high depending on context
        if indicator_type == INDICATOR_SSHD_LDD:
            if existing_types & {INDICATOR_XZ_VERSION_CHECK, INDICATOR_NOTIFY_SOCKET}:
                return SEVERITY_HIGH
            return SEVERITY_MEDIUM

        # NOTIFY_SOCKET probe is significant — it's specific to the backdoor
        if indicator_type == INDICATOR_NOTIFY_SOCKET:
            return SEVERITY_MEDIUM

        # Version checks alone are low
        if indicator_type == INDICATOR_XZ_VERSION_CHECK:
            suspicious_count = sum(
                1 for c in command_history
                if any(p.lower() in c.lower() for p in XZ_RECON_COMMANDS)
            )
            if suspicious_count >= 3:
                return SEVERITY_MEDIUM
            return SEVERITY_LOW

        # Default based on accumulation
        total_indicators = len(existing) + 1
        if total_indicators >= 5:
            return SEVERITY_HIGH
        if total_indicators >= 3:
            return SEVERITY_MEDIUM
        return SEVERITY_LOW

    def _fire_detection(self, indicator: Indicator) -> None:
        """Thread-safe callback invocation."""
        try:
            self.on_exploit_detected(
                indicator.client_ip,
                indicator.indicator_type,
                indicator.details,
                indicator.severity,
            )
        except Exception as exc:
            log.error("Error in on_exploit_detected callback: %s", exc)
