# progressive bandwidth degradation for flagged devices

import enum
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("wiredown.bandwidth_throttle")


class ThrottleStage(enum.Enum):
    FULL     = ("Full Speed",     100)
    DEGRADED = ("Degraded Speed",  50)
    CRAWL    = ("Crawl Mode",     10)
    TRICKLE  = ("Trickle Feed",    1)
    ISOLATED = ("Isolated",        0)

    def __init__(self, label: str, bandwidth_pct: int) -> None:
        self.label = label
        self.bandwidth_pct = bandwidth_pct

    @property
    def delay_ms(self) -> int:

        mapping = {
            100: 0,
            50:  200,
            10:  1_000,
            1:   5_000,
            0:   10_000,
        }
        return mapping.get(self.bandwidth_pct, 0)



STAGE_ORDER: List[ThrottleStage] = [
    ThrottleStage.FULL,
    ThrottleStage.DEGRADED,
    ThrottleStage.CRAWL,
    ThrottleStage.TRICKLE,
    ThrottleStage.ISOLATED,
]


class _DeviceState:

    __slots__ = ("mac", "ip", "stage_index", "stage_entered_at",
                 "engaged_at", "stage_duration")

    def __init__(self, mac: str, ip: Optional[str],
                 stage_duration: float) -> None:
        self.mac = mac
        self.ip = ip
        self.stage_index = 0  # starts at FULL
        self.stage_entered_at = time.time()
        self.engaged_at = time.time()
        self.stage_duration = stage_duration

    @property
    def stage(self) -> ThrottleStage:
        return STAGE_ORDER[self.stage_index]

    @property
    def is_final(self) -> bool:
        return self.stage_index >= len(STAGE_ORDER) - 1

    @property
    def time_in_stage(self) -> float:
        return time.time() - self.stage_entered_at

    @property
    def time_remaining(self) -> float:
        remaining = self.stage_duration - self.time_in_stage
        return max(0.0, remaining)

    @property
    def progress_pct(self) -> float:

        total_stages = len(STAGE_ORDER)
        completed = self.stage_index
        in_stage_frac = min(self.time_in_stage / self.stage_duration, 1.0)
        return ((completed + in_stage_frac) / total_stages) * 100.0

    def advance(self) -> Tuple[ThrottleStage, ThrottleStage]:
        old = self.stage
        self.stage_index = min(self.stage_index + 1, len(STAGE_ORDER) - 1)
        self.stage_entered_at = time.time()
        return old, self.stage


class BandwidthThrottle:

    def __init__(
        self,
        stage_duration: float = 15.0,
        on_isolate: Optional[Callable[..., Any]] = None,
        on_stage_change: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._stage_duration = stage_duration
        self._on_isolate = on_isolate
        self._on_stage_change = on_stage_change
        self._lock = threading.Lock()
        self._devices: Dict[str, _DeviceState] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        logger.info("BandwidthThrottle initialised (stage_duration=%.1fs)",
                     stage_duration)



    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._progression_loop, daemon=True,
            name="throttle-progression",
        )
        self._thread.start()
        logger.info("Bandwidth throttle progression thread started")

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("BandwidthThrottle stopped")



    def engage(self, mac: str, ip: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if mac in self._devices:
                logger.debug("Throttle already engaged for %s", mac)
                return self._status_dict(self._devices[mac])
            state = _DeviceState(mac, ip, self._stage_duration)
            self._devices[mac] = state
            logger.info("Throttle engaged for %s (ip=%s)", mac, ip)
            return self._status_dict(state)

    def disengage(self, mac: str) -> bool:
        with self._lock:
            removed = self._devices.pop(mac, None)
        if removed is not None:
            logger.info("Throttle disengaged for %s", mac)
            return True
        return False

    def get_status(self, mac: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            state = self._devices.get(mac)
            if state is None:
                return None
            return self._status_dict(state)

    def get_all_active(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._status_dict(s) for s in self._devices.values()]

    def should_delay(self, mac: str) -> int:
        with self._lock:
            state = self._devices.get(mac)
            if state is None:
                return 0
            return state.stage.delay_ms



    @staticmethod
    def _status_dict(state: _DeviceState) -> Dict[str, Any]:
        return {
            "mac": state.mac,
            "ip": state.ip,
            "stage": state.stage.label,
            "bandwidth_pct": state.stage.bandwidth_pct,
            "time_remaining": round(state.time_remaining, 1),
            "progress": round(state.progress_pct, 1),
            "delay_ms": state.stage.delay_ms,
            "engaged_at": state.engaged_at,
        }

    def _progression_loop(self) -> None:
        while self._running:
            time.sleep(0.5)  # check twice per second
            callbacks_to_fire: List[Tuple[str, ...]] = []

            with self._lock:
                for mac, state in list(self._devices.items()):
                    if state.is_final:
                        continue
                    if state.time_in_stage < state.stage_duration:
                        continue

                    old_stage, new_stage = state.advance()
                    progress = state.progress_pct
                    logger.info(
                        "Throttle stage change for %s: %s → %s (%.1f%%)",
                        mac, old_stage.label, new_stage.label, progress,
                    )

                    if self._on_stage_change is not None:
                        callbacks_to_fire.append(
                            ("stage_change", mac, old_stage.label,
                             new_stage.label, progress)
                        )

                    if new_stage == ThrottleStage.ISOLATED and self._on_isolate is not None:
                        callbacks_to_fire.append(("isolate", mac))


            for cb_info in callbacks_to_fire:
                if cb_info[0] == "stage_change":
                    self._fire_stage_change(cb_info[1], cb_info[2],
                                            cb_info[3], cb_info[4])
                elif cb_info[0] == "isolate":
                    self._fire_isolate(cb_info[1])

    def _fire_stage_change(self, mac: str, old_stage: str,
                           new_stage: str, progress: float) -> None:
        try:
            self._on_stage_change(mac, old_stage, new_stage, progress)
        except Exception:
            logger.exception("Error in stage-change callback for %s", mac)

    def _fire_isolate(self, mac: str) -> None:
        try:
            self._on_isolate(mac)
        except Exception:
            logger.exception("Error in isolate callback for %s", mac)
