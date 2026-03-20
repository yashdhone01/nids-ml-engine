"""
flow_monitor.py — Capture → Feature → Predict pipeline.

FlowMonitor wires together:
  PacketCapture  →  FeatureExtractor  →  NIDSEngine  →  alert callback

It runs the capture loop in a background thread so callers can do
other work (serve a dashboard, write to a log file, etc.) while
detection runs continuously.

Alert severity levels
---------------------
  INFO     — Normal traffic (logged at DEBUG level)
  LOW      — Probe / reconnaissance detected
  MEDIUM   — R2L / remote-to-local access attempt
  HIGH     — DoS attack
  CRITICAL — U2R / privilege escalation attempt
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from dataclasses import dataclass, asdict
from typing import Callable, Dict, List, Optional

from src.capture import FlowRecord, PacketCapture
from src.features import FeatureExtractor, FeatureVector, HostTable, TrafficWindow

log = logging.getLogger("nids.monitor")


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

_SEVERITY_MAP: Dict[str, str] = {
    "Normal": "INFO",
    "DoS":    "HIGH",
    "Probe":  "LOW",
    "R2L":    "MEDIUM",
    "U2R":    "CRITICAL",
}

_COLOR_MAP: Dict[str, str] = {
    "INFO":     "\033[0m",       # default
    "LOW":      "\033[93m",      # yellow
    "MEDIUM":   "\033[33m",      # dark yellow
    "HIGH":     "\033[91m",      # red
    "CRITICAL": "\033[95m",      # magenta
}
_RESET = "\033[0m"


@dataclass
class Alert:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    service: str
    prediction: str          # DoS, Probe, R2L, U2R, Normal
    confidence: float
    severity: str            # INFO / LOW / MEDIUM / HIGH / CRITICAL
    duration: float
    src_bytes: int
    dst_bytes: int
    flag: str

    @classmethod
    def from_flow_and_result(
        cls,
        flow: FlowRecord,
        result: Dict,
        vec: FeatureVector,
    ) -> "Alert":
        prediction = result.get("prediction", "Normal")
        confidence = float(result.get("confidence", 0.0))
        severity = _SEVERITY_MAP.get(prediction, "INFO")
        src_ip, dst_ip, src_port, dst_port, proto = flow.key

        return cls(
            timestamp=vec.timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            service=flow.service,
            prediction=prediction,
            confidence=confidence,
            severity=severity,
            duration=round(flow.duration, 3),
            src_bytes=flow.src_bytes,
            dst_bytes=flow.dst_bytes,
            flag=flow.flag,
        )

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_log_line(self) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] {self.severity:<8} {self.prediction:<7} "
            f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} "
            f"({self.protocol.upper()}/{self.service}) "
            f"conf={self.confidence:.2f} "
            f"bytes↑{self.src_bytes} ↓{self.dst_bytes}"
        )


# ---------------------------------------------------------------------------
# FlowMonitor
# ---------------------------------------------------------------------------

class FlowMonitor:
    """
    Orchestrates the full detection pipeline on a live interface.

    Parameters
    ----------
    interface : str
        Network interface to sniff (e.g. "eth0", "wlan0", "en0").
    engine : NIDSEngine
        Your existing trained model engine from src.predict.
    on_alert : callable, optional
        Called for every alert (including Normal traffic if log_normal=True).
        Receives a single Alert argument.  Runs in the prediction thread.
    alert_only : bool
        If True (default), suppress Normal/INFO alerts from on_alert.
    confidence_threshold : float
        Minimum confidence to emit an alert (default 0.5).
    bpf_filter : str
        Optional BPF filter string passed to Scapy (e.g. "not port 22").
    log_file : str, optional
        Path to write NDJSON alert log.  None = no file logging.
    """

    def __init__(
        self,
        interface: str,
        engine,                              # NIDSEngine
        on_alert: Optional[Callable[[Alert], None]] = None,
        alert_only: bool = True,
        confidence_threshold: float = 0.5,
        bpf_filter: str = "",
        log_file: Optional[str] = None,
    ):
        self.interface = interface
        self.engine = engine
        self.on_alert = on_alert
        self.alert_only = alert_only
        self.confidence_threshold = confidence_threshold
        self.log_file = log_file

        # Shared feature state
        self._window = TrafficWindow()
        self._hosts = HostTable()
        self._extractor = FeatureExtractor(self._window, self._hosts)

        # Alert queue — prediction runs on a worker thread so the
        # capture thread is never blocked by model inference.
        self._alert_queue: queue.Queue[FlowRecord] = queue.Queue(maxsize=2000)

        # Stats
        self.stats = {
            "flows_processed": 0,
            "alerts_emitted": 0,
            "packets_seen": 0,
            "start_time": 0.0,
        }

        self._capture: Optional[PacketCapture] = None
        self._capture_thread: Optional[threading.Thread] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False
        self._log_fh = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start monitoring.  Non-blocking — runs capture in background."""
        if self._running:
            return

        self._running = True
        self.stats["start_time"] = time.time()

        if self.log_file:
            self._log_fh = open(self.log_file, "a", buffering=1)  # noqa: WPS515

        self._capture = PacketCapture(
            interface=self.interface,
            on_flow_complete=self._enqueue_flow,
            bpf_filter="ip",
        )

        self._worker_thread = threading.Thread(
            target=self._prediction_worker,
            daemon=True,
            name="nids-predict",
        )
        self._worker_thread.start()

        self._capture_thread = threading.Thread(
            target=self._capture.start,
            daemon=True,
            name="nids-capture",
        )
        self._capture_thread.start()

        log.info("FlowMonitor started on interface '%s'", self.interface)

    def stop(self) -> None:
        """Stop monitoring and flush pending flows."""
        self._running = False
        if self._capture:
            self._capture.stop()
        if self._worker_thread:
            self._alert_queue.join()
        if self._log_fh:
            self._log_fh.close()
        log.info(
            "FlowMonitor stopped. Flows: %d  Alerts: %d  Packets: %d",
            self.stats["flows_processed"],
            self.stats["alerts_emitted"],
            self._capture.packets_seen if self._capture else 0,
        )

    def get_stats(self) -> Dict:
        s = dict(self.stats)
        s["uptime_seconds"] = round(time.time() - s["start_time"], 1)
        if self._capture:
            s["packets_seen"] = self._capture.packets_seen
            s["flows_in_progress"] = len(self._capture._flows)
        return s

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _enqueue_flow(self, flow: FlowRecord) -> None:
        """Called by PacketCapture (capture thread) for each completed flow."""
        try:
            self._alert_queue.put_nowait(flow)
        except queue.Full:
            log.warning("Alert queue full — dropping flow from %s", flow.key[0])

    def _prediction_worker(self) -> None:
        """Dequeues flows, extracts features, runs the ML model."""
        while self._running or not self._alert_queue.empty():
            try:
                flow = self._alert_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._process_flow(flow)
            except Exception as exc:  # noqa: BLE001
                log.error("Prediction error for flow %s: %s", flow.key, exc)
            finally:
                self._alert_queue.task_done()

    def _process_flow(self, flow: FlowRecord) -> None:
        vec = self._extractor.extract(flow)
        result = self.engine.predict(vec.to_dict())
        self.stats["flows_processed"] += 1

        prediction = result.get("prediction", "Normal")
        confidence = float(result.get("confidence", 0.0))

        # Filter by threshold and alert_only flag
        is_threat = prediction != "Normal"
        if not is_threat and self.alert_only:
            return
        if confidence < self.confidence_threshold:
            return

        alert = Alert.from_flow_and_result(flow, result, vec)
        self.stats["alerts_emitted"] += 1

        self._emit_alert(alert)

    def _emit_alert(self, alert: Alert) -> None:
        color = _COLOR_MAP.get(alert.severity, "")
        line = alert.to_log_line()
        print(f"{color}{line}{_RESET}")

        if self._log_fh:
            self._log_fh.write(alert.to_json() + "\n")

        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as exc:  # noqa: BLE001
                log.error("on_alert callback error: %s", exc)
