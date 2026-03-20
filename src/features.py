"""
features.py — KDD Cup 99-compatible feature extraction from live flows.

Converts a FlowRecord (produced by capture.py) into the 41-feature
vector expected by NIDSEngine.  Features are organised exactly as in
the original KDD dataset so the trained model needs zero changes.

Feature groups
--------------
  1–9   Basic features        (duration, protocol, service, flag, bytes…)
  10–22 Content features      (su_attempted, hot, num_failed_logins…)
  23–31 Time-based traffic    (count, srv_count, error rates…)
  32–41 Host-based traffic    (dst_host_count, srv_diff_host_rate…)

Content features (10-22) cannot be computed from raw packets without
application-layer DPI; they are set to safe defaults (0) and flagged.
A comment marks each one so you know where to add DPI later.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Dict, Deque, NamedTuple, Optional

from src.capture import FlowRecord, FlowKey

# ---------------------------------------------------------------------------
# Feature vector definition
# ---------------------------------------------------------------------------

KDD_FEATURE_NAMES = [
    # Basic (1-9)
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    # Content (10-22)  — requires DPI; defaults to 0
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login",
    # Time-window traffic (23-31)
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate",
    # Host-based traffic (32-41)
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

assert len(KDD_FEATURE_NAMES) == 41


class FeatureVector(NamedTuple):
    """Named wrapper around the 41-element dict so callers can inspect fields."""
    features: Dict[str, object]
    flow_key: FlowKey
    timestamp: float
    dpi_available: bool = False      # True once DPI is wired in

    def to_dict(self) -> Dict[str, object]:
        return dict(self.features)


# ---------------------------------------------------------------------------
# Traffic window — rolling 2-second window for time-based features
# ---------------------------------------------------------------------------

_WINDOW_SECONDS = 2.0


class _WindowEntry(NamedTuple):
    timestamp: float
    dst_ip: str
    dst_port: int
    service: str
    src_ip: str
    is_serror: bool   # SYN error (S0, S1, RSTOS0)
    is_rerror: bool   # REJ / RSTR


_SERROR_FLAGS = {"S0", "S1", "RSTOS0"}
_RERROR_FLAGS = {"REJ", "RSTR"}


class TrafficWindow:
    """
    Maintains a rolling 2-second deque of completed flows.
    Used to compute the count/rate features (features 23-41).

    One shared TrafficWindow instance should be passed to every
    FeatureExtractor.extract() call so counts reflect the true
    network-wide window.
    """

    def __init__(self, window_seconds: float = _WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self._entries: Deque[_WindowEntry] = deque()

    def add(self, flow: FlowRecord) -> None:
        now = time.time()
        entry = _WindowEntry(
            timestamp=now,
            dst_ip=flow.key[1],
            dst_port=flow.key[3],
            service=flow.service,
            src_ip=flow.key[0],
            is_serror=flow.flag in _SERROR_FLAGS,
            is_rerror=flow.flag in _RERROR_FLAGS,
        )
        self._entries.append(entry)
        self._prune(now)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._entries and self._entries[0].timestamp < cutoff:
            self._entries.popleft()

    def snapshot(self) -> list[_WindowEntry]:
        self._prune(time.time())
        return list(self._entries)


# ---------------------------------------------------------------------------
# Host-based traffic table — last 100 connections per destination host
# ---------------------------------------------------------------------------

_HOST_WINDOW = 100   # KDD uses last-100-connections window


class HostTable:
    """
    Tracks the last N flows per destination IP for host-based features.
    Also maintains a separate per-(dst_ip, service) sub-window.
    """

    def __init__(self, window: int = _HOST_WINDOW):
        self.window = window
        # dst_ip → deque of (service, src_port, is_serror, is_rerror)
        self._host: Dict[str, Deque] = {}
        # (dst_ip, service) → deque of src_ip
        self._srv: Dict[tuple, Deque] = {}

    def add(self, flow: FlowRecord) -> None:
        dst = flow.key[1]
        svc = flow.service
        src_port = flow.key[2]
        serr = flow.flag in _SERROR_FLAGS
        rerr = flow.flag in _RERROR_FLAGS
        src_ip = flow.key[0]

        # Host window
        if dst not in self._host:
            self._host[dst] = deque(maxlen=self.window)
        self._host[dst].append((svc, src_port, serr, rerr))

        # Service window
        key = (dst, svc)
        if key not in self._srv:
            self._srv[key] = deque(maxlen=self.window)
        self._srv[key].append(src_ip)

    def get_host_features(self, dst_ip: str, service: str) -> Dict[str, float]:
        host_conns = list(self._host.get(dst_ip, []))
        srv_conns = list(self._srv.get((dst_ip, service), []))

        n = len(host_conns)
        if n == 0:
            return {k: 0.0 for k in [
                "dst_host_count", "dst_host_srv_count",
                "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                "dst_host_serror_rate", "dst_host_srv_serror_rate",
                "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
            ]}

        same_srv  = sum(1 for c in host_conns if c[0] == service)
        serr_host = sum(1 for c in host_conns if c[2])
        rerr_host = sum(1 for c in host_conns if c[3])

        # Port rate: fraction of host connections from same source port as this flow
        # (approximated as fraction using the service's connections' src ports)
        # We use same_srv as a proxy here — to be more precise, pass src_port in.
        src_ports = [c[1] for c in host_conns if c[0] == service]
        dominant_port = max(set(src_ports), key=src_ports.count) if src_ports else -1
        same_port = sum(1 for p in src_ports if p == dominant_port)

        m = len(srv_conns)
        unique_hosts = len(set(srv_conns))
        srv_serr = sum(
            1 for c in host_conns if c[0] == service and c[2]
        )
        srv_rerr = sum(
            1 for c in host_conns if c[0] == service and c[3]
        )

        return {
            "dst_host_count":            float(n),
            "dst_host_srv_count":        float(same_srv),
            "dst_host_same_srv_rate":    same_srv / n,
            "dst_host_diff_srv_rate":    (n - same_srv) / n,
            "dst_host_same_src_port_rate": same_port / max(same_srv, 1),
            "dst_host_srv_diff_host_rate": unique_hosts / max(m, 1),
            "dst_host_serror_rate":      serr_host / n,
            "dst_host_srv_serror_rate":  srv_serr / max(same_srv, 1),
            "dst_host_rerror_rate":      rerr_host / n,
            "dst_host_srv_rerror_rate":  srv_rerr / max(same_srv, 1),
        }


# ---------------------------------------------------------------------------
# Feature extractor
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """
    Stateless helper — all state lives in TrafficWindow and HostTable.

    Usage
    -----
        window = TrafficWindow()
        hosts  = HostTable()
        extractor = FeatureExtractor(window, hosts)

        def on_flow(flow: FlowRecord):
            vec = extractor.extract(flow)
            result = engine.predict(vec.to_dict())

        capture = PacketCapture(interface="eth0", on_flow_complete=on_flow)
    """

    def __init__(self, window: TrafficWindow, hosts: HostTable):
        self.window = window
        self.hosts = hosts

    def extract(self, flow: FlowRecord) -> FeatureVector:
        """Convert a completed FlowRecord into a KDD-compatible feature dict."""

        # Update shared state BEFORE computing window features so this
        # flow is included in its own window (matches KDD methodology).
        self.window.add(flow)
        self.hosts.add(flow)

        features: Dict[str, object] = {}

        # ---- Basic features (1-9) ----------------------------------------
        features["duration"]      = round(flow.duration, 3)
        features["protocol_type"] = flow.protocol_type
        features["service"]       = flow.service
        features["flag"]          = flow.flag
        features["src_bytes"]     = flow.src_bytes
        features["dst_bytes"]     = flow.dst_bytes
        # land: src/dst ip+port are identical (loopback attack)
        src_ip, dst_ip, src_port, dst_port, _ = flow.key
        features["land"]          = int(src_ip == dst_ip and src_port == dst_port)
        # wrong_fragment: count of packets with non-zero fragment offset
        # (requires raw IP layer inspection — approximated as 0)
        features["wrong_fragment"] = 0   # TODO: track in PacketCapture
        features["urgent"]        = 0   # TODO: count TCP URG flag packets

        # ---- Content features (10-22) — DPI required ---------------------
        # These fields describe application-layer behaviour (login attempts,
        # root commands, file creations).  They require protocol-aware DPI
        # (e.g. parsing FTP/Telnet payloads).  All set to 0 for now.
        for name in [
            "hot", "num_failed_logins", "logged_in", "num_compromised",
            "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds",
            "is_host_login", "is_guest_login",
        ]:
            features[name] = 0  # DPI placeholder

        # ---- Time-window traffic features (23-31) ------------------------
        window_entries = self.window.snapshot()
        tw = self._compute_time_window(flow, window_entries)
        features.update(tw)

        # ---- Host-based traffic features (32-41) -------------------------
        hf = self.hosts.get_host_features(dst_ip, flow.service)
        features.update(hf)

        return FeatureVector(
            features=features,
            flow_key=flow.key,
            timestamp=time.time(),
            dpi_available=False,
        )

    @staticmethod
    def _compute_time_window(
        flow: FlowRecord,
        entries: list[_WindowEntry],
    ) -> Dict[str, float]:
        """Compute the 9 time-based features from the rolling 2-second window."""

        if not entries:
            return {
                "count": 0, "srv_count": 0,
                "serror_rate": 0.0, "srv_serror_rate": 0.0,
                "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
                "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0,
            }

        dst_ip  = flow.key[1]
        service = flow.service

        # All connections to the SAME destination host in last 2s
        to_same_host = [e for e in entries if e.dst_ip == dst_ip]
        count = len(to_same_host)

        if count == 0:
            count = 1  # at minimum this flow itself
            to_same_host = [entries[-1]] if entries else []

        same_srv  = sum(1 for e in to_same_host if e.service == service)
        serr      = sum(1 for e in to_same_host if e.is_serror)
        rerr      = sum(1 for e in to_same_host if e.is_rerror)

        # Connections to same SERVICE in last 2s
        to_same_srv = [e for e in entries if e.service == service]
        srv_count = len(to_same_srv)
        srv_serr  = sum(1 for e in to_same_srv if e.is_serror)
        srv_rerr  = sum(1 for e in to_same_srv if e.is_rerror)
        srv_diff_hosts = len(set(e.dst_ip for e in to_same_srv))

        return {
            "count":             float(count),
            "srv_count":         float(srv_count),
            "serror_rate":       serr / count,
            "srv_serror_rate":   srv_serr / max(srv_count, 1),
            "rerror_rate":       rerr / count,
            "srv_rerror_rate":   srv_rerr / max(srv_count, 1),
            "same_srv_rate":     same_srv / count,
            "diff_srv_rate":     (count - same_srv) / count,
            "srv_diff_host_rate": srv_diff_hosts / max(srv_count, 1),
        }
