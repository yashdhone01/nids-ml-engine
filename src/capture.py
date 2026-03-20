"""
capture.py — Live packet capture and flow aggregation.

Sniffs raw packets off a network interface and groups them into
bi-directional flows keyed by 5-tuple. Each completed flow is
handed off to the feature extractor as a FlowRecord.
"""

from __future__ import annotations

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, proto)


@dataclass
class PacketRecord:
    """Minimal per-packet data retained for flow statistics."""
    timestamp: float
    size: int          # total IP payload bytes
    src_bytes: int     # application-layer payload (approx TCP/UDP payload)
    flags: int         # TCP flags bitmask (0 for non-TCP)
    is_error: bool     # RST or FIN on a non-established connection


@dataclass
class FlowRecord:
    """
    Aggregated representation of a single network flow.
    Populated by PacketCapture; consumed by FeatureExtractor.
    """
    key: FlowKey
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Packet lists (forward = src→dst, reverse = dst→src)
    fwd_packets: List[PacketRecord] = field(default_factory=list)
    rev_packets: List[PacketRecord] = field(default_factory=list)

    # Quick-access counters (avoid re-scanning lists every update)
    fwd_bytes: int = 0
    rev_bytes: int = 0
    fwd_syn: int = 0
    fwd_fin: int = 0
    fwd_rst: int = 0
    rev_syn: int = 0
    rev_rst: int = 0

    # Service fingerprint (set once on first packet)
    service: str = "other"
    protocol_type: str = "tcp"
    flag: str = "OTH"       # KDD connection state flag

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    @property
    def src_bytes(self) -> int:
        return self.fwd_bytes

    @property
    def dst_bytes(self) -> int:
        return self.rev_bytes

    @property
    def total_packets(self) -> int:
        return len(self.fwd_packets) + len(self.rev_packets)


# ---------------------------------------------------------------------------
# Service + flag helpers
# ---------------------------------------------------------------------------

_PORT_SERVICE_MAP: Dict[int, str] = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "domain_u", 80: "http", 110: "pop_3",
    143: "imap4", 443: "http_443", 8080: "http_8001",
    6000: "X11", 194: "IRC", 513: "login", 514: "shell",
}


def _resolve_service(dst_port: int, proto: str) -> str:
    if proto == "icmp":
        return "ecr_i"
    return _PORT_SERVICE_MAP.get(dst_port, "other")


def _compute_flag(flow: FlowRecord) -> str:
    """
    Approximate KDD connection state flag from TCP flag counters.
    KDD flags: SF, S0, S1, S2, S3, REJ, RSTO, RSTOS0, RSTR, SH, OTH
    """
    if flow.protocol_type != "tcp":
        return "SF"

    syn  = flow.fwd_syn  + flow.rev_syn
    fin  = flow.fwd_fin
    rst  = flow.fwd_rst  + flow.rev_rst

    if syn == 0:
        return "OTH"
    if rst > 0 and syn == 1 and flow.rev_syn == 0:
        return "RSTOS0"
    if rst > 0:
        return "RSTO" if flow.fwd_rst > 0 else "RSTR"
    if syn == 1 and flow.rev_syn == 0 and fin == 0:
        return "S0"
    if syn >= 1 and flow.rev_syn >= 1 and fin == 0:
        return "S1"
    if fin > 0 and flow.rev_syn > 0:
        return "SF"
    return "OTH"


# ---------------------------------------------------------------------------
# TCP flag bitmask constants
# ---------------------------------------------------------------------------

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


# ---------------------------------------------------------------------------
# PacketCapture
# ---------------------------------------------------------------------------

class PacketCapture:
    """
    Captures live packets from a network interface and assembles them
    into FlowRecords.  Completed flows (idle > timeout) are emitted
    via the on_flow_complete callback.

    Usage
    -----
        def handle_flow(flow: FlowRecord):
            features = FeatureExtractor.extract(flow, window)
            engine.predict(features)

        cap = PacketCapture(interface="eth0", on_flow_complete=handle_flow)
        cap.start()
        ...
        cap.stop()
    """

    FLOW_TIMEOUT = 120.0        # seconds idle before a flow is considered done
    REAP_INTERVAL = 10.0        # how often to scan for timed-out flows

    def __init__(
        self,
        interface: str,
        on_flow_complete: Callable[[FlowRecord], None],
        flow_timeout: float = FLOW_TIMEOUT,
        bpf_filter: str = "",
    ):
        self.interface = interface
        self.on_flow_complete = on_flow_complete
        self.flow_timeout = flow_timeout
        self.bpf_filter = bpf_filter

        self._flows: Dict[FlowKey, FlowRecord] = {}
        self._lock = threading.Lock()
        self._running = False
        self._reaper_thread: Optional[threading.Thread] = None

        # Stats
        self.packets_seen = 0
        self.flows_completed = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start capture in the current thread (blocking). Call from a thread."""
        try:
            from scapy.all import sniff  # type: ignore
        except ImportError:
            raise RuntimeError(
                "Scapy is not installed. Run: pip install scapy"
            )

        self._running = True
        self._reaper_thread = threading.Thread(
            target=self._reap_loop, daemon=True, name="flow-reaper"
        )
        self._reaper_thread.start()

        sniff(
            iface=self.interface,
            filter=self.bpf_filter or "ip",
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def stop(self) -> None:
        """Signal capture to stop and flush all in-progress flows."""
        self._running = False
        with self._lock:
            for flow in list(self._flows.values()):
                self._complete_flow(flow)
            self._flows.clear()

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------

    def _handle_packet(self, pkt) -> None:  # noqa: ANN001
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore

        if not pkt.haslayer(IP):
            return

        self.packets_seen += 1
        ip = pkt[IP]
        now = time.time()

        # ---- Decode transport layer ----
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            proto = "tcp"
            flags = int(tcp.flags)
            payload = len(bytes(tcp.payload))
            is_error = bool(flags & TCP_RST)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            proto = "udp"
            flags, is_error = 0, False
            payload = len(bytes(udp.payload))
        elif pkt.haslayer(ICMP):
            src_port = dst_port = 0
            proto = "icmp"
            flags, is_error = 0, False
            payload = len(bytes(ip.payload))
        else:
            return  # ignore non-TCP/UDP/ICMP

        key: FlowKey = (ip.src, ip.dst, src_port, dst_port, proto)
        rev_key: FlowKey = (ip.dst, ip.src, dst_port, src_port, proto)

        pkt_record = PacketRecord(
            timestamp=now,
            size=len(ip),
            src_bytes=payload,
            flags=flags,
            is_error=is_error,
        )

        with self._lock:
            # Check if this belongs to an existing flow (fwd or rev)
            if key in self._flows:
                flow = self._flows[key]
                is_forward = True
            elif rev_key in self._flows:
                flow = self._flows[rev_key]
                key = rev_key
                is_forward = False
            else:
                # New flow
                flow = FlowRecord(
                    key=key,
                    start_time=now,
                    last_seen=now,
                    service=_resolve_service(dst_port, proto),
                    protocol_type=proto,
                )
                self._flows[key] = flow
                is_forward = True

            flow.last_seen = now
            self._update_flow(flow, pkt_record, is_forward, flags, proto)

    def _update_flow(
        self,
        flow: FlowRecord,
        pkt: PacketRecord,
        is_forward: bool,
        flags: int,
        proto: str,
    ) -> None:
        if is_forward:
            flow.fwd_packets.append(pkt)
            flow.fwd_bytes += pkt.src_bytes
            if proto == "tcp":
                if flags & TCP_SYN:
                    flow.fwd_syn += 1
                if flags & TCP_FIN:
                    flow.fwd_fin += 1
                if flags & TCP_RST:
                    flow.fwd_rst += 1
        else:
            flow.rev_packets.append(pkt)
            flow.rev_bytes += pkt.src_bytes
            if proto == "tcp":
                if flags & TCP_SYN:
                    flow.rev_syn += 1
                if flags & TCP_RST:
                    flow.rev_rst += 1

        # Finalise flag on every update (cheap string assignment)
        flow.flag = _compute_flag(flow)

    # ------------------------------------------------------------------
    # Flow reaper
    # ------------------------------------------------------------------

    def _reap_loop(self) -> None:
        while self._running:
            time.sleep(self.REAP_INTERVAL)
            self._reap_timed_out_flows()

    def _reap_timed_out_flows(self) -> None:
        now = time.time()
        timed_out = []
        with self._lock:
            for key, flow in list(self._flows.items()):
                if now - flow.last_seen >= self.flow_timeout:
                    timed_out.append(key)
        for key in timed_out:
            with self._lock:
                flow = self._flows.pop(key, None)
            if flow:
                self._complete_flow(flow)

    def _complete_flow(self, flow: FlowRecord) -> None:
        self.flows_completed += 1
        try:
            self.on_flow_complete(flow)
        except Exception as exc:  # noqa: BLE001
            print(f"[capture] on_flow_complete error: {exc}")
