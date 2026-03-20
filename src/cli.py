"""
cli.py — Command-line interface for the live NIDS monitor.

Usage
-----
    # Requires root / CAP_NET_RAW
    sudo python -m src.monitor --interface eth0

    # With options
    sudo python -m src.monitor \
        --interface eth0 \
        --threshold 0.7 \
        --log alerts.ndjson \
        --all-traffic          # show Normal flows too
        --bpf "not port 22"    # exclude SSH from analysis

    # List available interfaces
    python -m src.monitor --list-interfaces
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time

# ---------------------------------------------------------------------------
# Logging setup — before any other imports so submodules inherit the level
# ---------------------------------------------------------------------------

logging.basicConfig(
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING,
)
log = logging.getLogger("nids.cli")


def _print_banner(interface: str, threshold: float, log_file: str | None) -> None:
    print("\n" + "═" * 60)
    print("  🛡  NIDS — ML-Based Network Intrusion Detection System")
    print("═" * 60)
    print(f"  Interface  : {interface}")
    print(f"  Threshold  : {threshold}")
    print(f"  Log file   : {log_file or '(none)'}")
    print("═" * 60)
    print("  Severity legend:")
    print("    \033[93mLOW\033[0m      Probe / reconnaissance")
    print("    \033[33mMEDIUM\033[0m   R2L — remote-to-local access")
    print("    \033[91mHIGH\033[0m     DoS — denial of service")
    print("    \033[95mCRITICAL\033[0m U2R — privilege escalation")
    print("═" * 60 + "\n")


def _list_interfaces() -> None:
    """Print available network interfaces."""
    try:
        from scapy.all import get_if_list  # type: ignore
        ifaces = get_if_list()
        print("Available interfaces:")
        for iface in ifaces:
            print(f"  {iface}")
    except ImportError:
        # Fallback: read from /proc/net/dev on Linux
        if os.path.exists("/proc/net/dev"):
            with open("/proc/net/dev") as f:
                lines = f.readlines()[2:]
            for line in lines:
                iface = line.split(":")[0].strip()
                print(f"  {iface}")
        else:
            print("Scapy not installed. Install with: pip install scapy")


def _check_privileges() -> None:
    """Warn if not running as root (packet capture requires it on Linux)."""
    if os.name == "nt":
        return   # Windows handles this differently
    if os.geteuid() != 0:
        print("\n⚠️  Warning: packet capture typically requires root or CAP_NET_RAW.")
        print("   Try: sudo python -m src.monitor\n")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.monitor",
        description="ML-based live network intrusion detection system.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python -m src.monitor --interface eth0
  sudo python -m src.monitor --interface wlan0 --threshold 0.8 --log /var/log/nids.ndjson
  python -m src.monitor --list-interfaces
        """,
    )
    parser.add_argument(
        "--interface", "-i",
        default="eth0",
        metavar="IFACE",
        help="Network interface to sniff (default: eth0)",
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=0.5,
        metavar="FLOAT",
        help="Minimum confidence to emit an alert, 0.0–1.0 (default: 0.5)",
    )
    parser.add_argument(
        "--log", "-l",
        default=None,
        metavar="FILE",
        help="Write alerts as NDJSON to FILE (appends if exists)",
    )
    parser.add_argument(
        "--all-traffic",
        action="store_true",
        help="Print Normal flows as well as alerts",
    )
    parser.add_argument(
        "--bpf",
        default="",
        metavar="FILTER",
        help='BPF filter string (e.g. "not port 22")',
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )
    parser.add_argument(
        "--stats-interval",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Print pipeline stats every N seconds (default: 30, 0 = off)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.verbose:
        logging.getLogger("nids").setLevel(logging.DEBUG)

    if args.list_interfaces:
        _list_interfaces()
        return 0

    _check_privileges()

    # ---- Load model ----
    try:
        from src.predict import NIDSEngine  # type: ignore
        engine = NIDSEngine()
    except Exception as exc:
        print(f"❌  Failed to load NIDSEngine: {exc}")
        print("   Have you run `python -m src.train` yet?")
        return 1

    # ---- Start monitor ----
    from src.flow_monitor import FlowMonitor  # type: ignore

    monitor = FlowMonitor(
        interface=args.interface,
        engine=engine,
        alert_only=not args.all_traffic,
        confidence_threshold=args.threshold,
        bpf_filter=args.bpf,
        log_file=args.log,
    )

    _print_banner(args.interface, args.threshold, args.log)

    monitor.start()

    # ---- Stats printer ----
    def _print_stats() -> None:
        while True:
            time.sleep(args.stats_interval)
            s = monitor.get_stats()
            uptime = s.get("uptime_seconds", 0)
            print(
                f"\n── Stats ── uptime {uptime}s  "
                f"pkts {s.get('packets_seen', 0)}  "
                f"flows {s.get('flows_processed', 0)}  "
                f"alerts {s.get('alerts_emitted', 0)}  "
                f"in-flight {s.get('flows_in_progress', 0)}\n"
            )

    import threading
    if args.stats_interval > 0:
        stats_thread = threading.Thread(target=_print_stats, daemon=True)
        stats_thread.start()

    # ---- Graceful shutdown on Ctrl-C ----
    def _handle_signal(signum, frame):  # noqa: ANN001
        print("\n\nShutting down...")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Block main thread
    signal.pause() if hasattr(signal, "pause") else time.sleep(float("inf"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
