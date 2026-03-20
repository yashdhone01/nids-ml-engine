"""
test_pipeline.py — Offline integration test for Phase 1.
No network interface or root required.

Usage:  python test_pipeline.py
"""
from __future__ import annotations
import sys, time


# ---------------------------------------------------------------------------
# Synthetic flow builder
# ---------------------------------------------------------------------------

def make_flow(
    src_ip="192.168.1.100", dst_ip="10.0.0.1",
    src_port=54321, dst_port=80, proto="tcp",
    fwd_bytes=491, rev_bytes=1024, duration=0.5,
    flag="SF", service="http",
    fwd_syn=1, rev_syn=1, fwd_fin=1, fwd_rst=0, rev_rst=0,
):
    from src.capture import FlowRecord, PacketRecord
    key = (src_ip, dst_ip, src_port, dst_port, proto)
    now = time.time()
    flow = FlowRecord(key=key, start_time=now-duration, last_seen=now,
                      service=service, protocol_type=proto, flag=flag,
                      fwd_bytes=fwd_bytes, rev_bytes=rev_bytes)
    flow.fwd_packets.append(PacketRecord(
        timestamp=now-duration, size=max(fwd_bytes,1)+40,
        src_bytes=fwd_bytes, flags=0x002, is_error=False))
    if rev_bytes > 0:
        flow.rev_packets.append(PacketRecord(
            timestamp=now, size=rev_bytes+40,
            src_bytes=rev_bytes, flags=0x012, is_error=False))
    flow.fwd_syn=fwd_syn; flow.rev_syn=rev_syn
    flow.fwd_fin=fwd_fin; flow.fwd_rst=fwd_rst; flow.rev_rst=rev_rst
    return flow


# ---------------------------------------------------------------------------
# Window seeders
# ---------------------------------------------------------------------------

def _seed_normal_http(window, hosts, dst_ip="10.0.0.1", n=10):
    """
    Warm context for a Normal HTTP browse.
    Real browsers generate many prior connections to the same host/service.
    Without this, dst_host_count=1 overlaps with R2L's cold-start signature.
    """
    from src.features import _WindowEntry
    now = time.time()
    for i in range(n):
        window._entries.append(_WindowEntry(
            timestamp=now - (n-i)*0.3,
            dst_ip=dst_ip, dst_port=80, service="http",
            src_ip="192.168.1.100", is_serror=False, is_rerror=False,
        ))
        class _F:
            key = ("192.168.1.100", dst_ip, 54310+i, 80, "tcp")
            service = "http"; flag = "SF"
        hosts.add(_F())


def _seed_dos_window(window, hosts, dst_ip="10.0.0.1", n=300):
    """
    neptune/smurf: hundreds of unanswered SYNs to the same host.
    count≈300, serror_rate≈1.0 is the KDD99 DoS signature.
    """
    from src.features import _WindowEntry
    now = time.time()
    for i in range(n):
        window._entries.append(_WindowEntry(
            timestamp=now - (n-i)*0.004,
            dst_ip=dst_ip, dst_port=80, service="http",
            src_ip=f"10.0.1.{i%254+1}", is_serror=True, is_rerror=False,
        ))
        class _F:
            key = (f"10.0.1.{i%254+1}", dst_ip, 1024+i, 80, "tcp")
            service = "http"; flag = "S0"
        hosts.add(_F())


def _seed_probe_window(window, hosts, dst_ip="10.0.0.2", n=50):
    """
    portsweep/satan: same source, many different services.
    count≈50, rerror_rate≈1.0, diff_srv_rate≈1.0 is the KDD99 Probe signature.
    """
    from src.features import _WindowEntry
    services = [
        "http","ftp","smtp","ssh","telnet","other","private","domain_u",
        "finger","auth","shell","login","exec","klogin","kshell","pop_3",
        "imap4","netstat","systat","name","whois","sunrpc","gopher","uucp",
        "time","echo","discard","daytime","ftp_data","nntp","X11","bgp",
        "ldap","vmnet","urp_i","urh_i","red_i","eco_i","tim_i","tftp_u",
        "rje","remote_job","link","iso_tsap","hostnames","sql_net","supdup",
        "efs","ctf","mtp",
    ]
    now = time.time()
    for i in range(n):
        svc = services[i % len(services)]
        window._entries.append(_WindowEntry(
            timestamp=now - (n-i)*0.02,
            dst_ip=dst_ip, dst_port=1+i, service=svc,
            src_ip="192.168.1.50", is_serror=False, is_rerror=True,
        ))
        class _F:
            key = ("192.168.1.50", dst_ip, 60000, 1+i, "tcp")
            service = svc; flag = "REJ"
        hosts.add(_F())


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

SCENARIOS = [
    dict(
        name="Normal — HTTP browse",
        flow_kwargs=dict(fwd_bytes=491, rev_bytes=4096, flag="SF",
                         service="http", duration=0.12,
                         fwd_syn=1, rev_syn=1, fwd_fin=1),
        expect="Normal",
        # Real browsers always have prior connections to the same host.
        # 10 warm flows push dst_host_count to 11, making it unambiguous Normal.
        seed="http_warm",
    ),
    dict(
        name="Normal — SMTP email",
        flow_kwargs=dict(src_ip="192.168.1.10", dst_port=25,
                         fwd_bytes=512, rev_bytes=128, flag="SF",
                         service="smtp", duration=0.3,
                         fwd_syn=1, rev_syn=1, fwd_fin=1),
        expect="Normal",
        seed="none",
    ),
    dict(
        name="DoS — neptune SYN flood",
        flow_kwargs=dict(src_ip="10.0.1.1", dst_ip="10.0.0.1",
                         fwd_bytes=0, rev_bytes=0, flag="S0",
                         service="http", proto="tcp", duration=0.0,
                         fwd_syn=1, rev_syn=0, fwd_fin=0),
        expect="DoS",
        seed="dos",
    ),
    dict(
        name="Probe — portsweep",
        flow_kwargs=dict(src_ip="192.168.1.50", dst_ip="10.0.0.2",
                         fwd_bytes=0, rev_bytes=0, flag="REJ",
                         service="other", proto="tcp", duration=0.0,
                         fwd_syn=1, rev_syn=0, fwd_fin=0),
        expect="Probe",
        seed="probe",
    ),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_tests() -> bool:
    print("=" * 60)
    print("  NIDS Phase 1 — Pipeline integration test")
    print("=" * 60)

    try:
        from src.predict import NIDSEngine
        engine = NIDSEngine()
        print("✓  NIDSEngine loaded\n")
    except Exception as exc:
        print(f"✗  Could not load NIDSEngine: {exc}")
        print("   Run `python -m src.train` first.")
        return False

    from src.features import FeatureExtractor, HostTable, TrafficWindow
    all_passed = True

    for scenario in SCENARIOS:
        window = TrafficWindow(); hosts = HostTable()
        extractor = FeatureExtractor(window, hosts)

        seed = scenario.get("seed", "none")
        dst  = scenario["flow_kwargs"].get("dst_ip", "10.0.0.1")
        if   seed == "http_warm": _seed_normal_http(window, hosts, dst_ip=dst)
        elif seed == "dos":       _seed_dos_window(window, hosts, dst_ip=dst)
        elif seed == "probe":     _seed_probe_window(window, hosts, dst_ip=dst)

        flow   = make_flow(**scenario["flow_kwargs"])
        vec    = extractor.extract(flow)
        result = engine.predict(vec.to_dict())

        prediction = result["prediction"]
        confidence = result["confidence"]
        expected   = scenario["expect"]
        ok = prediction == expected

        color = "\033[92m" if ok else "\033[91m"
        reset = "\033[0m"
        mark  = "✓" if ok else "✗"
        print(f"  {color}{mark}{reset}  {scenario['name']:<35} "
              f"→ {prediction:<8} conf={confidence:.2f}  (expected {expected})")
        if not ok:
            all_passed = False

    # Feature spot-check
    print()
    print("Feature spot-check (HTTP browse, warm context):")
    w=TrafficWindow(); h=HostTable(); ex=FeatureExtractor(w,h)
    _seed_normal_http(w, h)
    vec=ex.extract(make_flow())
    for k in ["duration","protocol_type","service","flag","src_bytes","dst_bytes",
              "count","serror_rate","rerror_rate","dst_host_count",
              "dst_host_diff_srv_rate","dst_host_rerror_rate"]:
        print(f"  {k:<35} = {vec.features[k]}")

    print()
    print("All tests passed ✓" if all_passed else "Some tests failed ✗")
    return all_passed


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)