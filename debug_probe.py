"""
debug_probe.py — Run this to diagnose the Probe scenario.
Shows exactly what feature values the extractor computes.

Usage: python debug_probe.py
"""
import time, sys

def make_probe_flow():
    from src.capture import FlowRecord, PacketRecord
    key = ("192.168.1.50", "10.0.0.2", 60001, 22, "tcp")
    now = time.time()
    flow = FlowRecord(
        key=key, start_time=now, last_seen=now,
        service="other", protocol_type="tcp",
        flag="REJ", fwd_bytes=0, rev_bytes=0,
    )
    flow.fwd_packets.append(PacketRecord(
        timestamp=now, size=40, src_bytes=0, flags=0x002, is_error=False,
    ))
    flow.fwd_syn=1; flow.rev_syn=0; flow.fwd_fin=0
    return flow

from src.features import FeatureExtractor, HostTable, TrafficWindow, _WindowEntry

window = TrafficWindow()
hosts  = HostTable()

# Seed 50 probe connections
services = ["http","ftp","smtp","ssh","telnet","other","private",
            "domain_u","finger","auth","shell","login","exec",
            "klogin","kshell","pop_3","imap4","netstat","systat",
            "name","whois","sunrpc","gopher","uucp","time",
            "echo","discard","daytime","ftp_data","nntp",
            "X11","bgp","ldap","vmnet","urp_i","urh_i","red_i",
            "eco_i","tim_i","tftp_u","rje","remote_job","link",
            "iso_tsap","hostnames","sql_net","supdup","efs","ctf","mtp"]

now = time.time()
n = 50
for i in range(n):
    svc = services[i % len(services)]
    window._entries.append(_WindowEntry(
        timestamp=now - (n - i) * 0.02,
        dst_ip="10.0.0.2",
        dst_port=1 + i,
        service=svc,
        src_ip="192.168.1.50",
        is_serror=False,
        is_rerror=True,
    ))
    class _F:
        key = ("192.168.1.50", "10.0.0.2", 60000, 1 + i, "tcp")
        service = svc
        flag = "REJ"
    hosts.add(_F())

print(f"Window entries count : {len(window._entries)}")
print(f"Window age of oldest : {time.time() - window._entries[0].timestamp:.2f}s")
print(f"Window timeout       : {window.window_seconds}s")
print()

# Check how many entries target 10.0.0.2
to_host = [e for e in window._entries if e.dst_ip == "10.0.0.2"]
print(f"Entries to 10.0.0.2  : {len(to_host)}")
print(f"rerror in those      : {sum(1 for e in to_host if e.is_rerror)}")
unique_svcs = len(set(e.service for e in to_host))
print(f"Unique services      : {unique_svcs}")
print()

# Now extract features
extractor = FeatureExtractor(window, hosts)
flow = make_probe_flow()
vec  = extractor.extract(flow)

print("Key features for probe flow:")
for k in ["count","srv_count","serror_rate","rerror_rate",
          "srv_rerror_rate","same_srv_rate","diff_srv_rate",
          "dst_host_count","dst_host_rerror_rate","dst_host_diff_srv_rate"]:
    print(f"  {k:<35} = {vec.features[k]}")

print()
# Now predict
from src.predict import NIDSEngine
engine = NIDSEngine()
result = engine.predict(vec.to_dict())
print(f"Prediction: {result['prediction']} (conf={result['confidence']})")
