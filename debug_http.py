"""
debug_http.py — Diagnose the Normal HTTP false positive.
Usage: python debug_http.py
"""
import time

def make_http_flow():
    from src.capture import FlowRecord, PacketRecord
    key = ("192.168.1.100", "10.0.0.1", 54321, 80, "tcp")
    now = time.time()
    flow = FlowRecord(
        key=key, start_time=now-0.5, last_seen=now,
        service="http", protocol_type="tcp",
        flag="SF", fwd_bytes=491, rev_bytes=4096,
    )
    flow.fwd_packets.append(PacketRecord(timestamp=now-0.5, size=531, src_bytes=491, flags=0x002, is_error=False))
    flow.rev_packets.append(PacketRecord(timestamp=now, size=4136, src_bytes=4096, flags=0x012, is_error=False))
    flow.fwd_syn=1; flow.rev_syn=1; flow.fwd_fin=1
    return flow

from src.features import FeatureExtractor, HostTable, TrafficWindow
from src.predict import NIDSEngine, FEATURES

# Test 1: cold start (nothing in window/hosts)
print("=== Test 1: Cold start (empty window, empty host table) ===")
w=TrafficWindow(); h=HostTable(); ex=FeatureExtractor(w,h)
flow=make_http_flow()
vec=ex.extract(flow)
print("Features passed to model:")
for f in FEATURES:
    print(f"  {f:<35} = {vec.features.get(f, 'MISSING')}")
engine=NIDSEngine()
result=engine.predict(vec.to_dict())
print(f"\nPrediction: {result['prediction']} (conf={result['confidence']})\n")

# Test 2: warm start — 10 prior HTTP flows from same client (realistic browse session)
print("=== Test 2: Warm start (10 prior Normal HTTP flows in window) ===")
from src.features import _WindowEntry
w2=TrafficWindow(); h2=HostTable(); ex2=FeatureExtractor(w2,h2)
now=time.time()
# Seed 10 normal HTTP flows to same dst
for i in range(10):
    w2._entries.append(_WindowEntry(
        timestamp=now - (10-i)*0.3,
        dst_ip="10.0.0.1", dst_port=80,
        service="http", src_ip="192.168.1.100",
        is_serror=False, is_rerror=False,
    ))
    class _F:
        key=("192.168.1.100","10.0.0.1",54320+i,80,"tcp")
        service="http"; flag="SF"
    h2.add(_F())

flow2=make_http_flow()
vec2=ex2.extract(flow2)
for f in ['count','dst_host_count','dst_host_srv_count',
          'dst_host_diff_srv_rate','dst_host_rerror_rate',
          'dst_host_same_srv_rate']:
    print(f"  {f:<35} = {vec2.features.get(f)}")
result2=engine.predict(vec2.to_dict())
print(f"\nPrediction: {result2['prediction']} (conf={result2['confidence']})\n")

# Test 3: what does a typical R2L look like in this feature space?
print("=== Test 3: What R2L features look like (warezclient) ===")
r2l_features = {
    'duration': 0.0, 'protocol_type': 'tcp', 'service': 'ftp_data',
    'flag': 'SF', 'src_bytes': 0, 'dst_bytes': 7985, 'land': 0,
    'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0,
    'logged_in': 0, 'num_compromised': 0, 'count': 1, 'srv_count': 1,
    'dst_host_count': 1.0, 'dst_host_srv_count': 1.0,
    'dst_host_diff_srv_rate': 0.0, 'dst_host_rerror_rate': 0.0,
}
r2l_result=engine.predict(r2l_features)
print(f"  warezclient-like → {r2l_result['prediction']} (conf={r2l_result['confidence']})")

# How different is http from r2l in new feature space?
http_features = vec.to_dict()
print(f"\n  Key distinguishing values:")
print(f"  {'feature':<30} {'HTTP':>10} {'R2L':>10}")
for f in ['src_bytes','dst_bytes','service','dst_host_count','count']:
    print(f"  {f:<30} {str(http_features.get(f,'?')):>10} {str(r2l_features.get(f,'?')):>10}")
