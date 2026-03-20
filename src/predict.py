import joblib
import numpy as np
import pandas as pd
import os

# Must match TOP_FEATURES in preprocess.py exactly
FEATURES = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'count', 'srv_count',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_diff_srv_rate', 'dst_host_rerror_rate',
]

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']


class NIDSEngine:
    """
    ML-Based Network Intrusion Detection Engine.
    Classifies network traffic as: Normal, DoS, Probe, R2L, or U2R.
    """

    def __init__(self,
                 model_path='models/rf_model.pkl',
                 scaler_path='models/scaler.pkl',
                 encoders_path='models/label_encoders.pkl'):

        for path in [model_path, scaler_path]:
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Model artifact not found at '{path}'.\n"
                    f"Run: python -m src.train"
                )

        self.model  = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

        if os.path.exists(encoders_path):
            self.label_encoders = joblib.load(encoders_path)
        else:
            print("[NIDSEngine] Warning: label_encoders.pkl not found. "
                  "Re-run `python -m src.train` to generate it.")
            self.label_encoders = None

    def _encode_features(self, input_dict: dict) -> list:
        row = dict(input_dict)

        if self.label_encoders:
            for col in CATEGORICAL_COLS:
                raw_val = str(row.get(col, ''))
                le = self.label_encoders[col]
                if raw_val in le.classes_:
                    row[col] = int(le.transform([raw_val])[0])
                else:
                    print(f"[NIDSEngine] Unknown {col} value '{raw_val}'. Defaulting to 0.")
                    row[col] = 0
        else:
            # Verified static fallback (66 services, from models/label_encoders.pkl)
            _STATIC_MAPS = {
                'protocol_type': {'icmp': 0, 'tcp': 1, 'udp': 2},
                'service': {
                    'IRC': 0, 'X11': 1, 'Z39_50': 2, 'auth': 3, 'bgp': 4,
                    'courier': 5, 'csnet_ns': 6, 'ctf': 7, 'daytime': 8,
                    'discard': 9, 'domain': 10, 'domain_u': 11, 'echo': 12,
                    'eco_i': 13, 'ecr_i': 14, 'efs': 15, 'exec': 16,
                    'finger': 17, 'ftp': 18, 'ftp_data': 19, 'gopher': 20,
                    'hostnames': 21, 'http': 22, 'http_443': 23, 'imap4': 24,
                    'iso_tsap': 25, 'klogin': 26, 'kshell': 27, 'ldap': 28,
                    'link': 29, 'login': 30, 'mtp': 31, 'name': 32,
                    'netbios_dgm': 33, 'netbios_ns': 34, 'netbios_ssn': 35,
                    'netstat': 36, 'nnsp': 37, 'nntp': 38, 'ntp_u': 39,
                    'other': 40, 'pm_dump': 41, 'pop_2': 42, 'pop_3': 43,
                    'printer': 44, 'private': 45, 'red_i': 46,
                    'remote_job': 47, 'rje': 48, 'shell': 49, 'smtp': 50,
                    'sql_net': 51, 'ssh': 52, 'sunrpc': 53, 'supdup': 54,
                    'systat': 55, 'telnet': 56, 'tftp_u': 57, 'tim_i': 58,
                    'time': 59, 'urh_i': 60, 'urp_i': 61, 'uucp': 62,
                    'uucp_path': 63, 'vmnet': 64, 'whois': 65,
                },
                'flag': {
                    'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3,
                    'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7,
                    'S3': 8, 'SF': 9, 'SH': 10,
                },
            }
            for col, mapping in _STATIC_MAPS.items():
                row[col] = mapping.get(str(row.get(col, '')), 0)

        return [row.get(f, 0) for f in FEATURES]

    def predict(self, input_dict: dict) -> dict:
        features = self._encode_features(input_dict)
        X = self.scaler.transform(pd.DataFrame([features], columns=FEATURES))
        prediction = self.model.predict(X)[0]
        confidence = self.model.predict_proba(X)[0].max()
        return {
            'prediction': prediction,
            'confidence': round(float(confidence), 4),
            'status':     'alert' if prediction != 'Normal' else 'normal'
        }

    def predict_batch(self, records: list) -> list:
        return [self.predict(r) for r in records]