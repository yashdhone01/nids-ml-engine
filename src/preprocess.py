import pandas as pd
import numpy as np
from sklearn.datasets import fetch_kddcup99
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

TOP_15_FEATURES = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'count', 'srv_count'
]

LABEL_MAP = {
    'normal.': 'Normal',
    'back.': 'DoS', 'land.': 'DoS', 'neptune.': 'DoS',
    'pod.': 'DoS', 'smurf.': 'DoS', 'teardrop.': 'DoS',
    'ipsweep.': 'Probe', 'nmap.': 'Probe',
    'portsweep.': 'Probe', 'satan.': 'Probe',
    'ftp_write.': 'R2L', 'guess_passwd.': 'R2L', 'imap.': 'R2L',
    'multihop.': 'R2L', 'phf.': 'R2L', 'spy.': 'R2L',
    'warezclient.': 'R2L', 'warezmaster.': 'R2L',
    'buffer_overflow.': 'U2R', 'loadmodule.': 'U2R',
    'perl.': 'U2R', 'rootkit.': 'U2R'
}

def load_and_preprocess():
    print("Fetching KDD Cup 99 dataset...")
    # percent10=True fetches 10% subset — still 494K records, much faster
    data = fetch_kddcup99(subset=None, shuffle=True,
                          random_state=42, percent10=True)

    df = pd.DataFrame(data.data, columns=data.feature_names)
    df['label'] = data.target
    df['label'] = df['label'].str.decode('utf-8')
    df['attack_category'] = df['label'].map(LABEL_MAP)
    df = df.dropna(subset=['attack_category'])

    for col in ['protocol_type', 'service', 'flag']:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])

    X = df[TOP_15_FEATURES].fillna(0)
    y = df['attack_category']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    os.makedirs('models', exist_ok=True)
    joblib.dump(scaler, 'models/scaler.pkl')

    print(f"Dataset shape: {X_scaled.shape}")
    print(f"Label distribution:\n{y.value_counts()}")

    return X_scaled, y