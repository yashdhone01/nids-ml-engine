import pandas as pd
import numpy as np
from sklearn.datasets import fetch_kddcup99
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

# Expanded from 15 → 19 features.
# Added 4 host-based rate features that are critical for
# separating Probe from DoS and R2L from Normal.
TOP_FEATURES = [
    # Original 15
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'count', 'srv_count',
    # Added: host-based rates (already computed by features.py)
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_diff_srv_rate', 'dst_host_rerror_rate',
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

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']


def load_and_preprocess():
    print("Fetching KDD Cup 99 dataset...")
    data = fetch_kddcup99(subset=None, shuffle=True,
                          random_state=42, percent10=True)

    df = pd.DataFrame(data.data, columns=data.feature_names)
    df['label'] = data.target
    df['label'] = df['label'].str.decode('utf-8')
    df['attack_category'] = df['label'].map(LABEL_MAP)
    df = df.dropna(subset=['attack_category'])

    for col in CATEGORICAL_COLS:
        if hasattr(df[col].iloc[0], 'decode'):
            df[col] = df[col].str.decode('utf-8')

    label_encoders = {}
    os.makedirs('models', exist_ok=True)

    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        label_encoders[col] = le
        print(f"  {col} classes: {list(le.classes_)}")

    joblib.dump(label_encoders, 'models/label_encoders.pkl')
    print("Label encoders saved to models/label_encoders.pkl")

    X = df[TOP_FEATURES].fillna(0)
    y = df['attack_category']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, 'models/scaler.pkl')

    print(f"Dataset shape: {X_scaled.shape}")
    print(f"Label distribution:\n{y.value_counts()}")

    return X_scaled, y