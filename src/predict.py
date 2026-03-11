import joblib
import numpy as np

FEATURES = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'count', 'srv_count'
]

def load_model():
    model  = joblib.load('models/rf_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    return model, scaler

def get_confidence_tier(confidence):
    if confidence >= 0.85:
        return 'CONFIRMED'
    elif confidence >= 0.50:
        return 'SUSPICIOUS'
    else:
        return 'UNLIKELY'

def predict_single(input_dict: dict):
    model, scaler = load_model()
    features = [input_dict.get(f, 0) for f in FEATURES]
    X = scaler.transform([features])
    prediction  = model.predict(X)[0]
    confidence  = model.predict_proba(X)[0].max()
    tier        = get_confidence_tier(confidence)
    return {
        'prediction':  prediction,
        'confidence':  round(float(confidence), 4),
        'alert_tier':  tier,
        'status':      'alert' if prediction != 'Normal' else 'normal'
    }