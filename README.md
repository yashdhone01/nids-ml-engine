# NIDS — ML-Based Network Intrusion Detection System

A machine learning pipeline that classifies network traffic as **Normal, DoS, Probe, R2L, or U2R** using the KDD Cup 99 dataset.

## Results
| Model | Accuracy |
|---|---|
| Logistic Regression | ~89% |
| Decision Tree | ~95% |
| **Random Forest** | **~97%** |

## Project Structure
```
NIDS/
├── src/                  # Core ML pipeline
│   ├── preprocess.py     # Data loading & feature engineering
│   ├── train.py          # Model training & evaluation
│   └── predict.py        # Inference logic
├── notebooks/            # EDA & evaluation notebooks
├── models/               # Saved .pkl files (gitignored)
├── app.py                # Flask REST API
├── Dockerfile            # Container setup
└── requirements.txt      # Dependencies
```

## Quickstart
```bash
# 1. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train all models
python -m src.train

# 4. Start the API
python app.py
```

## API Usage
```bash
# Health check
GET http://localhost:5000/health

# Predict
POST http://localhost:5000/predict
Content-Type: application/json

{
  "duration": 0,
  "protocol_type": 1,
  "service": 21,
  "flag": 10,
  "src_bytes": 491,
  "dst_bytes": 0,
  "land": 0,
  "wrong_fragment": 0,
  "urgent": 0,
  "hot": 0,
  "num_failed_logins": 0,
  "logged_in": 0,
  "num_compromised": 0,
  "count": 2,
  "srv_count": 2
}
```

## Tech Stack
Python · Scikit-learn · Flask · Docker · KDD Cup 99

## Author
Yash Dhone — [yashdhone.vercel.app](https://yashdhone.vercel.app)