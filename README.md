# ML-Based Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.4-orange)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Docker](https://img.shields.io/badge/Docker-ready-blue)
![Accuracy](https://img.shields.io/badge/Accuracy-99.96%25-brightgreen)

A machine learning pipeline that classifies network traffic into **Normal, DoS, Probe, R2L, or U2R** attack categories using the KDD Cup 99 dataset (~494K records).

---

## 📊 Results

| Model | Accuracy | Training Time |
|---|---|---|
| Logistic Regression | 98.60% | 16.6s |
| Decision Tree | 99.95% | 1.4s |
| **Random Forest** | **99.96%** | 6.1s |

### Confusion Matrix
![Confusion Matrix](data/confusion_matrix.png)

### Feature Importance
![Feature Importance](data/feature_importance.png)

### Model Comparison
![Model Comparison](data/model_comparison.png)

---

## 🏗️ Project Structure
```
ml-network-ids/
├── src/
│   ├── preprocess.py     # Data loading, encoding, scaling
│   ├── train.py          # Train all 3 models, save best
│   └── predict.py        # Load model and predict
├── notebooks/
│   ├── 01_preprocessing.ipynb   # EDA + distribution charts
│   ├── 02_training.ipynb        # Model training + comparison
│   └── 03_evaluation.ipynb      # Confusion matrix + F1 scores
├── data/                 # Generated charts
├── models/               # Saved .pkl files (generated locally)
├── app.py                # Flask REST API
├── Dockerfile            # Container setup
└── requirements.txt
```

---

## ⚙️ Quickstart
```bash
# 1. Clone the repo
git clone https://github.com/yashdhone01/ML-Based-NIDS.git
cd ML-Based-NIDS

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Train models (downloads dataset automatically)
python -m src.train

# 5. Start the API
python app.py
```

---

## 🔌 API Usage

**Health check:**
```bash
GET http://localhost:5000/health
```

**Predict:**
```bash
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

**Response:**
```json
{
  "prediction": "DoS",
  "confidence": 0.98,
  "status": "alert"
}
```

---

## 🐳 Docker
```bash
docker build -t ids-api .
docker run -p 5000:5000 ids-api
```

---

## 📋 Classification Report
```
              precision    recall  f1-score   support

         DoS       1.00      1.00      1.00     78292
      Normal       1.00      1.00      1.00     19456
       Probe       0.97      0.98      0.97       822
         R2L       0.98      0.97      0.98       225
         U2R       1.00      0.80      0.89        10

    accuracy                           1.00     98805
   macro avg       0.99      0.95      0.97     98805
weighted avg       1.00      1.00      1.00     98805
```

---

## 🛠️ Tech Stack

- **Python 3.10**
- **Scikit-learn** — Logistic Regression, Decision Tree, Random Forest
- **Pandas / NumPy** — data preprocessing
- **Flask** — REST API
- **Docker** — containerization
- **Dataset** — KDD Cup 99 (~494K records)

---

## 👤 Author

**Yash Dhone**  
[GitHub](https://github.com/yashdhone01) · [LinkedIn](https://linkedin.com/in/yash-dhone) · [Portfolio](https://yashdhone.vercel.app)