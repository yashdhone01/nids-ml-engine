# ML-Based Network Intrusion Detection Engine

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.4-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-99.96%25-brightgreen)

A modular ML engine that classifies network traffic as **Normal, DoS, Probe, R2L, or U2R** using the KDD Cup 99 dataset (~494K records).

---

## Results

| Model | Accuracy |
|---|---|
| Logistic Regression | 98.60% |
| Decision Tree | 99.95% |
| **Random Forest** | **99.96%** |

---

## Quickstart
```bash
git clone https://github.com/yashdhone01/ML-Based-NIDS.git
cd ML-Based-NIDS

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt

python -m src.train          # downloads dataset + trains model
python example.py            # run the engine
```

---

## Usage
```python
from src.predict import NIDSEngine

engine = NIDSEngine()

result = engine.predict({
    'src_bytes': 491,
    'dst_bytes': 0,
    'count': 2,
    'srv_count': 2
})
# {'prediction': 'DoS', 'confidence': 0.98, 'status': 'alert'}

results = engine.predict_batch([record1, record2, ...])
```

---

## Project Structure
```
├── src/
│   ├── preprocess.py   # data pipeline
│   ├── train.py        # train & save model
│   └── predict.py      # NIDSEngine class
├── models/             # saved .pkl files (generated locally)
├── example.py          # usage demo
└── requirements.txt
```

---

## Tech Stack

Python · Scikit-learn · Pandas · NumPy · KDD Cup 99

---

## Author

**Yash Dhone** · [GitHub](https://github.com/yashdhone01) · [Portfolio](https://yashdhone.vercel.app)