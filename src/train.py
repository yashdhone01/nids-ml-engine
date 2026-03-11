import joblib
import time
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE
from src.preprocess import load_and_preprocess

def apply_smote(X_train, y_train):
    print("\nApplying SMOTE to fix class imbalance...")
    print("Before SMOTE:")
    unique, counts = np.unique(y_train, return_counts=True)
    for u, c in zip(unique, counts):
        print(f"  {u}: {c}")

    # SMOTE with safe min samples
    smote = SMOTE(random_state=42, k_neighbors=3)
    X_resampled, y_resampled = smote.fit_resample(X_train, y_train)

    print("\nAfter SMOTE:")
    unique, counts = np.unique(y_resampled, return_counts=True)
    for u, c in zip(unique, counts):
        print(f"  {u}: {c}")

    return X_resampled, y_resampled


def confidence_label(confidence):
    """Three-tier alert system based on confidence score."""
    if confidence >= 0.85:
        return 'CONFIRMED'
    elif confidence >= 0.50:
        return 'SUSPICIOUS'
    else:
        return 'UNLIKELY'


def evaluate_with_confidence(model, X_test, y_test):
    """Evaluate model and show confidence tier breakdown."""
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test).max(axis=1)

    confirmed  = (y_proba >= 0.85).sum()
    suspicious = ((y_proba >= 0.50) & (y_proba < 0.85)).sum()
    unlikely   = (y_proba < 0.50).sum()
    total      = len(y_proba)

    print("\n--- Confidence Tier Breakdown ---")
    print(f"  🔴 CONFIRMED  (≥85%) : {confirmed:>7} ({confirmed/total*100:.1f}%)")
    print(f"  🟡 SUSPICIOUS (50-85%): {suspicious:>7} ({suspicious/total*100:.1f}%)")
    print(f"  🟢 UNLIKELY   (<50%) : {unlikely:>7} ({unlikely/total*100:.1f}%)")

    return y_pred, y_proba


def train_all_models():
    X, y = load_and_preprocess()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Apply SMOTE only on training data
    X_train_bal, y_train_bal = apply_smote(X_train, y_train)

    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
        'Decision Tree':       DecisionTreeClassifier(max_depth=20, random_state=42),
        'Random Forest':       RandomForestClassifier(n_estimators=100,
                                                      n_jobs=-1, random_state=42)
    }

    results = {}
    for name, model in models.items():
        print(f"\n{'='*50}")
        print(f"Training {name}...")
        start = time.time()
        model.fit(X_train_bal, y_train_bal)
        elapsed = time.time() - start

        y_pred, y_proba = evaluate_with_confidence(model, X_test, y_test)
        acc = accuracy_score(y_test, y_pred)
        results[name] = {'accuracy': acc, 'model': model}

        print(f"\n--- Classification Report ---")
        print(f"  Accuracy : {acc*100:.2f}%")
        print(f"  Time     : {elapsed:.1f}s")
        print(classification_report(y_test, y_pred, zero_division=0))

    # Save best model
    best = results['Random Forest']['model']
    joblib.dump(best, 'models/rf_model.pkl')
    print("\n✅ Best model (Random Forest) saved to models/rf_model.pkl")

    # Summary table
    print("\n" + "="*50)
    print("FINAL RESULTS SUMMARY")
    print("="*50)
    for name, r in results.items():
        print(f"  {name:<25} : {r['accuracy']*100:.2f}%")

    return results, X_test, y_test


if __name__ == '__main__':
    train_all_models()