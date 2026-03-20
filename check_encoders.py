# Run this in your project to see exactly what your encoders contain.
# We simulate what it would look like based on KDD99 sklearn fetch.
import sys
sys.path.insert(0, '.')

try:
    import joblib
    encoders = joblib.load('models/label_encoders.pkl')
    for col, le in encoders.items():
        print(f"\n{col} ({len(le.classes_)} classes):")
        for i, c in enumerate(le.classes_):
            print(f"  {i:3d} → {c}")
except Exception as e:
    print(f"Error: {e}")
