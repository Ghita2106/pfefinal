import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from detector.features_simple import make_features

df = pd.read_csv("data/training.csv")

X = df.apply(
    lambda r: make_features(r["url"], r["method"], int(r["status"]), r["ua"]),
    axis=1
).tolist()

y = df["label"].tolist()

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X, y)

joblib.dump(model, "models/rf_apache.pkl")

print("Modèle entraîné et sauvegardé dans models/rf_apache.pkl")
