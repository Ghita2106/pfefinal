import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from detector.features_simple import make_features

print("Lecture du dataset")

data = pd.read_csv("data/training.csv")

X = []
y = []

for i,row in data.iterrows():

    features = make_features(
        row["url"],
        row["method"],
        int(row["status"]),
        row["ua"]
    )

    X.append(features)
    y.append(row["label"])


print("Entrainement du modèle")

model = RandomForestClassifier(
    n_estimators=100
)

model.fit(X,y)

joblib.dump(model,"models/rf_apache.pkl")

print("Modèle sauvegardé dans models/rf_apache.pkl ")
