import re
import json
import joblib
from detector.features_simple import make_features

LOG_FILE = "/var/log/apache2/access.log"

PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

model = joblib.load("models/rf_apache.pkl")

alerts = []

with open(LOG_FILE, "r", errors="ignore") as f:
    for line in f:
        m = PATTERN.search(line)
        if not m:
            continue

        d = m.groupdict()

        feats = make_features(
            d["url"],
            d["method"],
            int(d["status"]),
            d["ua"]
        )

        pred = model.predict([feats])[0]
        proba = model.predict_proba([feats])[0]
        conf = float(max(proba))

        if pred != "normal":
            alerts.append({
                "type": pred,
                "confidence": round(conf, 3),
                "ip": d["ip"],
                "timestamp": d["ts"],
                "method": d["method"],
                "url": d["url"],
                "status": int(d["status"]),
                "ua": d["ua"]
            })

with open("outputs/alerts_rf.json", "w", encoding="utf-8") as out:
    json.dump(alerts, out, indent=2)

print("Analyse terminée. Résultats dans outputs/alerts_rf.json")
