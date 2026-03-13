import re
import json
import joblib
from collections import defaultdict
from detector.features_simple import make_features

log_file = "/var/log/apache2/access.log"
model_file = "models/rf_apache.pkl"
output_file = "outputs/alerts_rf.json"

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

print("Chargement du modèle")
model = joblib.load(model_file)

alerts = []
attempts = defaultdict(int)

THRESHOLD = 5

with open(log_file, "r", errors="ignore") as f:

    for line in f:

        m = pattern.search(line)

        if m is None:
            continue

        data = m.groupdict()

        ip = data["ip"]
        url = data["url"]
        method = data["method"]
        status = int(data["status"])
        ua = data["ua"]

        path = url.split("?")[0]

        # ignorer quelques pages normales
        if path in ["/", "/index.php", "/logout.php", "/register.php", "/favicon.ico"]:
            continue

        # brute force sur login.php
        if path == "/login.php":

            if method == "POST":
                attempts[ip] += 1

                if attempts[ip] >= THRESHOLD:
                    alert = {
                        "type": "bruteforce",
                        "confidence": 1.0,
                        "ip": ip,
                        "timestamp": data["ts"],
                        "method": method,
                        "url": url,
                        "status": status,
                        "ua": ua
                    }

                    alerts.append(alert)

            continue

        # sinon on teste SQLi avec le modèle
        features = make_features(url, method, status, ua)

        pred = model.predict([features])[0]
        proba = model.predict_proba([features])[0]
        confidence = float(max(proba))

        if pred == "sqli":

            alert = {
                "type": "sqli",
                "confidence": round(confidence, 3),
                "ip": ip,
                "timestamp": data["ts"],
                "method": method,
                "url": url,
                "status": status,
                "ua": ua
            }

            alerts.append(alert)

with open(output_file, "w", encoding="utf-8") as out:
    json.dump(alerts, out, indent=2)

print("Analyse terminée")
