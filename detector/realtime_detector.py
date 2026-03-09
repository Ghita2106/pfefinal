import time
import re
import json
import joblib
from collections import defaultdict
from datetime import datetime, timedelta
from detector.features_simple import make_features

LOG_FILE = "/var/log/apache2/access.log"
MODEL_FILE = "models/rf_apache.pkl"
OUTPUT_FILE = "outputs/alerts_realtime.jsonl"

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

attempts = defaultdict(list)

WINDOW = 10
THRESHOLD = 5


def follow(f):
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line


def get_path(url):
    if "?" in url:
        return url.split("?")[0]
    return url


def main():
    print("Chargement du modèle...")
    model = joblib.load(MODEL_FILE)
    print("Détection temps réel lancée")

    with open(LOG_FILE, "r", errors="ignore") as log_file, open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        for line in follow(log_file):
            m = pattern.search(line)
            if not m:
                continue

            data = m.groupdict()

            ip = data["ip"]
            url = data["url"]
            path = get_path(url)
            method = data["method"]
            status = int(data["status"])
            ua = data["ua"]

            # ignorer quelques pages normales
            if path in ["/", "/index.php", "/logout.php", "/register.php"]:
                continue

            # brute force sur login.php
            if path == "/login.php":
                if method == "POST":
                    now = datetime.now()
                    attempts[ip].append(now)

                    attempts[ip] = [
                        t for t in attempts[ip]
                        if t > now - timedelta(seconds=WINDOW)
                    ]

                    if len(attempts[ip]) >= THRESHOLD:
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

                        print(f"[ALERTE] BRUTEFORCE | IP={ip} | URL={url}")

                        out.write(json.dumps(alert) + "\n")
                        out.flush()
                continue

            # sinon on teste la SQLi avec le modèle
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

                print(f"[ALERTE] SQLI | IP={ip} | URL={url}")

                out.write(json.dumps(alert) + "\n")
                out.flush()


if __name__ == "__main__":
    main()
