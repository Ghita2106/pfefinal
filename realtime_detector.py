import time
import re
import json
import joblib
from collections import defaultdict
from datetime import datetime, timedelta
from detector.features_simple import make_features

LOG_FILE = "/var/log/apache2/access.log"
MODEL_PATH = "models/rf_apache.pkl"
OUTPUT_FILE = "outputs/alerts_realtime.jsonl"

PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

# Mémoire pour le brute force
attempts = defaultdict(list)
WINDOW = 10      # 10 secondes
THRESHOLD = 5    # 5 tentatives = alerte

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

def main():
    print("[+] Chargement du modèle Random Forest...")
    model = joblib.load(MODEL_PATH)
    print("[+] Détection temps réel démarrée...")

    with open(LOG_FILE, "r", errors="ignore") as logfile, open(OUTPUT_FILE, "a", encoding="utf-8") as outfile:
        for line in follow(logfile):
            m = PATTERN.search(line)
            if not m:
                continue

            d = m.groupdict()
            url = d["url"]
            ip = d["ip"]
            method = d["method"]
            status = int(d["status"])
            ua = d["ua"]

            # Ignorer les pages normales
            if url in ["/", "/index.php", "/logout.php", "/register.php"]:
                continue

            # -----------------------------
            # 1. Détection brute-force par règle
            # -----------------------------
            if url == "/login.php" and method == "POST":
                now = datetime.now()
                attempts[ip].append(now)

                # garder seulement les tentatives récentes
                attempts[ip] = [
                    t for t in attempts[ip]
                    if t > now - timedelta(seconds=WINDOW)
                ]

                if len(attempts[ip]) >= THRESHOLD:
                    alert = {
                        "type": "bruteforce",
                        "confidence": 1.0,
                        "ip": ip,
                        "timestamp": d["ts"],
                        "method": method,
                        "url": url,
                        "status": status,
                        "ua": ua
                    }

                    print(f"[ALERTE] BRUTEFORCE | IP={ip} | URL={url} | TENTATIVES={len(attempts[ip])}")

                    outfile.write(json.dumps(alert) + "\n")
                    outfile.flush()

                continue

            # -----------------------------
            # 2. Détection SQLi par modèle ML
            # -----------------------------
            feats = make_features(url, method, status, ua)
            pred = model.predict([feats])[0]
            proba = model.predict_proba([feats])[0]
            conf = float(max(proba))

            # éviter les faux positifs sur login GET
            if url == "/login.php" and method == "GET":
                continue

            if pred == "sqli":
                alert = {
                    "type": "sqli",
                    "confidence": round(conf, 3),
                    "ip": ip,
                    "timestamp": d["ts"],
                    "method": method,
                    "url": url,
                    "status": status,
                    "ua": ua
                }

                print(f"[ALERTE] SQLI | IP={ip} | URL={url} | CONF={alert['confidence']}")

                outfile.write(json.dumps(alert) + "\n")
                outfile.flush()

if __name__ == "__main__":
    main()
