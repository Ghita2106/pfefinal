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
bruteforce_alerted = {}

WINDOW = 60
THRESHOLD = 5

last_sqli_alert = {}
SQLI_ALERT_DELAY = 5
BRUTEFORCE_ALERT_DELAY = 30


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


def save_alert(out, alert):
    out.write(json.dumps(alert) + "\n")
    out.flush()


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

            # nettoyage des anciennes tentatives
            now_dt = datetime.now()
            attempts[ip] = [
                t for t in attempts[ip]
                if t > now_dt - timedelta(seconds=WINDOW)
            ]

            # si plus aucune tentative récente, on réautorise une future alerte brute force
            if len(attempts[ip]) == 0 and ip in bruteforce_alerted:
                del bruteforce_alerted[ip]

            # si l'utilisateur se déconnecte, on remet le compteur à zéro
            if path == "/logout.php":
                attempts[ip].clear()
                if ip in bruteforce_alerted:
                    del bruteforce_alerted[ip]
                continue

            # ignorer quelques pages normales
            if path in ["/", "/index.php", "/register.php", "/favicon.ico"]:
                continue

            # -------------------------
            # Détection brute force
            # -------------------------
            if path == "/login.php" and method == "POST":
                attempts[ip].append(now_dt)

                # anti-spam d'alerte brute force
                now_ts = time.time()
                already_alerted = ip in bruteforce_alerted
                recent_alert = (
                    already_alerted and
                    now_ts - bruteforce_alerted[ip] < BRUTEFORCE_ALERT_DELAY
                )

                if len(attempts[ip]) >= THRESHOLD and not recent_alert:
                    bruteforce_alerted[ip] = now_ts

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

                    print(f"[BRUTEFORCE] IP={ip} | Tentatives={len(attempts[ip])} | URL={url}")
                    save_alert(out, alert)

                continue

            # ne pas envoyer login.php au modèle ML
            if path == "/login.php":
                continue

            # -------------------------
            # Détection SQL injection
            # -------------------------
            features = make_features(url, method, status, ua)
            pred = model.predict([features])[0]
            proba = model.predict_proba([features])[0]
            confidence = float(max(proba))

            if pred == "sqli":
                now_ts = time.time()

                if ip in last_sqli_alert and now_ts - last_sqli_alert[ip] < SQLI_ALERT_DELAY:
                    continue

                last_sqli_alert[ip] = now_ts

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

                print(f"[SQLI] IP={ip} | URL={url}")
                save_alert(out, alert)


if __name__ == "__main__":
    main()
