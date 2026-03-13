import time
import re
import json
import joblib
from collections import defaultdict
from datetime import datetime, timedelta
from detector.features_simple import make_features

log_file = "/var/log/apache2/access.log"
model_file = "models/rf_apache.pkl"
output_file = "outputs/alerts_realtime.jsonl"

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

print("Chargement du modèle")
model = joblib.load(model_file)

attempts = defaultdict(list)

WINDOW = 60
THRESHOLD = 5

# mots suspects pour SQL injection
sql_words = ["union", "select", "sleep", "or 1=1", "and 1=1", "%27", "'"]


def follow(file):
    file.seek(0, 2)

    while True:
        line = file.readline()

        if not line:
            time.sleep(0.2)
            continue

        yield line


def get_path(url):
    if "?" in url:
        return url.split("?")[0]

    return url


with open(log_file, "r", errors="ignore") as f, open(output_file, "a") as out:

    print("Détection temps réel lancée")

    for line in follow(f):

        m = pattern.search(line)

        if m is None:
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

        # détection brute force
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

                    print("[BRUTEFORCE]", ip, url)

                    out.write(json.dumps(alert) + "\n")
                    out.flush()

            continue

        # petite détection simple SQLi par mots
        low_url = url.lower()

        for word in sql_words:
            if word in low_url:

                alert = {
                    "type": "sqli",
                    "confidence": 1.0,
                    "ip": ip,
                    "timestamp": data["ts"],
                    "method": method,
                    "url": url,
                    "status": status,
                    "ua": ua
                }

                print("[SQLI]", ip, url)

                out.write(json.dumps(alert) + "\n")
                out.flush()

                break

        # sinon on teste SQL injection avec le modèle
        features = make_features(url, method, status, ua)

        pred = model.predict([features])[0]

        if pred == "sqli":

            alert = {
                "type": "sqli",
                "confidence": 0.8,
                "ip": ip,
                "timestamp": data["ts"],
                "method": method,
                "url": url,
                "status": status,
                "ua": ua
            }

            print("[SQLI]", ip, url)

            out.write(json.dumps(alert) + "\n")
            out.flush()
