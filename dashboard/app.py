from flask import Flask, render_template, jsonify
import json
import os
from collections import Counter

app = Flask(__name__)

RF_FILE = "outputs/alerts_rf.json"
REALTIME_FILE = "outputs/alerts_realtime.jsonl"


def load_offline_alerts():
    if not os.path.exists(RF_FILE):
        return []

    try:
        with open(RF_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass

    return []


def load_realtime_alerts():
    alerts = []

    if not os.path.exists(REALTIME_FILE):
        return alerts

    try:
        with open(REALTIME_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass

    return alerts


def load_all_alerts():
    offline = load_offline_alerts()
    realtime = load_realtime_alerts()
    all_alerts = offline + realtime

    unique = []
    seen = set()

    for alert in all_alerts:
        key = (
            alert.get("type"),
            alert.get("ip"),
            alert.get("timestamp"),
            alert.get("url"),
            alert.get("method")
        )
        if key not in seen:
            seen.add(key)
            unique.append(alert)

    unique.reverse()
    return unique


def build_stats(alerts):
    type_counter = Counter()
    ip_counter = Counter()

    for alert in alerts:
        alert_type = alert.get("type", "unknown")
        ip = alert.get("ip", "unknown")
        type_counter[alert_type] += 1
        ip_counter[ip] += 1

    total = len(alerts)
    sqli = type_counter.get("sqli", 0)
    bruteforce = type_counter.get("bruteforce", 0)
    unique_ips = len(ip_counter)

    sqli_percent = round((sqli / total) * 100, 1) if total else 0
    bruteforce_percent = round((bruteforce / total) * 100, 1) if total else 0

    if total == 0:
        risk_label = "Aucun risque"
        risk_score = 0
    elif total <= 3:
        risk_label = "Faible"
        risk_score = 25
    elif total <= 7:
        risk_label = "Moyen"
        risk_score = 60
    else:
        risk_label = "Élevé"
        risk_score = 90

    return {
        "total": total,
        "sqli": sqli,
        "bruteforce": bruteforce,
        "unique_ips": unique_ips,
        "sqli_percent": sqli_percent,
        "bruteforce_percent": bruteforce_percent,
        "risk_label": risk_label,
        "risk_score": risk_score,
        "top_ips": ip_counter.most_common(5),
        "by_type": dict(type_counter)
    }


@app.route("/")
def index():
    alerts = load_all_alerts()
    stats = build_stats(alerts)
    return render_template("index.html", alerts=alerts, stats=stats)


@app.route("/import-logs")
def import_logs():
    return render_template("upload_logs.html")


@app.route("/api/alerts")
def api_alerts():
    alerts = load_all_alerts()
    stats = build_stats(alerts)
    return jsonify({
        "alerts": alerts,
        "stats": stats
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
