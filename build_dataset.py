import re
import csv

PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

def parse_line(line):
    m = PATTERN.search(line)
    if not m:
        return None
    d = m.groupdict()
    return {
        "url": d["url"],
        "method": d["method"],
        "status": d["status"],
        "ua": d["ua"]
    }

def process_file(infile, label, writer):
    with open(infile, "r", errors="ignore") as f:
        for line in f:
            data = parse_line(line)
            if data:
                writer.writerow([data["url"], data["method"], data["status"], data["ua"], label])

def main():
    with open("data/training.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["url", "method", "status", "ua", "label"])

        process_file("data/normal.log", "normal", writer)
        process_file("data/bruteforce.log", "bruteforce", writer)
        process_file("data/sqli.log", "sqli", writer)

    print("Dataset créé : data/training.csv")

if __name__ == "__main__":
    main()
