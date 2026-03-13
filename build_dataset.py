import re
import csv

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

def read_file(file,label,writer):

    with open(file,"r",errors="ignore") as f:

        for line in f:

            m = pattern.search(line)

            if m is None:
                continue

            d = m.groupdict()

            writer.writerow([
                d["url"],
                d["method"],
                d["status"],
                d["ua"],
                label
            ])


with open("data/training.csv","w",newline="") as csvfile:

    writer = csv.writer(csvfile)

    writer.writerow(["url","method","status","ua","label"])

    read_file("data/normal.log","normal",writer)
    read_file("data/bruteforce.log","bruteforce",writer)
    read_file("data/sqli.log","sqli",writer)

print("Dataset créé : data/training.csv")
