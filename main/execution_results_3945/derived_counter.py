from pathlib import Path

sysmon_events = [1, 3, 6, 7, 10, 11, 13, 14, 22, 23]
LABEL = "[DERIVED]"
CVE = "CVE-2023-27350"

# hífens
DASHES = "\u2010\u2011\u2012\u2013\u2014\u2212"


def normalize(text: str) -> str:
    for d in DASHES:
        text = text.replace(d, "-")
    return text


derived = {}  
cves = {}     

for i in range(1, 12):
    derived[i], cves[i] = {}, {}
    for s in sysmon_events:
        path = Path(f"retry_test_{i}/security_analysis_{s}.md")
        if not path.exists():
            print(f"Missing: {path}")
            continue
        content = normalize(path.read_text(encoding="utf-8"))
        derived[i][s] = content.count(LABEL)
        cves[i][s] = content.upper().count(CVE)


def print_table(title, data):
    print(f"\n{title}")
    print("run | " + " ".join(f"{s:>3}" for s in sysmon_events) + " | total")
    for i in range(1, 12):
        row = [data[i].get(s, 0) for s in sysmon_events]
        print(f"{i:>3} | " + " ".join(f"{c:>3}" for c in row) + f" | {sum(row):>5}")


print_table("[DERIVED] por run e evento", derived)
print_table(f"{CVE}: nº de menções por run e evento", cves)

print(f"\nRuns (de 10) em que cada evento menciona {CVE}:")
for s in sysmon_events:
    n = sum(1 for i in range(1, 12) if cves[i].get(s, 0) > 0)
    print(f"  evento {s:>2}: {n}/10")