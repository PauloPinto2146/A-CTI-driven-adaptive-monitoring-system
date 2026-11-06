import json
import re

misp_event_id = 3945

with open(f"context_built_{misp_event_id}.json", "r", encoding="utf-8") as f:
    context = json.load(f)

x = input("Which sysmon event ID to analyze?\n")
entry_context = context.get(str(x))
if entry_context is None:
    raise SystemExit(f"Event {x} not found in the context.")

attack_pattern_names = entry_context.get("attack_pattern_names", [])
ioc_array = entry_context.get("ioc_array", [])

with open(f"security_analysis_{x}.md", "r", encoding="utf-8") as f:
    security_analysis = f.read()


def is_present(value: str, text: str) -> bool:
    """Case-insensitive match of the whole value (not as part of a longer token)."""
    pattern = r"(?<![\w.\-])" + re.escape(str(value)) + r"(?![\w\-])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


# ---- Attack patterns ----
print("=== Attack patterns ===")
ap_found = 0
for apn in attack_pattern_names:
    present = is_present(apn, security_analysis)
    ap_found += present
    print(f"{apn!r}: {present}")
print(f"Attack patterns covered: {ap_found}/{len(attack_pattern_names)}\n")

# ---- IoC attributes ----
print("=== IoC attributes ===")
ioc_found = 0
ioc_total = 0
for ioc in ioc_array:
    for attr_type, value in ioc.items():
        present = is_present(value, security_analysis)
        ioc_total += 1
        ioc_found += present
        print(f"[{attr_type}] {value}: {present}")
print(f"IoC attributes used: {ioc_found}/{ioc_total}")