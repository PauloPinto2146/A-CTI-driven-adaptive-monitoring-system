import re

event_id = input("Which sysmon event ID to analyze?\n")

with open(f"security_analysis_{event_id}.md", "r", encoding="utf-8") as f:
    security_analysis = f.read()


def is_present(value: str, text: str) -> bool:
    """Case-insensitive match of the whole value (not inside a longer token)."""
    pattern = r"(?<![\w.\-])" + re.escape(value.strip()) + r"(?![\w\-])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


print("Type a value to check (empty line to quit).")
while True:
    value = input("Which value to check:\n").strip()
    if not value:
        break
    print(f"{value!r} present in security analysis {event_id}: {is_present(value, security_analysis)}\n")