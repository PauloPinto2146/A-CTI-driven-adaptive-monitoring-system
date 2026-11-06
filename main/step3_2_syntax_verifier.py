import os
import subprocess
from pathlib import Path
from dotenv import load_dotenv


def verify(xml_str, event_id):
	load_dotenv()
	path = os.getenv("SYSMON_CONFIG_FILE_PATH")
	Path(path).write_text(xml_str, encoding="utf-8")

	result = subprocess.run(
		[os.getenv("SYSMON_EXE"), "-c", path],
		capture_output=True,
	)

	# Sysmon costuma emitir UTF-16-LE; fallback para utf-8 se não for
	raw = result.stdout or b""
	try:
		output = raw.decode("utf-16-le")
		if "Sysmon" not in output and "onfiguration" not in output:
			output = raw.decode("utf-8", errors="replace")
	except UnicodeDecodeError:
		output = raw.decode("utf-8", errors="replace")

	valid = "Configuration file validated." in output

	if not valid:
		print(f"The sysmon configuration event {event_id} is invalid.")
	else:
		print(f"The sysmon configuration event {event_id} is valid.")
		
	return valid