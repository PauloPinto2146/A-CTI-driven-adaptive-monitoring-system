# https://github.com/MISP/PyMISP/blob/main/docs/tutorial/Search-FullOverview.ipynb
from pymisp import PyMISP
import json

from datetime import datetime
import time
import urllib3
import os

misp_url = os.getenv("MISP_URL")
misp_key = os.getenv("API_KEY")
misp_verifycert = False

if misp_verifycert == False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Desabilitar avisos de certificado SSL

misp = PyMISP(misp_url, misp_key, misp_verifycert)

fetched_objects = []

def count_report_objects(objects):
    type_count = 0
    orgs = []
    for obj in objects:
        if obj.get("type") == "report":
            type_count += 1
            orgs.append(obj.get("name", "Unknown"))
    print(f"Number of 'report' objects fetched: {type_count}")
    print(f"Organizations that created 'report' objects:")
    for org in set(orgs):
        print(f"- {org}")


time_interval = 2 # 2 minutos
publish_timestamp = f"{time_interval}m" # 2 minutos atrás

while True:
    r = misp.search(
            controller="events",
            timestamp = publish_timestamp,
            return_format="stix2",
            limit = 100,
        )
    
    objects = r.get("objects", [])
    
    if objects:
        fetched_objects.extend(objects)
        print(f"\nFetched {len(fetched_objects)} reports.")
        count_report_objects(objects)
        print(f"Last fetch time: {datetime.now()}\n")
        with open("periodic_fetched_events.json", "w") as f:
            json.dump({"type": "bundle", "objects": fetched_objects}, f)
    else:
        print(f"No new reports found ({datetime.now()}).")

    # Esperar o intervalo de tempo antes de buscar novamente
    time.sleep(time_interval * 60)


"""

Feeds que uso:

CIRCL OSINT Feed
The Botvrij.eu Data
DigitalSide Threat-Intel OSINT Feed
Threatfox
MalwareBazaar
URLhaus
Infoblox-Threat-Intelligence
Rösti - Repackaged Öpen Source Threat Intelligence
NOCACTI: Intrusion Feed
NOCACTI: Adversary Infrastructure Feed

--------------------------------------------------

No new reports found (2026-03-05 10:41:38.705533).
No new reports found (2026-03-05 10:43:40.030398).
No new reports found (2026-03-05 10:45:42.431460).
No new reports found (2026-03-05 10:47:43.149200).

Fetched 1744 reports.
Number of 'report' objects fetched: 5
Organizations that created 'report' objects:
- SQL_Infiltration-Din01-3_2026
- SSH_Abuse_Failures-mlb01-3_2026
- FortiGateLoginSpraying-BrightRiver01-3_2026
- FortiGateExploitationAndScanning-BrightRiver01-3_2026
- SSH_Infiltration-mlb01-3_2026
Last fetch time: 2026-03-05 10:49:51.837979

No new reports found (2026-03-05 10:51:55.550036).
No new reports found (2026-03-05 10:54:00.499215).
No new reports found (2026-03-05 10:56:01.127372).
No new reports found (2026-03-05 10:58:02.520759).
No new reports found (2026-03-05 11:00:04.140267).
No new reports found (2026-03-05 11:02:04.185544).
No new reports found (2026-03-05 11:04:06.328155).
No new reports found (2026-03-05 11:06:09.193492).
No new reports found (2026-03-05 11:08:13.743039).
No new reports found (2026-03-05 11:10:15.076504).
No new reports found (2026-03-05 11:12:16.502677).
No new reports found (2026-03-05 11:14:18.904101).
No new reports found (2026-03-05 11:16:20.743250).
No new reports found (2026-03-05 11:18:22.487822).
No new reports found (2026-03-05 11:20:24.116086).
No new reports found (2026-03-05 11:22:25.489542).
No new reports found (2026-03-05 11:24:27.058775).
No new reports found (2026-03-05 11:26:28.472844).
No new reports found (2026-03-05 11:28:30.077920).
No new reports found (2026-03-05 11:30:31.310179).
No new reports found (2026-03-05 11:32:32.764255).
No new reports found (2026-03-05 11:34:34.521229).
No new reports found (2026-03-05 11:36:36.221944).
No new reports found (2026-03-05 11:38:37.873410).
No new reports found (2026-03-05 11:40:40.004774).
No new reports found (2026-03-05 11:42:44.037928).
No new reports found (2026-03-05 11:44:45.609003).
No new reports found (2026-03-05 11:46:47.267313).
No new reports found (2026-03-05 11:48:50.027906).
No new reports found (2026-03-05 11:50:52.726020).
No new reports found (2026-03-05 11:52:56.073656).
No new reports found (2026-03-05 11:54:58.845277).
No new reports found (2026-03-05 11:57:02.341655).
No new reports found (2026-03-05 11:59:06.990908).
No new reports found (2026-03-05 12:01:11.138353).
No new reports found (2026-03-05 12:03:14.442686).
No new reports found (2026-03-05 12:05:19.129516).
No new reports found (2026-03-05 12:07:22.449961).
No new reports found (2026-03-05 12:09:25.982762).
No new reports found (2026-03-05 12:11:29.556751).
No new reports found (2026-03-05 12:13:31.691572).

"""