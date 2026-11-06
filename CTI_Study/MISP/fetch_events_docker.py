# https://github.com/MISP/PyMISP/blob/main/docs/tutorial/Search-FullOverview.ipynb
from pymisp import PyMISP
import json

misp_url = 'https://127.0.0.1'
misp_key = "wEHyToYFmjSrnpm6nOw3sHr07hW3Hb6zNVNODpKv"
misp_verifycert = False

misp = PyMISP(misp_url, misp_key, misp_verifycert)

all_objects = []

print(f"Fetching events modified between 31d and 32d ago...")
r = misp.search(
    controller="events",
    publish_timestamp=["31d","32d"],
    return_format="stix2",
    limit = 1000
)
all_objects = r.get("objects", [])

print(f"Total objects fetched (without filtering): {len(all_objects)}")

# Retirar objetos duplicados (baseado no id)
unique_objects = {obj['id']: obj for obj in all_objects}
all_objects = list(unique_objects.values())

with open("stix2_docker_data.json", "w") as f:
    json.dump({"type": "bundle", "objects": all_objects}, f)

print(f"Total objects non-duplicate: {len(all_objects)}")
