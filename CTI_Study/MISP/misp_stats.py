import ijson
import os
from pymisp import PyMISP
import json

misp_url = os.getenv("MISP_URL")
misp_key = os.getenv("API_KEY")
misp_verifycert = False

misp = PyMISP(misp_url, misp_key, misp_verifycert)

report_directory = os.fsencode("MISPvsSTIX")

def count_events():
    stix_counter = 0
    misp_counter = 0
    for file in os.listdir(report_directory):
        filename = os.fsdecode(file)
        if filename.endswith("STIX.json"):
            stix_counter += 1
        elif filename.endswith("MISP.json"):
            misp_counter += 1
    print("STIX counter: ", stix_counter)
    print("MISP counter: ", misp_counter)

def count_relationships():
    not_repeat_set = set()
    file_dict = {}

    report_dir = os.fsdecode(report_directory)

    for filename in os.listdir(report_dir):
        if filename.endswith("STIX.json"):
            file_dict[f"{filename}-STIX_rel"] = 0
            file_dict[f"{filename}-STIX_obj"] = 0
            file_dict[f"{filename}-STIX_sighting"] = 0
        if filename.endswith("MISP.json"):
            file_dict[f"{filename}-MISP_ObjectReference"] = 0
            file_dict[f"{filename}-MISP_GalaxyClusterRelation"] = 0
            file_dict[f"{filename}-MISP_TargetingClusterRelation"] = 0

    for filename in os.listdir(report_dir):
        filepath = os.path.join(report_dir, filename)
        with open(filepath, "rb") as f:
            if filename.endswith("STIX.json"):
                objects = ijson.items(f, "objects.item")
                for obj in objects:
                    stix_file_rel_count = 0
                    if obj["type"] == "relationship":
                        stix_file_rel_count += 1
                        file_dict[f"{filename}-STIX_rel"] += 1
                    if obj.get("type") != "report" and obj.get("object_refs"):
                        count = len(obj["object_refs"])
                        file_dict[f"{filename}-STIX_obj"] += count
                    if obj["type"] == "sighting":
                        stix_file_rel_count += 1
                        file_dict[f"{filename}-STIX_sighting"] += 1
            elif filename.endswith("MISP.json"):
                with open(filepath, "rb") as f:
                    objects = ijson.items(f, "response.item.Event.Object.item")
                    for obj in objects:
                        objeto = obj.get("ObjectReference", [])
                        for obj2 in objeto:
                            if obj2["relationship_type"] is not None:
                                id = obj2["id"]
                                rel_type = obj2["relationship_type"]
                                ref_id = obj2["referenced_id"]
                                key = (id, rel_type, ref_id)
                                if key not in not_repeat_set:
                                    file_dict[f"{filename}-MISP_ObjectReference"] += 1
                                    not_repeat_set.add(key)
                with open(filepath, "rb") as f:
                    galaxies = ijson.items(f, "response.item.Event.Galaxy.item")
                    for galaxy in galaxies:
                        for gc in galaxy.get("GalaxyCluster", []):
                            for gcr in gc.get("GalaxyClusterRelation", []):
                                gcr_id = str(gcr.get("galaxy_cluster_id", ""))
                                gcr_rel_type = str(gcr.get("referenced_galaxy_cluster_type", ""))
                                gcr_ref_id = str(gcr.get("referenced_galaxy_cluster_id", ""))
                                key = (gcr_id, gcr_rel_type, gcr_ref_id)
                                if key not in not_repeat_set:
                                    file_dict[f"{filename}-MISP_GalaxyClusterRelation"] += 1
                                    not_repeat_set.add(key)
                            for tcr in gc.get("TargetingClusterRelation", []):
                                if isinstance(tcr, dict):
                                    items = [tcr]
                                elif isinstance(tcr, list):
                                    items = tcr
                                else:
                                    continue

                                for item in items:
                                    tcr_id = str(item.get("galaxy_cluster_id", ""))
                                    tcr_rel_type = str(item.get("referenced_galaxy_cluster_type", ""))
                                    tcr_rgc_ref_id = str(item.get("referenced_galaxy_cluster_id", ""))
                                    key = (tcr_id, tcr_rel_type, tcr_rgc_ref_id)
                                    if key not in not_repeat_set:
                                        file_dict[f"{filename}-MISP_TargetingClusterRelation"] += 1
                                        not_repeat_set.add(key)
    c1 = 0
    print("-----------------------------")
    print("STIX")
    print("-----------------------------")
    for file in file_dict:
        if file.endswith("STIX_rel") or file.endswith("STIX_obj") or file.endswith("STIX_sighting"):
            print(f"{file} : {file_dict[file]}")
            c1 += file_dict[file]
    print(f"Total: {c1}\n\n")

    c2 = 0
    c3 = 0
    c4 = 0
    print("-----------------------------")
    print("MISP")
    print("-----------------------------")
    for file in file_dict:
        if file.endswith("MISP_ObjectReference"):
            print(f"{file} : {file_dict[file]}")
            c2 += file_dict[file]
        if file.endswith("MISP_GalaxyClusterRelation"):
            print(f"{file} : {file_dict[file]}")
            c3 += file_dict[file]
        if file.endswith("MISP_TargetingClusterRelation"):
            print(f"{file} : {file_dict[file]}")
            c4 += file_dict[file]
    print(f"    MISP_ObjectReference total: {c2}")
    print(f"    MISP_GalaxyClusterRelation total: {c3}")
    print(f"    MISP_TargetingClusterRelation total: {c4}")
    print(f"Total: {c2+c3+c4}\n\n")


def count_external_references():
    total_count = 0
    report_dir = os.fsdecode(report_directory)

    for filename in os.listdir(report_dir):
        filepath = os.path.join(report_dir, filename)

        count_ex_refs = 0
        with open(filepath, "rb") as f:
            if filename.endswith("STIX.json"):
                objects = ijson.items(f, "objects.item")
                for obj in objects:
                    if obj.get("external_references"):
                        ex_ref_obj = obj.get("external_references")
                        for ex_ref in ex_ref_obj:
                            if ex_ref.get("url"):
                                count_ex_refs += 1
                                total_count +=1
                print(f"{filename} has {count_ex_refs} external references with url values")
    print("Total: ", total_count)

def get_object_by_ID():
    object_id = input("Qual o ID do objeto a procurar?: ")
    x = misp.get_object(object_id)
    print(json.dumps(x, indent=4))

input_string = """
Qual a opção que quer escolher?\n
    1. Contar quantos eventos tem \n
    2. Contar relações em relatório \n
    3. Contar referências externas (STIX) \n
    4. Ver objeto por ID \n
"""

x = input(input_string)

if x == "1":
    count_events()
elif x == "2":
    count_relationships()
elif x == "3":
    count_external_references()
elif x == "4":
    get_object_by_ID()


"""
CVSS4

AV (Attack Vector)
    - Network (N)
    - Adjacent (A)
    - Local (L)
    - Physical (P)
AC (Attack complecity)
    - Low (L)
    - High (H)
AT (Attack requirements)
    - Low (L)
    - High (H)
PR (Previleges Required)
    - None (N)
    - Low (L)
    - High (H)
UI (User Interaction)
    - None (N)
    - Passive (P)
    - Active (A)
VC (Vulnerable System Confidentiality)
VI (Vulnerable System Integrity)
VA (Vulnerable System Availability)
SC (Subsequent System Confidentiality)
SI (Subsequent System Availability)
SA (Subsequent System Confidentiality)
    - None (N)
    - Low (L)
    - High (H)
E (Exploit Maturity)
    - Not Defined (X)
    - Attacked (A) (Está a ser explorado ativamente com evidência real)
    - PoC (P) (Proof-of-Concept, existe código exposto do exploit)
    - Unreported (U) (Pode existir mas não foi observado)

fLzO5xbQs1Gp23aF4RfPzJ1Rx9FkB5ej0slNhXvE
    
"""
