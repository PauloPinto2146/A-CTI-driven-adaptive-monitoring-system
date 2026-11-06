import json
import os
import sys
import requests
import time

from dotenv import load_dotenv
from step2_1_data_enricher import create_vulnerability_context, create_attack_pattern_context

# ======================================================================================

def load_object(folder, stix_id):
    path = os.path.join(folder, f"{stix_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for obj in data.get("objects", []):
        if obj.get("id") == stix_id:
            return obj
    return None

# ======================================================================================

def attackPattern_to_analytics(attack_pattern_ids, attack_pattern_names, json_dump = False): 

    total_analytics = {}

    load_dotenv()
    PASTA_ATTACK = os.getenv("ATTACK_DIR")
    PASTA_REL = os.getenv("REL_DIR")
    PASTA_ANALYTIC = os.getenv("ANALYTIC_DIR")
    PASTA_DETECTION_STRATEGY = os.getenv("DETECTION_STRATEGY_DIR")
    PASTA_DATA_COMPONENT = os.getenv("DATA_COMPONENT_DIR")
    i = 1
    print("Going to extract attack pattern info of:")
    for api in attack_pattern_ids:
        print(api)

    for attack_pattern_id in attack_pattern_ids:

        print("==============================")
        print(f"Analysing {attack_pattern_id} ({i}/{len(attack_pattern_ids)})")
        print("==============================")
        i+=1
        found = False
        # Find attack pattern file 
        if load_object(PASTA_ATTACK, attack_pattern_id) is None:
            print(f"Attack pattern {attack_pattern_id} not found, skipping")
            continue

        # Find "detects" relationships with the attack pattern 
        detections_strategies = [] 
        print(f"Going to find \"detects\" relationships. Analysing {len(os.listdir(PASTA_REL))} files")
        for ficheiro in os.listdir(PASTA_REL): 
            if ficheiro.endswith(".json"): 
                caminho_completo = os.path.join(PASTA_REL, ficheiro) 
                try: 
                    with open(caminho_completo, "r", encoding="utf-8") as f: 
                        data = json.load(f) 
                        objetos = data.get("objects", []) 
                        for obj in objetos: 
                            if obj.get("type") == "relationship": 
                                rel_type = obj.get("relationship_type", "") 
                                source = obj.get("source_ref") 
                                target = obj.get("target_ref") 
                                # rel_id = obj.get("id") 
                                if rel_type == "detects": 
                                    if target == attack_pattern_id: 
                                        print("Found relationship: ", obj.get("id"))
                                        detections_strategies.append(source)
                except Exception as e: 
                    print(f"Erro ao processar {ficheiro}: {e}") 
        analytics = []
        print(f"Going to find detection strategies. Analysing {len(os.listdir(PASTA_DETECTION_STRATEGY))} files")
        for ficheiro in os.listdir(PASTA_DETECTION_STRATEGY): 
            if ficheiro.endswith(".json"): 
                caminho_completo = os.path.join(PASTA_DETECTION_STRATEGY, ficheiro) 
                try: 
                    with open(caminho_completo, "r", encoding="utf-8") as f: 
                        data = json.load(f) 
                        objetos = data.get("objects", []) 
                        for obj in objetos: 
                            if obj.get("type") == "x-mitre-detection-strategy":
                                if obj.get("id") in detections_strategies:
                                    analytics_from_ds = obj.get("x_mitre_analytic_refs", [])
                                    for analytic_ref in analytics_from_ds:
                                        if analytic_ref not in detections_strategies:
                                            if analytic_ref not in analytics:
                                                analytics.append(analytic_ref)
                except Exception as e: 
                    print(f"Erro ao processar {ficheiro}: {e}") 

        print(f"Going to find analytics. Analysing {len(os.listdir(PASTA_ANALYTIC))} files")
        analysed_analytics = []
        for ficheiro in os.listdir(PASTA_ANALYTIC): 
            if ficheiro.endswith(".json"): 
                caminho_completo = os.path.join(PASTA_ANALYTIC, ficheiro) 
                try: 
                    with open(caminho_completo, "r", encoding="utf-8") as f: 
                        data = json.load(f) 
                        objetos = data.get("objects", []) 
                        for obj in objetos: 
                            if obj.get("type") == "x-mitre-analytic":
                                obj_id = obj.get("id")
                                if obj_id in analytics and obj_id not in analysed_analytics:
                                    log_sources = obj.get("x_mitre_log_source_references", [])
                                    for log_source in log_sources:
                                        if log_source.get("x_mitre_data_component_ref") not in total_analytics:
                                            if "Sysmon" in log_source.get("name"):
                                                total_analytics[log_source.get("x_mitre_data_component_ref")] = {
                                                    "name": log_source.get("name"),
                                                    "channel": log_source.get("channel"),
                                                    "id": log_source.get("x_mitre_data_component_ref")
                                                }
                                                print("added: ", log_source.get("channel"))
                                    analysed_analytics.append(obj.get("id"))
                except Exception as e: 
                    print(f"Erro ao processar {ficheiro}: {e}") 
    
    # Take the "name" for each data component
    print(f"Ended data search. Organizing it now.")
    for log in total_analytics:
        data_component_id = total_analytics[log]['id']
        for ficheiro in os.listdir(PASTA_DATA_COMPONENT): 
            if ficheiro.endswith(".json"): 
                caminho_completo = os.path.join(PASTA_DATA_COMPONENT, ficheiro) 
                try: 
                    with open(caminho_completo, "r", encoding="utf-8") as f: 
                        data = json.load(f) 
                        objetos = data.get("objects", []) 
                        for obj in objetos: 
                            if obj.get("type") == "x-mitre-data-component":
                                if obj.get("id") == data_component_id:
                                    total_analytics[log]['data-component-name'] = obj.get("name")
                except Exception as e: 
                    print(f"Erro ao processar {ficheiro}: {e}")

    # Order total_analytics by name
    total_analytics = dict(sorted(total_analytics.items(), key=lambda item: item[1]['name']))
        

    data = [
                {
                    "name": log['name'],
                    "channel": log['channel'],
                    "id": log['id'],
                    "data-component-name": log['data-component-name']
                }
                for log in total_analytics.values()
            ]

    if json_dump:
        with open(f"analytics_output_{attack_pattern_names}.json", "w", encoding="utf-8") as f:
            if not total_analytics:
                json.dump([], f, indent=4)
            else:
                json.dump(data, f, indent=4)
    print(data)
    return data


# ======================================================================================

def get_SysmonIDs(attack_patterns_ids, attack_patterns_names):
    res = []
    
    analytic_data = attackPattern_to_analytics(attack_patterns_ids, attack_patterns_names)
    
    for a in analytic_data:
        
        if a.get("name") == "WinEventLog:Sysmon":
            eventCodes_string = a.get("channel")[10:]
            eventCodes = eventCodes_string.split(",")
            eventCodes_int = []
            for e in sorted(eventCodes):
                eventCodes_int.append(int(e))
            res.extend(eventCodes_int)
    return list(set(sorted(res)))
# ========================================================================================================================================================================================================================================================================


HASH_ATTRIBUTES = {
    "md5", "sha1",  "sha256", "imphash"
}

FILE_ATTRIBUTES = {
    "filename", "filename-pattern", "pattern-in-file"
    "filename|md5", "filename|sha1", "filename|sha256", "filename|imphash"
}


NETWORK_ATTRIBUTES = {
    "ip-src", "ip-dst", "port",
    "domain", "hostname", "url",
}

REGISTRY_ATTRIBUTES = {
    "regkey", "regkey|value",
}

PIPE_ATTRIBUTES = {
    "named pipe",
}

MISP_SYSMON_MAPPING = {
    1: HASH_ATTRIBUTES | FILE_ATTRIBUTES,
    2: FILE_ATTRIBUTES,
    3: HASH_ATTRIBUTES | FILE_ATTRIBUTES | NETWORK_ATTRIBUTES,
    # 4 n/a
    5: FILE_ATTRIBUTES,
    6: HASH_ATTRIBUTES | FILE_ATTRIBUTES,
    7: HASH_ATTRIBUTES | FILE_ATTRIBUTES,
    8: FILE_ATTRIBUTES,
    9: FILE_ATTRIBUTES,
    10: FILE_ATTRIBUTES,
    11: FILE_ATTRIBUTES,
    12: FILE_ATTRIBUTES | REGISTRY_ATTRIBUTES,
    13: FILE_ATTRIBUTES | REGISTRY_ATTRIBUTES,
    14: FILE_ATTRIBUTES | REGISTRY_ATTRIBUTES,
    15: HASH_ATTRIBUTES | FILE_ATTRIBUTES,
    # 16 sysmon configuration update log
    17: FILE_ATTRIBUTES | PIPE_ATTRIBUTES,
    18: FILE_ATTRIBUTES | PIPE_ATTRIBUTES,
    #19 no correspondence
    #20 no correspondence
    #21 no correspondence
    22: FILE_ATTRIBUTES | NETWORK_ATTRIBUTES,
    23: HASH_ATTRIBUTES | FILE_ATTRIBUTES,
    24: HASH_ATTRIBUTES | FILE_ATTRIBUTES,
    25: FILE_ATTRIBUTES,
    26: HASH_ATTRIBUTES | FILE_ATTRIBUTES,
}

HASH_PREFERENCE = ["SHA256", "SHA1", "MD5", "IMPHASH"]

def choose_hash_algorithm(hash_algorithms):
    # Pick a single hash algorithm from those the monitoring tool supports.
    supported = {h.upper() for h in hash_algorithms}
    for algorithm in HASH_PREFERENCE:
        if algorithm in supported:
            return algorithm
    return None  # no usable algorithm: hashes will be dropped


def select_iocs(ioc_dict, sysmon_id, chosen_hash_algorithm):
    relevant_attributes = MISP_SYSMON_MAPPING.get(sysmon_id, set())
    chosen = chosen_hash_algorithm.lower() if chosen_hash_algorithm else None
    res = []

    for ioc_type, iocs in ioc_dict.items():
        for ioc in iocs:
            selected_ioc = {
                attribute: value
                for attribute, value in ioc.items()
                if attribute in relevant_attributes
                and (attribute not in HASH_ATTRIBUTES or attribute == chosen)
            }
            if selected_ioc:
                res.append(selected_ioc)

    return res
# ========================================================================================================================================================================================================================================================================

def build_context_dict(ioc_extraction):
    # Build ioc and cve context that depend on external info not present in the report
    vulnerability_context, cves = create_vulnerability_context(ioc_extraction["cves"])
    print("vulnerability_context = ", vulnerability_context)
    print("cves = ", cves)

    attack_pattern_dict = ioc_extraction["attack_pattern_dict"]
    sysmon_ids = get_SysmonIDs(attack_pattern_dict["attack_patterns_ids"], attack_pattern_dict["attack_patterns_names"])
    context_dict = {}

    for sysmon_id in sysmon_ids:
        print(" ====================================================")
        print(f"Getting context data for sysmon ID {sysmon_id}...\n")

        	# 2.2 Build attack pattern context (this one depends which sysmon event we are talking about)
        ap_names, ap_context = create_attack_pattern_context(ioc_extraction["attack_pattern_dict"]["attack_patterns_ids"], sysmon_id, "Windows")

        hash_algorithm_to_consider = choose_hash_algorithm(ioc_extraction["hash_algorithms"])

        	# 2.3 Build the dictionary
        context_dict[sysmon_id] = {}
        context_dict[sysmon_id]["attack_pattern_context"] = ap_context
        context_dict[sysmon_id]["attack_pattern_names"] = ap_names
        context_dict[sysmon_id]["ioc_array"] = select_iocs(ioc_extraction["ioc_dict"], sysmon_id, hash_algorithm_to_consider)
        context_dict[sysmon_id]["vul_context"] = vulnerability_context
        context_dict[sysmon_id]["cves"] = cves
        context_dict[sysmon_id]["threat_description"] = ioc_extraction["threat_description"]
        print(" ====================================================")

    context_dict["sysmon_hash_algorithms_to_consider"] = hash_algorithm_to_consider

    return context_dict

# ========================================================================================================================================================================================================================================================================
