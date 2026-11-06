import json
import sys
import os
import requests 

from dotenv import load_dotenv

# ======================================================================================

def getVulnerabilities(misp_event_data):
	context_string = ""
	cves = []

	misp_result = misp_event_data.get("response")[0]
	event = misp_result.get("Event")

	objects = event.get("Object")
	for obj in objects:
		obj_attr = obj.get("Attribute")
		for a in obj_attr:
			if a.get("type") == "vulnerability":
				cves.append(a.get("value"))

	event_attribute = event.get("Attribute")
	for attr in event_attribute:
		if attr.get("type") == "vulnerability":
			cves.append(attr.get("value"))

	return cves

# ======================================================================================

def getHash_algorithms(misp_event_data):
	"""
	Hash algorithm(s) to apply for hashing. Algorithms supported include MD5, SHA1, SHA256, IMPHASH and * (all). Default: None
	"""
	supported_sysmon_hash_algorithms = ["md5", "sha1", "sha256", "imphash"]
	hash_algorithms_res = []

	misp_result = misp_event_data.get("response")[0]
	event = misp_result.get("Event")

	# Hash algorithms are attributes that can be present in the "Attribute" object and as attributes of "Object"s

	attribute = event.get("Attribute")
	for a in attribute:
		atype = a.get("type")
		if atype in supported_sysmon_hash_algorithms:
			atype_upper = atype.upper()
			if atype_upper not in hash_algorithms_res:
				hash_algorithms_res.append(atype_upper)

	objects = event.get("Object")
	for obj in objects:
		obj_attributes = obj.get("Attribute")
		for a in obj_attributes:
			atype = a.get("type")
			if atype in supported_sysmon_hash_algorithms:
				atype_upper = atype.upper()
				if atype_upper not in hash_algorithms_res:
					hash_algorithms_res.append(atype_upper)

	return hash_algorithms_res

# ======================================================================================

def get_attack_patterns_from_MISP_event(misp_event_data):
    response = misp_event_data.get("response", [])
    event = response[0].get("Event", {}) if response else {}

    # Extrair os attack patterns na Galaxy
    galaxy = event.get("Galaxy", [])
    attack_patterns_ids = []
    attack_patterns_names = []
    for g in galaxy:
        if g.get("type") == "mitre-attack-pattern":
            galaxy_cluster = g.get("GalaxyCluster", [])
            for gx in galaxy_cluster:
                attack_pattern_id = gx.get("uuid")
                if attack_pattern_id:
                    attack_patterns_name = gx.get("meta").get("external_id")[0]
                    attack_patterns_ids.append("attack-pattern--" + attack_pattern_id)
                    attack_patterns_names.append(attack_patterns_name)
    if not attack_patterns_ids:
        print("No attack pattern found in  Galaxy of event.")
        return

    return attack_patterns_ids, attack_patterns_names

# ======================================================================================

def extract_iocs(misp_event_data):
	
	event = misp_event_data.get("response")[0].get("Event")
	ioc_dict = {}

	# IoCs grouped in objects, keyed by object name
	for o in event.get("Object") or []:
		entry = {}
		for a in o.get("Attribute") or []:
			if a.get("to_ids"):
				entry[a.get("type")] = a.get("value")
		if entry:
			ioc_dict.setdefault(o.get("name"), []).append(entry)

	# IoCs at event level, keyed by category
	for a in event.get("Attribute") or []:
		if a.get("to_ids"):
			ioc_dict.setdefault(a.get("category"), []).append({a.get("type"): a.get("value")})


	return ioc_dict

# ======================================================================================

def get_threat_description(misp_event_data):
	for a in misp_event_data.get("response")[0].get("Event").get("Attribute"):
		if a.get("comment") == "Description":
			return a.get("value")
	return ""

# ======================================================================================

def get_misp_data(misp_event_data):
	# 1. Create a dictionary that will hold all information
	res = {}

	# 2. Get the MISP data from the event
		# 2.1 Get the attack pattern data for create_attack_pattern_context function (from context_builder.py)
	
	attack_patterns_ids, attack_patterns_names = get_attack_patterns_from_MISP_event(misp_event_data)
	attack_pattern_dict = {}
	attack_pattern_dict["attack_patterns_ids"] = attack_patterns_ids
	attack_pattern_dict["attack_patterns_names"] = attack_patterns_names

		# 2.2 Get IOC info for the create_network_ioc_context function (from context_builder.py)
	ioc_dict = extract_iocs(misp_event_data)

		# 2.3 Get CVE's for the create_vulnerability_context function (from context_builder.py)
	cves = getVulnerabilities(misp_event_data)

	hash_algorithms = getHash_algorithms(misp_event_data)

		# 2.4 Get threat description that can aid th llm in context
	threat_description = get_threat_description(misp_event_data)

	# 3 Organize the information in the result dictionary
	res["attack_pattern_dict"] = attack_pattern_dict
	res["ioc_dict"] = ioc_dict
	res["cves"] = cves
	res["hash_algorithms"] = hash_algorithms
	res["threat_description"] = threat_description

	return res