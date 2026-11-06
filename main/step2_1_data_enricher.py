import json
import os
import requests
import time

from dotenv import load_dotenv
from mitreattack.stix20 import MitreAttackData

# ================================================================================
# ============================VULNERABILITY CONTEXT===============================
# ================================================================================

# Function to retry if the API's do not work at the first attempt  
def get_json_with_retry(url, params=None, retries=10, delay=2):
    for attempt in range(1, retries + 1):
        try:
            print(f"Attempt no {attempt}")
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"[{attempt}/{retries}] Error fetching {url}: {e}")
            if attempt == retries:
                raise

            time.sleep(delay)

# ================================================================================

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def pick_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            primary = [e for e in entries if e.get("type") == "Primary"]
            return (primary or entries)[0].get("cvssData", {})
    return {}

def create_vulnerability_context(cves):
    if not cves:
        return "", cves

    context = "Known vulnerabilities:\n"
    for c in cves:
        try:
            data = get_json_with_retry(NVD_URL, params={"cveId": c})
            vulns = data.get("vulnerabilities", [])
            nvd = vulns[0].get("cve", {}) if vulns else {}
        except Exception as e:
            print(f"Could not retrieve NVD data for {c}: {e}")
            nvd = {}

        if not nvd:
            context += f"\n- {c}\n"
            continue

        description = next(
            (d["value"] for d in nvd.get("descriptions", []) if d.get("lang") == "en"),
            "No description available.",
        )
        cvss = pick_cvss(nvd.get("metrics", {}))

        context += f"\n- {c}: {description}\n"
        if cvss:
            g = lambda k: cvss.get(k, "N/A")
            context += (
                f"  Attack vector: {g('attackVector')}; attack complexity: {g('attackComplexity')}; "
                f"privileges required: {g('privilegesRequired')}; user interaction: {g('userInteraction')}\n"
                f"  Impact: {g('confidentialityImpact')} on confidentiality, "
                f"{g('integrityImpact')} on integrity, {g('availabilityImpact')} on availability\n"
            )
            """
            Attack vector: NETWORK; attack complexity: LOW; 
            privileges required: NONE; user interaction: NONE\n  
            Impact: HIGH on confidentiality, 
            HIGH on integrity, HIGH on availability\n",
            """

    return context.replace("```", ""), cves



















# ================================================================================
# ==========================ATTACK PATTERN CONTEXT================================
# ================================================================================

def sysmon_id_detector(refs, sysmon_event_id):
    for x in refs:
        if (x.get("name") or "") == "WinEventLog:Sysmon":
            codes = (x.get("channel") or "").removeprefix("EventCode=").split(",")
            if str(sysmon_event_id) in [c.strip() for c in codes]:
                return True
    return False

# ================================================================================

def create_attack_pattern_context(attack_pattern_ids, sysmon_event_id, platform = "Windows"):
    res = []
    attack_pattern_names_to_consider = []
    no_analytic_count = 0
    for attack_pattern_id in attack_pattern_ids:
        analytics, detection_strategies, attack_pattern = get_attack_pattern_mitre(attack_pattern_id, sysmon_event_id)
        if len(analytics) == 0:
            no_analytic_count += 1
            print(f"{attack_pattern.get("id")} ({attack_pattern_id}) does not have analytics or it does not have any data components that correspond to {sysmon_event_id} ({no_analytic_count}/{len(attack_pattern_ids)})")
        else:
            attack_pattern_names_to_consider.append(attack_pattern.get("id"))
            attack_pattern_context = f"""
    The attack pattern {attack_pattern.get("id")}-{attack_pattern.get("name")} is described as:
    \"{attack_pattern.get("description")}\"
            \n
            """
            
            detection_strategies_context = ""
            for _, ditem in detection_strategies.items():
                detection_strategies_context += f"The attack pattern {attack_pattern.get("id")} is detected using {ditem.get("external_id")} ({ditem.get("name")}) which has the following {platform} analytics associated:\n"
            attack_pattern_context += detection_strategies_context

            analytics_context = ""
            for _, aitem in analytics.items():
                analytics_context += f"     - {aitem.get("external_id")} descibed as: \"{aitem.get("description")}\" with mutable elements:\n"
                for me in aitem.get("x_mitre_mutable_elements"):
                    analytics_context += f"         . {me.get("field")}: {me.get("description")}\n"
            attack_pattern_context += analytics_context
            res.append(attack_pattern_context)

    return attack_pattern_names_to_consider, res

# ========================================================================================================================================================================================================================================================================

def get_attack_pattern_mitre(attack_pattern_uuid, sysmon_event_id, platform = "Windows"):
    #Platforms can be: Windows, Linux, macOS, Containers, IaaS, ESXi or Network Devices, it will depend on the infrastructure and threat model

    load_dotenv()
    enteprise_attack_json = os.getenv("ENTERPRISE_JSON")
    
    # 1. If file not present locally, do automatic download
    if not os.path.exists(enteprise_attack_json):
        print("Downloading enterprise-attack.json from MITRE ATT&CK (this may take a while)...")
        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url)
        
        if response.status_code == 200:
            with open(enteprise_attack_json, "w", encoding="utf-8") as f:
                f.write(response.text)
            print("Download concluído com sucesso!")
        else:
            raise Exception(f"Error while retrieve MITRE's enterprise-attack.json : Status {response.status_code}")

    mitre_data = MitreAttackData(enteprise_attack_json)

    # Get attack patterns
    techniques = mitre_data.get_techniques()

    attack_pattern = {}
    for t in techniques:
        if t.get("id") == attack_pattern_uuid:
            attack_pattern = t
            break

    parsed_attack_pattern = {
        "id": attack_pattern.get("external_references")[0].get("external_id"),
        "name": attack_pattern.get("name"),
        "description": attack_pattern.get("description") #just_firstParagh(attack_pattern.get("description"))
    }

    # Find relationships with this attack pattern (maybe not necessary yet)
    all_objects = mitre_data.src.query([])
    technique_relationships = []
    for o in all_objects:
        if o.get("type") == "relationship":
            sref = o.get("source_ref")
            tref = o.get("target_ref")
            if sref == attack_pattern_uuid or tref == attack_pattern_uuid:
                entry = {
                    "source_ref" : sref,
                    "relationship_type": o.get("relationship_type"),
                    "target_ref" : tref,
                }
                technique_relationships.append(entry)

    # Find detections strategies of the technique 
    detections_strategies = mitre_data.get_detection_strategies_detecting_technique(attack_pattern_uuid)
    parsed_detection_strategies = {}
    for ds in detections_strategies:
        entry = {
            "external_id": ds.get("object").external_references[0].get("external_id"),
            "name": ds.get("object").name,
            "analytics": ds.get("object").x_mitre_analytic_refs
        }
        parsed_detection_strategies[ds.get("object").id] = entry
    

    parsed_analytics = {}
    for pds_id, entry in parsed_detection_strategies.items():

        # Find data Analytics of the detection strategy
        data_components = mitre_data.get_analytics_by_detection_strategy(pds_id)
        for dc in data_components:
            if dc.get("x_mitre_platforms")[0] == platform and sysmon_id_detector(dc.get("x_mitre_log_source_references"), sysmon_event_id):
                entry = {
                    "external_id": dc.get("external_references")[0].get("external_id"),
                    "description": dc.get("description"),
                    "x_mitre_mutable_elements": dc.get("x_mitre_mutable_elements")
                }
                parsed_analytics[dc.get("id")] = entry

    #print(technique_relationships)

    return parsed_analytics, parsed_detection_strategies, parsed_attack_pattern

# ======================================================================================
