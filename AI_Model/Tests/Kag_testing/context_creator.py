import json
import sys
import os
import requests 

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


if project_root not in sys.path:
	sys.path.insert(0, project_root)

from Monitorizacao.Metric_extractor.attackpattern_extractor import get_attack_pattern_mitre, get_attack_patterns_from_MISP_event, get_capec_consequences_and_descriptions
from Monitorizacao.Metric_extractor.ioc_extractor import getVulnerabilities_for_context, extract_network_iocs_for_RAG

def create_attack_pattern_context(attack_pattern_ids, sysmon_event_id, platform = "Windows"):
	res = []
	attack_pattern_names_to_consider = []
	attack_pattern_ids_to_consider = []

	for attack_pattern_id in attack_pattern_ids:
		analytics, detection_strategies, attack_pattern = get_attack_pattern_mitre(attack_pattern_id, sysmon_event_id)
		if len(analytics) == 0:
			print(f"{attack_pattern.get("id")} ({attack_pattern_id}) does not have analytics or it does not have any data components that correspond to {sysmon_event_id}")
		else:
			attack_pattern_names_to_consider.append(attack_pattern.get("id"))
			attack_pattern_context = f"""
	The attack pattern {attack_pattern.get("id")}-{attack_pattern.get("name")} is described as:
	\"{attack_pattern.get("description")}\"
			\n
			"""
			
			detection_strategies_context = ""
			for _, ditem in detection_strategies.items():
				detection_strategies_context = f"The attack pattern {attack_pattern.get("id")} ({attack_pattern_id}) is detected using {ditem.get("external_id")} ({ditem.get("name")}) which has the following {platform} analytics associated:\n"
			attack_pattern_context += detection_strategies_context

			analytics_context = ""
			for _, aitem in analytics.items():
				analytics_context += f"		- {aitem.get("external_id")} descibed as: \"{aitem.get("description")}\" With mutable elements:\n"
				for me in aitem.get("x_mitre_mutable_elements"):
					analytics_context += f"			. {me.get("field")}: {me.get("description")}\n"
			attack_pattern_context += analytics_context
			res.append(attack_pattern_context)

	return attack_pattern_names_to_consider, res


# ================================================================================

def create_vulnerability_context(misp_event_id):

	cves = getVulnerabilities_for_context(misp_event_id)
	context_string = ""
	capec_ids = []

	if len(cves) > 0:
		context_string = "(EPSS is the measurement of probability that a vulnerability will be exploied in the next 30 days, the percentile provides a measure of an EPSS probability relative to all other scores):\n"
		first_url = "https://api.first.org/data/v1/epss"
		nist_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
		cwe_url = "https://cwe-api.mitre.org/api/v1/cwe/weakness"

		for c in cves:
			try:
				response_first = requests.get(first_url, params={"cve": c})
				response_first.raise_for_status()
				first_json = response_first.json()
				first_data = first_json.get("data")[0] if first_json.get("data") else {}
			except Exception as e:
				print(f"Error fetching EPSS data for {c}: {e}")
				first_data = {}

			try:
				response_nist = requests.get(nist_url, params={"cveId": c})
				response_nist.raise_for_status()
				response_nist_json = response_nist.json()
				vulnerabilities = response_nist_json.get("vulnerabilities", [])
				nist_data = vulnerabilities[0].get("cve") if vulnerabilities else {}
			except Exception as e:
				print(f"Error fetching NVD data for {c}: {e}")
				nist_data = {}

			descriptions = nist_data.get("descriptions", [])
			description_text = "No description available."
			for d in descriptions:
				if d.get("lang") == "en":
					description_text = d.get("value")
					break

			metrics = nist_data.get("metrics", {})
			cvss_v31_list = metrics.get("cvssMetricV31", [])
			cvss_score = "N/A"
			if cvss_v31_list:
				cvssData = cvss_v31_list[0].get("cvssData", {})
				cvss_score = cvssData.get("baseScore", "N/A")
				attack_vector = cvssData.get("attackVector", "N/A")
				impact_string = f"{cvssData.get("confidentialityImpact")} on Confidentiality, {cvssData.get("integrityImpact")} on Integrity and {cvssData.get("availabilityImpact")} on Availability. "
				impact_string += f"({cvssData.get("attackComplexity")} attack complexity, {cvssData.get("privilegesReuireds")} privileges required and {cvssData.get("userInteraction")} user interaction)."

			weaknesses_ids = []
			if nist_data:
				for weakness in nist_data.get("weaknesses", []):
					for d in weakness.get("description", []):
						weaknesses_ids.append(d.get("value")[4:])

			cwe_info = "No CWE context retrieved"
			weakness_context_string = ""
			if weaknesses_ids:
				try:
					request_link = f"{cwe_url}/{",".join(weaknesses_ids)}"
					response_cwe = requests.get(request_link)
					# Check if we actually got JSON before decoding
					if response_cwe.status_code == 200 and "application/json" in response_cwe.headers.get("Content-Type", ""):
						cwe_json = response_cwe.json()
						for w in cwe_json.get("Weaknesses"):
							capec_ids += w.get("RelatedAttackPatterns")
							weakness_context_string += f"CWE-{w.get("ID")}: {w.get("Name")}"
							likelihood = w.get("LikelihoodOfExploit")
							if likelihood:
								weakness_context_string += f" (Likelihood of exploit: {likelihood}). "
							else:
								weakness_context_string += ". "
							detectionMethods = w.get("DetectionMethods")
							weakness_context_string = weakness_context_string[:-2]
							if detectionMethods:
								weakness_context_string += ". Detections methods: "
								for dM in detectionMethods:
									weakness_context_string += f'"{dM.get("Description")}" (with {dM.get("Effectiveness") if dM.get("Effectiveness") else "Unknown"} effectiveness).'
					else:
						print(f"CWE API returned non-JSON response or error status: {response_cwe.status_code}")
				except Exception as e:
					print(f"Error querying CWE API: {e}")
			capec_consequences, descriptions= get_capec_consequences_and_descriptions(capec_ids)
			context_string += f"""
- {c}: {description_text}
	EPSS = {first_data.get("epss", "N/A")}
	Percentile = {first_data.get("percentile", "N/A")}
	CVSSv31 Base Score = {cvss_score}
	Attack Vector = {attack_vector}
	Impact = {impact_string}
	Weaknesses = {weakness_context_string}
	Consequences if attacked = {capec_consequences}
	Attack Patterns related = {descriptions}
	"""

	return context_string, cves

# ================================================================================

def create_network_ioc_context(misp_event_id):

	ioc_dict, event_timestamp, event_threat_level = extract_network_iocs_for_RAG(misp_event_id)

	if event_threat_level == 1:
		threat_level_string = "High"
	elif event_threat_level == 2:
		threat_level_string = "Medium"
	else:
		threat_level_string = "Low"

	ip_api = "http://ip-api.com/batch"
	context_string = f"The following indicators of compromise have been reported in {event_timestamp} and with {threat_level_string} threat level:\n"
	for type, value_array in ioc_dict.items():
		if type == "ip-src" or type == "ip.dst":
			response = requests.post(ip_api, json = value_array).json()
			context_string += f"	- {type}: "
			for r in response:
				context_string += f"{r.get("query")} (org: {r.get("org")}, AS: {r.get("as")}), " 
			context_string = context_string[:-2]
		else:
			context_string += f"	- {type}: {value_array}\n" 

	return context_string, ioc_dict

if __name__ == "__main__":
	#res = create_attack_pattern_context(['attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', 'attack-pattern--eb062747-2193-45de-8fa2-e62549c37ddf', 'attack-pattern--ac08589e-ee59-4935-8667-d845e38fe579', 'attack-pattern--29be378d-262d-4e99-b00d-852d573628e6', 'attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161', 'attack-pattern--4fe28b27-b13c-453e-a386-c2ef362a573b', 'attack-pattern--92d7da27-2d91-488e-a00c-059dc162766d', 'attack-pattern--b80d107d-fa0d-4b60-9684-b0433e8bdba0', 'attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807'])
	print(create_vulnerability_context("7227")[0])
	#print(create_network_ioc_context("7227")[0])



"""

=============== 
CWE

Escolhas CWE API:
- Name, para introduzir o conceito ao LLM
- LikelihoodOfExploit, para que o LLM tenha noção do quão provávvel é de ser aplicado e se vale a pena
- Description, para explicar textualmente ao LLM qual a fraqueza
- DetectionsMethods, tem descrição e efeciência que podem ser úteis para o LLM definir o que monitorizar basedo nisso
- RelatedAttackPatterns que dá padroes de ataque do CAPEC

Deixado de lado
- ID
- Abstraction
- Structure
- Status
- Diagram
- RelatedWeaknesses
- WeaknessOrdinalities
- ApplicablePlatforms*
- BackgroundDetails
- AlternateTerms
- ModesOfIntroduction
- CommonConsequences**
- PotentialMitigations
- DemonstrativeExamples*
- ObservedExamples*
- References
- MappingNotes
- Notes
- ContentHistory

*Não aplicado por questões de espaço mas potencialmente útil
** Não aplicado porque o CVE já tem métricas de propriedades de segurança afetadas
===============

"""