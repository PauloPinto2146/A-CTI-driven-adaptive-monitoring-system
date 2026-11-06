import xml.etree.ElementTree as ET
import copy
import os
import subprocess

from pathlib import Path
from dotenv import load_dotenv

# ==============================================================================================================


def aggregator(sysmon_snippets, misp_event_id, hash_algorithms):
	# 1. Store the 'correct' version (preserves original Event ID 1 generated rules) for resource compsumption testing
	correct_root = build_sysmon_xml(sysmon_snippets, hash_algorithms, force_exclude_event_1=False)
	write_xml(correct_root, misp_event_id, "_correct")

	# 2. Store the "malware" version (force ProcessCreate onmatch="exclude") for malware testing
	malware_testing_root = build_sysmon_xml(sysmon_snippets, hash_algorithms, force_exclude_event_1=True)
	write_xml(malware_testing_root, misp_event_id, "")
	valid = apply_sysmon_config(correct_root, misp_event_id)

	return valid

# ==============================================================================================================

def apply_sysmon_config(xml_root, event_id):

	xml_str = ET.tostring(xml_root, encoding="unicode")
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

# ==============================================================================================================

def build_sysmon_xml(sysmon_snippets, hash_algorithms, force_exclude_event_1):
	sysmon_snippets_copy = copy.deepcopy(sysmon_snippets)

	"""
	FIRST OF ALL. Need to find if these:

	- ProcessCreate (1)
	- ProcessTerminate (5)
	
	are in there or not, if they are, we need to do <TAG onmatch="include" /> so it does not have any logs in there unwanted
	"""

	# This "forcing" is because the tracer is dependent on the sysmon event id 1 for tracing porpuses
	if force_exclude_event_1:
		sysmon_snippets_copy = [entry for entry in sysmon_snippets_copy if "1" not in entry]
		sysmon_snippets_copy.append({
			"1": {
				"sysmon_snippet": "<Sysmon schemaversion=\"4.30\">\n\t<EventFiltering>\n\t\t<ProcessCreate onmatch=\"exclude\" />\n\t</EventFiltering>\n</Sysmon>"
			}
		})
	else:
		# "Correct" version: if Event ID 1 not exists in report, add by an empty include (same for 5)
		found_1 = any("1" in entry for entry in sysmon_snippets_copy)
		if not found_1:
			sysmon_snippets_copy.append({
				"1": {
					"sysmon_snippet": "<Sysmon schemaversion=\"4.30\">\n\t<EventFiltering>\n\t\t<ProcessCreate onmatch=\"include\" />\n\t</EventFiltering>\n</Sysmon>"
				}
			})

	found_5 = any("5" in entry for entry in sysmon_snippets_copy)
	if not found_5:
		sysmon_snippets_copy.append({
			"5": {
				"sysmon_snippet": "<Sysmon schemaversion=\"4.30\">\n\t<EventFiltering>\n\t\t<ProcessTerminate onmatch=\"include\"/>\n\t</EventFiltering>\n</Sysmon>"
			}
		})


	final_xml_root = ET.Element("Sysmon")
	final_xml_root.set("schemaversion", "4.91")

	"""
	Hash algorithm(s) to apply for hashing. Algorithms supported include MD5, SHA1, SHA256, IMPHASH and * (all). Default: None
	"""
	if len(hash_algorithms) > 3:
		hash_algorithms_string = "*"
	else:
		hash_algorithms_string = ""
		for h in hash_algorithms:
			hash_algorithms_string += h + ","
		hash_algorithms_string = hash_algorithms_string[:-1]

	ET.SubElement(final_xml_root, "HashAlgorithms").text = hash_algorithms_string

	event_filtering = ET.SubElement(final_xml_root, "EventFiltering")

	# Replace FileDelete tag with FileDeleteDetected
	tag_rename = {"FileDelete": "FileDeleteDetected"}

	first = True
	for entry in sysmon_snippets_copy:
	    for sysmon_event_id, results in entry.items():

	        is_23 = int(sysmon_event_id) == 23
	        if is_23:
	            sysmon_event_id = 26

	        x = results.get("sysmon_snippet")

	        comment = ET.Comment(f"== Sysmon event {sysmon_event_id} ==")
	        if not first:
	            comment.tail = "\n\n"
	        first = False
	        event_filtering.append(comment)

	        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
	        root = ET.fromstring(x, parser=parser)

	        for tag in root.findall(".//EventFiltering"):
	            for rulegroup in tag:
	                if is_23:
	                    for el in rulegroup.iter():
	                        el.tag = tag_rename.get(el.tag, el.tag)
	                event_filtering.append(rulegroup)
	
	return final_xml_root

# ==============================================================================================================

def print_xml(xml_root):
	ET.indent(xml_root, space="    ")
	print(ET.tostring(xml_root, encoding="unicode"))


# ==============================================================================================================

def write_xml(xml_root, misp_event_id, tag):
	ET.indent(xml_root, space="    ")

	with open(f"execution_results_{misp_event_id}/config_file_{misp_event_id}{tag}.xml", "w", encoding="utf-8") as f:
		f.write(ET.tostring(xml_root, encoding="unicode"))

# ==============================================================================================================