import xml.etree.cElementTree as ET
import subprocess
import os

from dotenv import load_dotenv

# ======================================================================

def get_all_sysmon_events():

	file_path = f"sysmon_schema.xml"
	rulenames = []
	if os.path.exists(file_path):
		events = ET.parse(file_path)

		event_root = events.getroot()

		for event in event_root.findall("event"):
			if event.get("value") == "255":
				continue
			else:
				rulename = event.get("rulename")
				if rulename not in rulenames:
					rulenames.append(rulename)

	"""
	print("All rules: ")
	for rule in rulenames:
		print(f"	{rule}")
	"""
	return rulenames

# ======================================================================

def get_schema_version():

	load_dotenv()
	sysmon_path = os.getenv("SYSMON_EXE")

	# Run the schema
	res = subprocess.run(
	    [sysmon_path, "-s"],
	    capture_output=True,
	)

	sysmon_schema = res.stdout.decode("utf-16")
	start = sysmon_schema.find("<manifest")

	if start == -1:
		raise ValueError("XML inválido: <manifest> não encontrado")

	clean_xml = sysmon_schema[start:]

	root_manifest = ET.fromstring(clean_xml)
	schema_version = root_manifest.attrib.get("schemaversion")

	return schema_version

# ======================================================================

def create_base_config_file():
	# Base config file means sysmon runs and logs nothing
	
	# XML root (get sysmon version automatically soon)
	sysmon_root = ET.Element("Sysmon", schemaversion = get_schema_version())

	eventFiltering = ET.SubElement(sysmon_root, "EventFiltering")
	# Turn off the three default events
	default_events = ["ProcessCreate", "ProcessTerminate"]
	for default_event in default_events:
		ET.SubElement(eventFiltering, default_event, onmatch = "include")

	# Build the xml
	xml_file_tree = ET.ElementTree(sysmon_root)
	ET.indent(xml_file_tree, space="  ", level=0)

	return xml_file_tree

# ======================================================================

def create_default_sysmon_config_file():
	# This function craetes a config file with nothing, meaning sysmon runs in "default mode"

	# XML root (get sysmon version automatically soon)
	sysmon_root = ET.Element("Sysmon", schemaversion = get_schema_version())

	# No events
	eventFiltering = ET.SubElement(sysmon_root, "EventFiltering")

	# Build the xml
	xml_file_tree = ET.ElementTree(sysmon_root)
	ET.indent(xml_file_tree, space="  ", level=0)

	return xml_file_tree

# ======================================================================

def load_path_and_configFile():
	load_dotenv()
	return os.getenv("SYSMON_EXE")

# ======================================================================

def create_all_config_file():
	# This function creates the config file that logs everything in sysmon
	
	# xml root (get sysmon version automatically soon)
	sysmon_root = ET.Element("Sysmon", schemaversion = get_schema_version())
	# All Hash algorithms
	ET.SubElement(sysmon_root, "HashAlgorithms").text = "*"

	# All event filtering
	eventFiltering = ET.SubElement(sysmon_root, "EventFiltering")
	sysmon_events = get_all_sysmon_events()

	# To allow malware and the app to run without blockage
	not_consider_events = ["FileDelete", "FileBlockExecutable", "FileBlockShredding"]
	for event in sysmon_events:
		#exclude with 0 conditions means all types of events
		if event in not_consider_events:
			# Removes 23 because it is not necessary to store the items and it blocks 26 events to be logged
			ET.SubElement(eventFiltering, event, onmatch = "include")
		else:
			ET.SubElement(eventFiltering, event, onmatch = "exclude") 

	# Build the xml
	xml_file_tree = ET.ElementTree(sysmon_root)
	ET.indent(xml_file_tree, space="  ", level=0)

	return xml_file_tree

# ======================================================================

def get_tags_from_ids(eventCodeIDs, eventCodeMap):
	# This function retrieves MISP tags and converts it into sysmon event ID's
	tagList = []
	for eventCode in eventCodeIDs:
		tagList.append(eventCodeMap[eventCode])
	return tagList


# =======================================================================

def run_command(command):
	result = subprocess.run(command, check = True, capture_output = True)

	stdout = result.stdout.decode("utf-16-le", errors="ignore")
	stderr = result.stderr.decode("utf-16-le", errors="ignore")

	if result.returncode != 0:
		raise RuntimeError("Error while executing Sysmon")

	return stdout, stderr


def clear_sysmon_logs():

	command = [
		"wevtutil",
		"cl",
		"Microsoft-Windows-Sysmon/Operational"
	]

	result = subprocess.run(command, check = True, capture_output = True)

	stdout = result.stdout.decode("utf-16-le", errors="ignore")
	stderr = result.stderr.decode("utf-16-le", errors="ignore")

	print("Cleared sysmon logs!\n")

# =======================================================================

def apply_config_file(option):
	sysmon_config_path = f"config_files\\{option}_config_file.xml"

	# 1. Create XML
	if option == "Nothing":
		xml_config_file = create_base_config_file()
	elif option == "All":
		xml_config_file = create_all_config_file()
	elif option == "Default":
		xml_config_file = create_default_sysmon_config_file()
	
	# 2. Find paths
	sysmon_path = load_path_and_configFile()
	
	# 3. Create de base config file
	with open(sysmon_config_path, "wb") as f:
		xml_config_file.write(f, encoding="utf-8", xml_declaration=False)

    # 4. Apply the base config file
	command = [
		sysmon_path,
		"-c",
		sysmon_config_path
	]

	run_command(command)

	return True #True if command has been run

if __name__ == "__main__":
	apply_config_file("Default")