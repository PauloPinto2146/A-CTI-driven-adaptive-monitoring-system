import psutil
import sys
import os
import json
import requests
import re

from windows_tools.installed_software import get_installed_software
from datetime import datetime
from dotenv import load_dotenv

# ====================================================================

def list_installed_programs():
    res = []
    for software in get_installed_software():
        if software['name']:
            res.append(f"{software['name']} {f"(v{software['version']})" if software['version'] else ""}")
    return res

# ====================================================================

def list_services():
    services = []
    for service in psutil.win_service_iter():
        try:
            s = service.as_dict()
            if s["status"] == "running":
                services.append(s["name"])
        except Exception:
            continue
    return services

# ====================================================================

def list_running_processes():
    processes = set()
    for proc in psutil.process_iter(['exe']):
        exe = proc.info.get('exe')
        if exe: 
            processes.add(exe)
    return sorted(list(processes))

# ====================================================================

def list_network_exposure(printBool = False):
    connections = {} 
    for conn in psutil.net_connections():
        try:
            if conn.status != "NONE":
                if conn.status == "LISTEN":
                    if connections.get("LISTEN"):
                        connections["LISTEN"].append({
                            "laddr": conn.laddr
                        })
                    else:
                        connections["LISTEN"] = []
                        connections["LISTEN"].append({
                            "laddr": conn.laddr
                        })
                else:
                    if connections.get(conn.status):
                        connections[conn.status].append({
                            "raddr": conn.raddr,
                            "laddr": conn.laddr
                        })
                    else:
                        connections[conn.status] = []
                        connections[conn.status].append({
                            "laddr": conn.laddr
                        })
        except Exception:
            continue
    return connections

# ====================================================================

def mark_time():
    now = datetime.now()
    return now

# ====================================================================

def print_time_it_took(init_time, final_time, string):
    duration = final_time - init_time
    total_seconds = int(duration.total_seconds())
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    print(f"Time it took ({string}): {minutes} minutes and {seconds} seconds\n")

# ====================================================================

def listRegistryNetwork():
    res = []
    load_dotenv()

    registrypath = os.getenv("REGISTRY_FILE")

    with open(registrypath, "r") as f:
        registry = json.load(f)

    iocs = registry.get("iocs")
    for ioc in iocs:
        ioc_type = ioc.get("type")
        if ioc_type == "ip-src" or ioc_type == "ip-dst" or ioc_type == "filename" or ioc_type == "hostname":
            entry = {
                        "type" : ioc.get("type"),
                        "timestamp" :ioc.get("timestamp"),
                        "value" : ioc.get("value"),
                        "threat_level_id": ioc.get("threat_level_id")
                    }
            if entry not in res:
                res.append(entry)

    return res, len(res)

# ====================================================================

def listRegistryVulnerabilities():
    res = []
    load_dotenv()

    registrypath = os.getenv("REGISTRY_FILE")

    with open(registrypath, "r") as f:
        registry = json.load(f)

    context = registry.get("context")
    for c in context:
        vulnerabilities = c.get("vulnerabilities")
        for vul in vulnerabilities:
            
            cvss = vul.get("cvssV31")
            for cv in cvss:
                if cv.get("type") == "Primary":
                    cvssdata = cv.get("cvssData")
                    entry = {
                                "cve" : vul.get("cve"),
                                "descriptons": vul.get("descriptions"),
                                "epss" : vul.get("epss"),
                                "percentile" : vul.get("percentile"),
                                "vectorString": cvssdata.get("vectorString"),
                                "baseScore" : cvssdata.get("baseScore"),
                                "baseSeverity" : cvssdata.get("baseSeverity"),
                                "exploitabilityScore" : cv.get("exploitabilityScore"),
                                "impactScore": cv.get("impactScore")
                            }
                    if entry not in res:
                        res.append(entry)
    return res

# ====================================================================

def listRegistryAttackPatterns():
    res = []
    load_dotenv()

    registrypath = os.getenv("REGISTRY_FILE")

    with open(registrypath, "r") as f:
        registry = json.load(f)

    attackPatterns = registry.get("attack-patterns")
    for ap in attackPatterns:
        entry = {
                "value" : ap.get("value"),
                "timestamp": ap.get("timestamp"),
                "threat_level_id" : ap.get("threat_level_id"),
            }
        res.append(entry)
    return res

# ========================== SYSMON EXAMPLES FOR LLM CONTEXT ==========================

def get_sysmon_examples_from_github():
    res = {}

    # 1. Define the regex match pattern for the directories that have the sysmon rules
    pattern = r"[1-9][0-9]+_.*"
    
    # 2. Get, through the github API, the directories of Olaf Hartong and get all the directory names to download next
    git_api = "https://api.github.com/repos/olafhartong/sysmon-modular/contents/"
    git_response = requests.get(git_api)
    dir_urls = {}
    if git_response.status_code == 200:
        main = git_response.json()
        for x in main:
            if x["type"] == "dir" and re.match(pattern, x["name"]):
                print(f"Getting {x["name"]} url...")
                dir_urls[x["name"]] = x["url"]
    else:
        print("Error while accessing the GitHub API: ", git_response.status_code)
        return

    # 3. For each directory get the examples
    for name, url in dir_urls.items():
        print(f"Geting {name} examples with url {url}")
        res[name] = get_directory_examples(url)

    return res

def get_directory_examples(api_url):
    examples = []

    response = requests.get(api_url)
    if response.status_code == 200:
        files = response.json()
        for file in files:
            # Be sure that it is a file and not a dir
            if file["type"] == "file":
                file_name = file["name"]
                raw_url = file["download_url"]
                
                # Download the content
                file_content = requests.get(raw_url).text
                examples.append(file_content)
        return examples
    else:
        print("Error while accessing GitHub API.")
        print("response = ", response.text)
        print("Status code = ", response.status_code)
        return examples

def populate_context_json():

    # 1. Get context.json file
    load_dotenv()
    context_json_path = os.getenv("CONTEXT_PATH")
    with open(context_json_path, "r") as f:
        json_content = json.load(f)

    # 2. get sysmon examples
    res_path = os.getenv("RES_PATH")
    try:
        if res_path:
            with open(res_path, "r") as f:
                res_dict = json.load(f)
        else:
            res_dict = get_sysmon_examples_from_github()
    except Exception as e:
        print("Error: ", e)

    # 3. For each entry find the examples and populate it
    match_flag = False # In case there are no examples 
    new_json_file = {}
    for i, entry in json_content.items():
        for r in res_dict:
            match1 = f"{i}_"
            match2 = f"_{i}_"
            if r[:2] == match1 or r[:3] == match1 or match2 in r:
                print(f"{i} matched!")
                match_flag = True
                i_examples = res_dict[r]
                new_entry = {
                    "sysmon_event_description": entry.get("sysmon_event_description"),
                    "sysmon_tags": entry.get("sysmon_event_description"),
                    "examples": i_examples
                }
                new_json_file[i] = new_entry
                break
        if not match_flag:
            print(f"{i} did not match with anything")
            new_entry = {
                    "sysmon_event_description": entry.get("sysmon_event_description"),
                    "sysmon_tags": entry.get("sysmon_event_description"),
                    "examples": ""
                }
            new_json_file[i] = new_entry
        match_flag = False

    with open(context_json_path, "w") as f:
        json.dump(new_json_file, f, indent = 4)

# ====================================================================

def find_ports(ip, ports):
    for type, info in ports.items():
        if type != "LISTEN":
            for i in info:
                raddr = i.get("raddr") 
                if raddr:
                    if str(raddr.ip) == ip:
                        return raddr.port
    return
                        

# ====================================================================

def get_ips_information(ports):
    ips_to_analyze = []

    for type, info in ports.items():
        if type != "LISTEN":
            for i in info:
                raddr = i.get("raddr") 
                if raddr:
                    query_entry = {"query": raddr.ip, "fields": "status,org,as,query"}
                    if query_entry not in ips_to_analyze:
                        ips_to_analyze.append(query_entry)
                        

    ip_api = "http://ip-api.com/batch"

    response = requests.post(ip_api, json = ips_to_analyze)
    if response.status_code == 200:
        res = []
        for r in response.json():
            if r.get("status") == "success":
                # Remove query status for noise reduction
                port = find_ports(r.get("query"), ports) 
                res.append(
                    {
                        "raddr": r.get("query"),
                        "org": r.get("org"),
                        "AS": r.get("as"),
                        "port": port
                    })
    else:
        print("Error while trying to reach IP-API: ", response.status_code)
        return
    return res

# ====================================================================

def convert_to_contains(misp_id):
    
    with open(f"sysmon_configuration_file_{misp_id}.xml", "r", encoding="utf-8") as f:
        xml_content = f.read()
    
    # IMPORTANT: replace "is any" before "is"
    xml_content = xml_content.replace(
        'condition="is any"',
        'condition="contains any"'
    )

    xml_content = xml_content.replace(
        'condition="is"',
        'condition="contains"'
    )
    
    xml_content = xml_content.replace(
        'condition="begin with"',
        'condition="contains"'
    )

    xml_content = xml_content.replace(
        'condition="end with"',
        'condition="contains"'
    )
    
    with open(f"sysmon_configuration_file_{misp_id}_contains.xml", "w", encoding="utf-8") as f:
        f.write(xml_content)

# ====================================================================

def get_sysmon_event_name(sysmon_event_id):

    sysmon_events = {
        1 : "ProcessCreate",
        2 : "FileCreateTime",
        3 : "NetworkConnect",
        5 : "ProcessTerminate",
        6 : "DriverLoad",
        7 : "ImageLoad",
        8 : "CreateRemoteThread",
        9 : "RawAccessRead",
        10 : "ProcessAccess",
        11 : "FileCreate",
        12 : "RegistryEvent",
        13 : "RegistryEvent",
        14 : "RegistryEvent",
        15 : "FileCreateStreamHash",
        17 : "PipeEvent",
        18 : "PipeEvent",
        19 : "WmiEvent",
        20 : "WmiEvent",
        21 : "WmiEvent",
        22 : "DnsQuery",
        23 : "FileDelete",
        24 : "ClipboardChange",
        25 : "ProcessTampering",
        26 : "FileDeleteDetected",
        27 : "FileBlockExecutable",
        28 : "FileBlockShredding",
        29 : "FileExecutableDetected"
    }

    return sysmon_events.get(int(sysmon_event_id))


# ====================================================================

if __name__ == "__main__":
   convert_to_contains(3945)
   convert_to_contains(9007)