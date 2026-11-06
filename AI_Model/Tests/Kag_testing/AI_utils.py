import psutil
import sys
import os
import json
import requests

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
    processes = []
    for proc in psutil.process_iter(['exe']):
        try:
            exe = proc.info.get("exe")
            if exe not in processes:
                processes.append(proc.info.get("exe"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

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

def print_time_it_took(init_time, final_time):
    duration = final_time - init_time
    total_seconds = int(duration.total_seconds())
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    print(f"\n\n\n#### Time it took: {minutes} minutes and {seconds} seconds")

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

# ====================================================================

def get_network_connect_examples():
    # URL da API do GitHub para a diretoria específica
    api_url = "https://api.github.com/repos/olafhartong/sysmon-modular/contents/3_network_connection_initiated"

    examples = []

    response = requests.get(api_url)
    if response.status_code == 200:
        files = response.json()
        for file in files:
            # Garantir que é um ficheiro e não outra subpasta
            if file["type"] == "file":
                file_name = file["name"]
                # O 'download_url' aponta diretamente para o conteúdo "raw" (bruto) do ficheiro
                raw_url = file["download_url"]
                
                # Fazer o download do conteúdo do XML
                file_content = requests.get(raw_url).text
                
                examples.append(file_content)
        return examples
    else:
        print("Erro ao aceder à API do GitHub.")
        return examples


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

if __name__ == "__main__":
    if sys.argv[1] == "programs":
        programs = list_installed_programs()
        for p in programs:
            print(p)
        print(f"Listed {len(programs)} programs")
    elif sys.argv[1] == "network":
        network_exposure = list_network_exposure()
        for ne in network_exposure:
            print(f"{ne} : {network_exposure[ne]}")
        print(f"Listed {len(network_exposure)} network exposures")
    elif sys.argv[1] == "services":
        services = list_services()
        for s in services:
            print(s)
        print(f"Listed {len(services)} services")
    elif sys.argv[1] == "processes":
        processes = list_running_processes()
        for p in processes:
            print(p)
        print(f"Listed {len(processes)} running processes")
    elif sys.argv[1] == "listRegistryNetwork":
        network_iocs, len_res = listRegistryNetwork()
        for n in network_iocs:
            print(n)
        print(f"Listed {len_res} iocs from registry file")
    elif sys.argv[1] == "listRegistryVulnerabilities":
        registry_vulnerabilities = listRegistryVulnerabilities()
        for v in registry_vulnerabilities:
            print(v)
        print(f"Listed {len(registry_vulnerabilities)} vulnerabilities from registry file")
    elif sys.argv[1] == "attackpatterns":
        attack_patterns = listRegistryAttackPatterns()
        for ap in attack_patterns:
            print(ap)
        print(f"Listed {len(attack_patterns)} attack patterns from registry file")
    elif sys.argv[1] == "NetworkConnect":
        res = get_network_connect_examples()
        for r in res:
            print(r)
    elif sys.argv[1] == "ips":
        ports = list_network_exposure()
        res = get_ips_information(ports)
        for r in res:
            print(r)