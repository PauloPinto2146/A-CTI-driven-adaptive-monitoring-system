import winreg
import psutil
import sys
import os
import json

from datetime import datetime
from dotenv import load_dotenv

# ====================================================================

def list_installed_programs():

    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    key = winreg.OpenKey(registry, key_path)

    programs = []

    for i in range(0, winreg.QueryInfoKey(key)[0]):

        try:
            subkey_name = winreg.EnumKey(key, i)
            subkey_path = key_path + "\\" + subkey_name

            subkey = winreg.OpenKey(registry, subkey_path)

            try:
                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                programs.append(name)
            except:
                pass

        except Exception:
            continue

    return programs

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
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            processes.append(proc.info)
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
    print(f"Time it took: {minutes} minutes and {seconds} seconds")

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