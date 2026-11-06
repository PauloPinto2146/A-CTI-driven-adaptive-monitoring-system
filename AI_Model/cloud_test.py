import os
import json

from ollama import Client
from AI_utils import mark_time, print_time_it_took, list_network_exposure, listRegistryNetwork, listRegistryVulnerabilities

client = Client(
    host="https://ollama.com",
    headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
)

prompt = """
        You are a strict Cyber Security Expert and Risk Analyst. Your task is to analyze threat intelligence against a host's current state and justify which Indicators of Compromise (IoCs) are critical to monitor.

    Context for your decision:
        1. Time Relevancy: How recent or applicable are the threat intelligence metrics.
        2. Vulnerabilities reported: The likelihood, impact and risk of a malicious action in the network of the host.
        3. Attack Surface: Cross-reference the host's active ports, vulnerabilities and the IoCs in the CTI report.

Data Provided:
    - Current Host Network State (Active addresses and ports):
{"TIME_WAIT": [{"laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53502]}, {"raddr": ["2606:4700:2ff9::1", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53501]}, {"raddr": ["2a06:98c1:3107::6812:2715", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53307]}, {"raddr": ["2606:4700:2ff9::1", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53503]}, {"raddr": ["20.150.95.164", 443], "laddr": ["192.168.1.147", 53495]}, {"raddr": ["2a00:1450:4003:80b::200e", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53315]}, {"raddr": ["127.0.0.1", 53485], "laddr": ["127.0.0.1", 53491]}, {"raddr": ["2606:4700:3036::6815:4be3", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53500]}], "LISTEN": [{"laddr": ["0.0.0.0", 49666]}, {"laddr": ["0.0.0.0", 49667]}, {"laddr": ["0.0.0.0", 16992]}, {"laddr": ["::", 16992]}, {"laddr": ["0.0.0.0", 623]}, {"laddr": ["172.21.32.1", 139]}, {"laddr": ["::", 49665]}, {"laddr": ["::", 7680]}, {"laddr": ["127.0.0.1", 64530]}, {"laddr": ["0.0.0.0", 135]}, {"laddr": ["0.0.0.0", 5040]}, {"laddr": ["::", 49693]}, {"laddr": ["127.0.0.1", 53485]}, {"laddr": ["::", 49667]}, {"laddr": ["0.0.0.0", 49668]}, {"laddr": ["::1", 49669]}, {"laddr": ["0.0.0.0", 7680]}, {"laddr": ["0.0.0.0", 49693]}, {"laddr": ["::", 623]}, {"laddr": ["0.0.0.0", 445]}, {"laddr": ["::", 445]}, {"laddr": ["0.0.0.0", 49665]}, {"laddr": ["::", 135]}, {"laddr": ["0.0.0.0", 49664]}, {"laddr": ["::1", 42050]}, {"laddr": ["::", 49664]}, {"laddr": ["127.0.0.1", 11434]}, {"laddr": ["::", 49668]}, {"laddr": ["192.168.1.147", 139]}, {"laddr": ["::", 49666]}], "ESTABLISHED": [{"laddr": ["127.0.0.1", 53384]}, {"raddr": ["127.0.0.1", 49671], "laddr": ["127.0.0.1", 49670]}, {"raddr": ["2a06:98c1:3107::6812:2715", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53505]}, {"raddr": ["127.0.0.1", 49670], "laddr": ["127.0.0.1", 49671]}, {"raddr": ["140.82.112.26", 443], "laddr": ["192.168.1.147", 53418]}, {"raddr": ["2603:1020:5:9::400", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 49428]}, {"raddr": ["127.0.0.1", 53384], "laddr": ["127.0.0.1", 53385]}, {"raddr": ["127.0.0.1", 62866], "laddr": ["127.0.0.1", 62867]}, {"raddr": ["2a04:4e42:86::347", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53498]}, {"raddr": ["127.0.0.1", 62867], "laddr": ["127.0.0.1", 62866]}, {"raddr": ["2a06:98c1:3107::6812:2715", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53504]}, {"raddr": ["34.107.243.93", 443], "laddr": ["192.168.1.147", 53497]}, {"raddr": ["2603:1063:7::cc", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53676]}, {"raddr": ["2603:1063:45::2c", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 62041]}, {"raddr": ["2603:1063:12:10c::365:7ea3", 443], "laddr": ["2001:818:ea21:2800:683d:5b37:927d:4654", 53240]}, {"raddr": ["34.107.243.93", 443], "laddr": ["192.168.1.147", 53496]}]}

    - Cyber Threat Intelligence (CTI) Report containing verified IoCs (threat_level_id 3:Low, 2: Medium, 1: High)
[{"type": "ip-src", "timestamp": 1772455068, "value": "185.216.70.170", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "77.90.38.170", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "154.216.19.224", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "154.216.17.157", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "176.65.141.201", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "176.65.141.232", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "206.123.145.13", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "sos.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "audiodg.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "audiofg.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "KB332.ps1", "threat_level_id": 2}]

    - Vulnerabilities reported:
[{"cve": "CVE-2023-48788", "descriptons": [{"lang": "en", "value": "A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiClientEMS version 7.2.0 through 7.2.2, FortiClientEMS 7.0.1 through 7.0.10 allows attacker to execute unauthorized code or commands via specially crafted packets."}], "epss": "0.940780000", "percentile": "0.999090000", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL", "exploitabilityScore": 3.9, "impactScore": 5.9}]


    Your Task:
        Provide a detailed security analysis. For each category (Source IPs, Destination IPs, Ports, and Images), explain which elements from the data pose a real threat to this host and why they must be selected for monitoring (you are writin for an AI model, not a person).

    Strict Rules to Follow:
        1. Do NOT hallucinate IP addresses. Only consider the data  provided.
        2. For process images (executables), prioritize the files discovered in the CTI report. If you suggest additional system binaries, they must strictly relate to the exploitation of the listed vulnerabilities.
        3. Start your response directly with the technical analysis sections.
        4. Do NOT include markdown tables, "To/From" headers, dates, executive summaries, or final disclaimers.
        """

messages = [
  {
    'role': 'user',
    'content': prompt,
  },
]
init_time = mark_time()
for part in client.chat('gemma3:27b-cloud', messages=messages, stream=True):
  print(part['message']['content'], end='', flush=True)
final_time = mark_time()
print_time_it_took(init_time, final_time)