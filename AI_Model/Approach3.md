# Approach 3 - Asking to filter decide the IoCs to consider in a given sysmon tag and THEN produce the sysmon config portion.

Approach 2, compared to 1, improved in terms of valid structure, additionally, in some models, the risk assessment was considered and resulted in considering different services.
This third approach aims to a different problem. Besides structural and risk assessment improvements the majority of the AI models couldn't figure out that the IP address given was not meant to be considered in the final result.
Considering this problem, a possible solution (discussed in a meeting in 21/05/2026 with the professor João Marco) can be to ask the AI which IoCs are to be considered in the sysmon configuration file and then produce the sysmon configuration file. This approach is meant to divide the two main tasks that were being given to the AI model: (1) IoC selection and (2) Creation of the sysmon event tag.

In this prompt we will consider the `NetworkConnect` tag and more various types of IoCs than previous approaches:
- The ones coming from a MISP report that are related to network (ip-src, ip-dst, filename, hostname)
- The ones that are common to consider given an attack pattern
- The information in the host (services, programs, network exposure)

In this approach I want to evaluate:

- Does the final result respect the analysis done?
- Does 

prompt:

```
    You are a strict Cyber Security Expert and Risk Analyst. Your task is to analyze threat intelligence against a host's current state and justify which Indicators of Compromise (IoCs) are critical to monitor.

    Context for your decision:
        1. Time Relevancy: How recent or applicable are the threat intelligence metrics.
        2. Vulnerabilities reported: The likelihood, impact and risk of a malicious action in the network of the host.
        3. Attack Surface: Cross-reference the host's active ports, vulnerabilities and the IoCs in the CTI report.

Data Provided:
    - Current Host Network State (Active addresses and ports):
{"LISTEN": [{"laddr": ["127.0.0.1", 11434]}, {"laddr": ["::", 135]}, {"laddr": ["0.0.0.0", 16992]}, {"laddr": ["0.0.0.0", 7680]}, {"laddr": ["0.0.0.0", 49666]}, {"laddr": ["::", 7680]}, {"laddr": ["127.0.0.1", 58693]}, {"laddr": ["192.168.1.147", 139]}, {"laddr": ["::", 49665]}, {"laddr": ["0.0.0.0", 49664]}, {"laddr": ["0.0.0.0", 49693]}, {"laddr": ["0.0.0.0", 135]}, {"laddr": ["::", 49664]}, {"laddr": ["::1", 49669]}, {"laddr": ["::", 49693]}, {"laddr": ["0.0.0.0", 5040]}, {"laddr": ["::", 16992]}, {"laddr": ["::", 49666]}, {"laddr": ["0.0.0.0", 49665]}, {"laddr": ["::", 49667]}, {"laddr": ["::", 445]}, {"laddr": ["::", 49668]}, {"laddr": ["0.0.0.0", 623]}, {"laddr": ["172.21.32.1", 139]}, {"laddr": ["0.0.0.0", 445]}, {"laddr": ["0.0.0.0", 49668]}, {"laddr": ["::", 623]}, {"laddr": ["::1", 42050]}, {"laddr": ["0.0.0.0", 49667]}], "ESTABLISHED": [{"laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 57821]}, {"raddr": ["146.75.90.142", 443], "laddr": ["192.168.1.147", 54146]}, {"raddr": ["140.82.113.26", 443], "laddr": ["192.168.1.147", 56567]}, {"raddr": ["127.0.0.1", 63579], "laddr": ["127.0.0.1", 63580]}, {"raddr": ["2620:1ec:42::133", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 61842]}, {"raddr": ["2603:1063:12:14f::365:7ea3", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 56804]}, {"raddr": ["127.0.0.1", 63578], "laddr": ["127.0.0.1", 63577]}, {"raddr": ["3.160.132.32", 443], "laddr": ["192.168.1.147", 54186]}, {"raddr": ["2600:9000:2134:8600:5:a780:9d40:93a1", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 54138]}, {"raddr": ["52.112.100.63", 443], "laddr": ["192.168.1.147", 62129]}, {"raddr": ["127.0.0.1", 49670], "laddr": ["127.0.0.1", 49671]}, {"raddr": ["99.86.159.53", 443], "laddr": ["192.168.1.147", 54183]}, {"raddr": ["13.69.239.78", 443], "laddr": ["192.168.1.147", 62703]}, {"raddr": ["34.107.243.93", 443], "laddr": ["192.168.1.147", 54102]}, {"raddr": ["2620:1ec:42::132", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 62701]}, {"raddr": ["3.160.132.40", 443], "laddr": ["192.168.1.147", 54181]}, {"raddr": ["20.189.173.27", 443], "laddr": ["192.168.1.147", 62704]}, {"raddr": ["99.86.165.254", 443], "laddr": ["192.168.1.147", 54188]}, {"raddr": ["127.0.0.1", 63580], "laddr": ["127.0.0.1", 63579]}, {"raddr": ["13.107.6.254", 443], "laddr": ["192.168.1.147", 53281]}, {"raddr": ["2603:1063:7::cc", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 52722]}, {"raddr": ["20.42.72.131", 443], "laddr": ["192.168.1.147", 62702]}, {"raddr": ["204.79.197.222", 443], "laddr": ["192.168.1.147", 56325]}, {"raddr": ["127.0.0.1", 49671], "laddr": ["127.0.0.1", 49670]}, {"raddr": ["127.0.0.1", 63577], "laddr": ["127.0.0.1", 63578]}, {"raddr": ["2603:1020:5:9::401", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 49434]}, {"raddr": ["2603:1026:c15:c1a::2", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 54189]}, {"raddr": ["2603:1061:f:103::254", 443], "laddr": ["2001:818:ea21:2800:c949:a8e2:d078:66d4", 56345]}], "TIME_WAIT": [{"laddr": ["192.168.1.147", 54187]}]}

    - Cyber Threat Intelligence (CTI) Report containing verified IoCs (threat_level_id 3:Low, 2: Medium, 1: High)
[{"type": "ip-src", "timestamp": 1772455068, "value": "185.216.70.170", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "77.90.38.170", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "154.216.19.224", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "154.216.17.157", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "176.65.141.201", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "176.65.141.232", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "206.123.145.13", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "sos.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "audiodg.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "audiofg.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "KB332.ps1", "threat_level_id": 2}]

    - Vulnerabilities reported:
[{"cve": "CVE-2023-48788", "descriptons": [{"lang": "en", "value": "A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiClientEMS version 7.2.0 through 7.2.2, FortiClientEMS 7.0.1 through 7.0.10 allows attacker to execute unauthorized code or commands via specially crafted packets."}], "epss": "0.940780000", "percentile": "0.999090000", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL", "exploitabilityScore": 3.9, "impactScore": 5.9}]


    Your Task step-by-step:
        1. Provide a detailed security analysis. For each category (Source IPs, Destination IPs, Ports, and Images), explain which elements from the data pose a real threat to this host and why they must be selected for monitoring (you are writin for an AI model, not a person).

    Strict Rules to Follow:
        1. Do NOT hallucinate IP addresses. Only consider the data  provided.
        2. For process images (executables), prioritize the files discovered in the CTI report. If you suggest additional system binaries, they must strictly relate to the exploitation of the listed vulnerabilities.
        3. Start your response directly with the technical analysis sections.
        4. Do NOT include markdown tables, "To/From" headers, dates, executive summaries, or final disclaimers.

```

---

# Gemma3:27b-cloud


## Source IP Analysis

The CTI report lists several source IPs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, and 206.123.145.13, all with a medium threat level (2). Given the critical vulnerability CVE-2023-48788 affecting Fortinet products and the observed activity on port 443, these IPs warrant immediate and continuous monitoring.  The high CVSS score (9.8) and critical severity of the vulnerability indicate a high probability of exploitation. Port 443 connections to these IPs should be logged extensively, and any unusual activity, such as frequent connection attempts or large data transfers, should trigger an alert. Monitoring should include deep packet inspection where feasible, to identify potentially malicious payloads.

## Destination IP Analysis

The host's network state reveals numerous established connections to external IPs, notably on port 443.  Specifically, connections to 52.112.120.233, 52.112.100.62, 104.18.39.21, 35.186.224.39, 34.107.243.93, 140.82.114.25, 162.159.135.234, 4.207.247.137 and 52.97.117.2 all require active monitoring. While none of these IPs are directly listed in the CTI report, the consistent use of port 443, combined with the identified vulnerability CVE-2023-48788 and the associated attack patterns (Exploit Public-Facing Application), raises suspicion. These connections must be correlated with system logs and process activity to identify any anomalous behavior. Network traffic analysis should focus on identifying malicious payloads delivered via HTTPS.

## Port Analysis

Port 443 is the most critical port to monitor. The host is actively establishing connections to multiple external hosts on this port, correlating with the CTI report’s identified malicious IPs and the high-severity vulnerability.  Given the exploit vector, focusing on port 443 traffic is paramount.  Additionally, ports 135 and 445 are listening, and the CTI report indicates potential Remote Desktop Protocol (T1021.001) activity.  While there’s no direct IoC for RDP exploitation, the open ports represent a significant attack surface and should be closely monitored for unauthorized access attempts. Port 139 is also listening and represents another potential attack vector.

## Image Analysis

The CTI report identifies "sos.exe," "audiodg.exe," "audiofg.exe" and “KB332.ps1” as suspicious filenames. Monitoring for the execution of these processes is crucial.  "sos.exe" and the audio related executables are highly suspicious because they are not standard system files, and their presence could indicate malware or tools used for persistence. "KB332.ps1" is a PowerShell script, aligning with the "PowerShell - T1059.001" attack pattern, and its execution should be logged and analyzed. Furthermore, given the SQL injection vulnerability (CVE-2023-48788), processes interacting with databases (e.g., SQL Server services) require heightened scrutiny. Specifically, monitoring 'sqlservr.exe' for unusual activity, such as unexpected connections or excessive resource consumption, is essential. Also, 'cmd.exe' and 'powershell.exe' should be monitored due to their common use in exploitation and post-exploitation activities.

Time it took: 0 minutes and 33 seconds

```xml
<NetworkConnect onmatch="include">
    <!-- Monitoring connections to identified malicious IPs from CTI report -->
    <DestinationIp condition="is any of">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
    <!-- Monitoring connections on port 443 due to identified vulnerability and high observed activity -->
    <DestinationPort>443</DestinationPort>
    <!-- Monitoring connections on port 135 and 445 due to open ports and potential RDP exploitation -->
    <DestinationPort>135</DestinationPort>
    <DestinationPort>445</DestinationPort>
    <!-- Monitoring for suspicious images identified in CTI -->
    <Image condition="contains any">sos.exe;audiodg.exe;audiofg.exe;KB332.ps1</Image>
    <!-- Monitoring database-related processes for anomalous activity tied to SQL injection vulnerability -->
    <Image condition="contains any">sqlservr.exe</Image>
    <!-- Monitoring common exploitation tools -->
    <Image condition="contains any">cmd.exe;powershell.exe</Image>
    <!-- Monitoring for outbound connections initiated by the host, indicating potential C2 communication -->
    <Initiated>true</Initiated>
    <!-- Monitoring traffic on all protocols, but prioritizing 443 -->
    <Protocol>tcp</Protocol>
</NetworkConnect>
```
Time it took: 0 minutes and 26 seconds

---


# Gemma4:31b-cloud

### Source IPs Analysis

The CTI report identifies seven high-risk source IPs: `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, and `206.123.145.13`. All are assigned `threat_level_id: 2` (Medium). While no current `ESTABLISHED` or `TIME_WAIT` connections match these IPs, they must be prioritized for monitoring due to the host's exposure of critical services (SMB/RPC) and a critical CVE. Any ingress traffic from these IPs to the host's active listener ports should be flagged as a high-probability attack attempt.

### Destination IPs Analysis
The host exhibits active connections to numerous external IPs via port 443 (HTTPS). Notable destinations include `3.160.132.5`, `99.86.165.254`, `2.22.85.178`, and `140.82.113.26`. None of these match the provided CTI source IPs. However, since the host is vulnerable to `CVE-2023-48788` (Remote Code Execution), any new outbound connection to an unknown IP following an unexpected inbound request to the host's listeners must be monitored as a potential reverse shell or C2 beacon. 

 ### Ports Analysis
 The host's attack surface is high-risk. Active listeners on ports `135` (RPC) and `445` (SMB) are highly targeted for lateral movement and remote exploitation. Specifically, the presence of port `445` combined with the critical nature of `CVE-2023-48788` (Base Score: 9.8) indicates a severe risk of unauthorized command execution. Monitor all inbound traffic to ports `135`, `139`, and `445` for exploitation patterns, as these are the primary vectors for the vulnerabilities associated with the network state.     

 ### Images Analysis

 Critical monitoring must be applied to the following binaries identified in the CTI report: `sos.exe`, `audiodg.exe`, `audiofg.exe`, and `KB332.ps1`. `audiodg.exe` and `audiofg.exe` are high-priority targets as they often represent masquerading techniques (mimicking legitimate Windows audio services) to hide malicious persistence. `KB332.ps1` indicates a PowerShell-based attack vector, which aligns with the "unauthorized code execution" impact of `CVE-2023-48788`. Any execution or creation of these files on the filesystem must be treated as a confirmed compromise.

 Time it took: 0 minutes and 21 seconds  

```xml
<NetworkConnect onmatch="include">
    <!-- Monitor CTI identified high-risk source IPs attempting to connect to host -->
    <SourceIp condition="contains any">
        185.216.70.170;
        77.90.38.170;
        154.216.19.224;
        154.216.17.157;
        176.65.141.201;
        176.65.141.232;
        206.123.145.13;
    </SourceIp>
    <!-- Monitor SMB/RPC ports exposed on 0.0.0.0 targeted by T1190 and T1021.001 -->
    <DestinationPort>445</DestinationPort>
    <DestinationPort>135</DestinationPort>
    <!-- Monitor HTTPS traffic for C2 and Exfiltration (T1071.001/T1567) aligned with current established connections -->
    <DestinationPort>443</DestinationPort>
    <!-- Monitor network activity from specifically identified malicious binaries in CTI report -->
    <Image condition="contains any">
        sos.exe;
        audiodg.exe;
        audiofg.exe;
    </Image>
</NetworkConnect>                                                                                                  
```
Time it took: 0 minutes and 6 seconds 


# Comparison

| LLM | Valid sysmon? | Perform better than app1? | Notice IP address? | IoCs correctly used? | Creative? | It did what was asked of it? | Respect Constraints? | Time |
|:---:|:-------------:|:-------------------------:|:------------------:|:--------------------:|:---------:|:----------------------------:|:--------------------:|:----:|
| Qwen2.5:14b | ✅ | ✅ | ✅ | ➖ | ✅ | ➖ | ➖ | 2min 19s (faster) | 
| llama3.1:8b (latest) | ➖ | ❌ | ✅ | ➖ | ✅ | ❌ | ➖ | 2min 37s (faster) | 
| Gemma3:4b (latest) | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ➖ | 0min 37s (faster) | 
| Gemma4:e4b (latest) | ❌ | ✅ | ➖ | ➖ | ✅ | ➖ | ✅ | 4min 10s (faster) | 

❌ - No
✅ - Yes
➖ - Partially