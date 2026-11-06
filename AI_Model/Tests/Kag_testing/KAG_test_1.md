=== CONTEXT ===

```
The attack pattern T1486-Data Encrypted for Impact is described as:
"Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.(Citation: US-CERT Ransomware 2016)(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017)(Citation: US-CERT SamSam 2018)
"


        The attack pattern T1486 is detected using DET0215 (Detection of Multi-Platform File Encryption for Impact) which has the following Windows analytics associated:
                - AN0602 descibed as: "High-frequency file write operations using uncommon extensions, followed by ransom note creation, registry tampering, or shadow copy deletion. Often uses CLI tools like vssadmin, wbadmin, cipher, or PowerShell." With mutable elements:
                        . FileExtension: Non-standard or randomly generated file extensions may indicate encrypted content.
                        . TargetFolder: Focus on user document folders, network shares, or system paths like %System32%.
                        . TimeWindow: Correlate rapid writes and renames within seconds across high file count.
                        . CommandLine: Flag common ransomware tools or functions (vssadmin delete shadows /all /quiet).


The attack pattern T1190-Exploit Public-Facing Application is described as:
"Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.
"


        The attack pattern T1190 is detected using DET0080 (Exploit Public-Facing Application – multi-signal correlation (request → error → post-exploit process/egress)) which has the following Windows analytics associated:
                - AN0219 descibed as: "Adversary sends crafted HTTP/S (or other service) input to an Internet-facing app (IIS/ASP.NET, API, device portal). Chain: (1) abnormal request patterns to public endpoint → (2) elevated 4xx/5xx or unusual methods/paths → (3) server process (w3wp.exe/other service) spawns shell/LOLbins or loads non-standard modules → (4) optional outbound callback from the host/container." With mutable elements:
                        . PublicVIPs: List of public IPs/hostnames that front apps; used to scope web log and Zeek/proxy data.
                        . SuspiciousPatterns: Regex set for exploit-like inputs (../, union select, cmd=, ${jndi:, rO0AB (Java serialization), %00, ${env:}, ${${::-j}ndi}).
                        . ErrorRateThreshold: Spike threshold for HTTP status 5xx/4xx per client or URI (e.g., >5 in 5m).
                        . TimeWindow: Correlation horizon between request, error, process spawn, and egress (e.g., 15 minutes).
                        . AllowedChildList: Known child processes of app pools (e.g., msbuild.exe in CI) to reduce false positives.


The attack pattern T1059.001-PowerShell is described as:
"Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.(Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).
"


        The attack pattern T1059.001 is detected using DET0455 (Abuse of PowerShell for Arbitrary Execution) which has the following Windows analytics associated:
                - AN1252 descibed as: "Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and indirect (.NET automation) invocations." With mutable elements:
                        . CommandLinePattern: Regex pattern for encoded, obfuscated, or hidden PowerShell arguments (e.g., '-enc', '-nop').
                        . ParentProcessName: Filter based on abnormal parents like Excel, WinWord, or mshta spawning PowerShell.
                        . TimeWindow: Scope detection to off-hours, lateral movement timeframes, or non-maintenance windows.
                        . LoadedModuleList: Tuneable to monitor rare or never-before-seen .NET assemblies tied to PowerShell abuse.
                        . ScriptBlockLengthThreshold: Adjustable threshold for length of script blocks logged by Event ID 4104 (useful for filtering noise).


The attack pattern T1572-Protocol Tunneling is described as:
"Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.
"


        The attack pattern T1572 is detected using DET0538 (Detection Strategy for Protocol Tunneling accross OS platforms.) which has the following Windows analytics associated:
                - AN1483 descibed as: "Processes such as plink.exe, ssh.exe, or netsh.exe establishing outbound network connections where traffic patterns show encapsulated protocols (e.g., RDP over SSH). Defender observations include anomalous process-to-network relationships, large asymmetric data flows, and port usage mismatches." With mutable elements:
                        . AllowedTools: Whitelist legitimate tunneling tools (e.g., used by admins).
                        . DataAsymmetryThreshold: Ratio of sent vs received bytes that indicates tunneling activity.
                        . TimeWindow: Correlate process creation with network connection within N seconds.


The attack pattern T1497.001-System Checks is described as:
"Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors.(Citation: Deloitte Environment Awareness)
"


        The attack pattern T1497.001 is detected using DET0168 (Virtualization/Sandbox Evasion via System Checks across Windows, Linux, macOS) which has the following Windows analytics associated:
                - AN0478 descibed as: "Script or binary performs a rapid sequence of system discovery checks (e.g., CPU count, RAM size, registry keys, running processes) indicative of VM detection" With mutable elements:
                        . TimeWindow: Sequence of system enumeration events within X seconds
                        . ProcessAncestry: Parent-child lineage to identify potentially suspicious launch sources (e.g., Office, browser, WMI, PowerShell)
                        . UserContext: Limit to non-admin or interactive sessions if desired


The attack pattern T1041-Exfiltration Over C2 Channel is described as:
"Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications."


        The attack pattern T1041 is detected using DET0348 (Detection Strategy for Exfiltration Over C2 Channel) which has the following Windows analytics associated:
                - AN0988 descibed as: "Identifies suspicious outbound traffic volume mismatches from processes that typically do not generate network activity, particularly over C2 protocols like HTTPS, DNS, or custom TCP/UDP ports, following file or data access." With mutable elements:
                        . DataVolumeThreshold: Set threshold for outbound transfer size exceeding typical C2 traffic (e.g., >1MB in <5min).
                        . KnownBenignProcesses: List of approved processes that may exhibit high outbound traffic (e.g., updates).


The attack pattern T1567-Exfiltration Over Web Service is described as:
"Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.
"


        The attack pattern T1567 is detected using DET0548 (Detection Strategy for Exfiltration Over Web Service) which has the following Windows analytics associated:
                - AN1511 descibed as: "Processes that normally do not initiate network communications suddenly making outbound HTTPS connections with high outbound-to-inbound data ratios. Defender view: correlation between process creation logs (e.g., Word, Excel, PowerShell) and subsequent anomalous network traffic volumes toward common web services (Dropbox, Google Drive, OneDrive)." With mutable elements:
                        . MonitoredServices: List of legitimate web services to baseline (Dropbox, OneDrive, Google Drive).
                        . ExfilVolumeThreshold: Outbound data threshold for flagging unusual activity, tunable by environment.
                        . TimeWindow: Aggregation period to calculate anomalies in outbound data volume.


The attack pattern T1021.001-Remote Desktop Protocol is described as:
"Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.
"


        The attack pattern T1021.001 is detected using DET0327 (Multi-event Detection Strategy for RDP-Based Remote Logins and Post-Access Activity) which has the following Windows analytics associated:
                - AN0931 descibed as: "Remote Desktop (RDP) logon by a user followed by unusual process execution, file access, or lateral movement activity within a short timeframe." With mutable elements:
                        . TimeWindow: Temporal threshold to correlate login with post-login activity (e.g., 5 minutes)
                        . UserContext: Tune for non-admin users or service accounts expected to use RDP
                        . ProcessList: Define suspicious post-login processes such as cmd.exe, powershell.exe, certutil.exe
                        . HostAccessPatterns: Scope detection to uncommon or first-time access between source and destination hosts


The attack pattern T1562.001-Disable or Modify Tools is described as:
"Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or configuration files so that tools do not operate properly, or other methods to interfere with security tools scanning or reporting information. Adversaries may also disable updates to prevent the latest security patches from reaching tools on victim systems.(Citation: SCADAfence_ransomware)
"




The attack pattern T1071.001-Web Protocols is described as:
"Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.
"


        The attack pattern T1071.001 is detected using DET0027 (Detection of Web Protocol-Based C2 Over HTTP, HTTPS, or WebSockets) which has the following Windows analytics associated:
                - AN0075 descibed as: "Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs." With mutable elements:
                        . ProcessNameExclusions: Filter out legitimate browser/network utilities
                        . UserAgentAnomalies: Detect non-browser user-agents or spoofed headers
                        . OutboundByteRatioThreshold: Flag when outbound > inbound volume by 90%+
```


# Question:

Tell for this attack patterns: ['attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', 'attack-pattern--eb062747-2193-45de-8fa2-e62549c37ddf', 'attack-pattern--ac08589e-ee59-4935-8667-d845e38fe579', 'attack-pattern--29be378d-262d-4e99-b00d-852d573628e6', 'attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161', 'attack-pattern--4fe28b27-b13c-453e-a386-c2ef362a573b', 'attack-pattern--92d7da27-2d91-488e-a00c-059dc162766d', 'attack-pattern--b80d107d-fa0d-4b60-9684-b0433e8bdba0', 'attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807']
Knowing these are associated with a vulnerability that has 0.988 epss value, which information would you consider for the NetworkConnect portion of a sysmon configuration file?

---

# With Kag

To determine the `NetworkConnect` portion of a Sysmon configuration, we must identify which attack patterns involve network activity and what specific indicators (ports, processes, or behaviors) are mentioned in their corresponding detection analytics.

Based on the provided context, here is the breakdown of the relevant information for the `NetworkConnect` configuration:

### 1. Relevant Attack Patterns & Analytics
The following patterns explicitly mention network communications or outbound connections:

*   **T1190 (Exploit Public-Facing Application):**
    *   **Analytics (AN0219):** Focuses on outbound callbacks from server processes (e.g., `w3wp.exe`).
    *   *Config Insight:* Monitor network connections originating from web server process pools.
*   **T1059.001 (PowerShell):**
    *   **Analytics (AN1252):** Mentions PowerShell potentially followed by network connections.
    *   *Config Insight:* Monitor `powershell.exe` initiating network connections.
*   **T1021.001 (Remote Desktop Protocol):**
    *   **Analytics (AN0931):** RDP logins (typically TCP 3389).
    *   *Config Insight:* Track incoming/outgoing RDP traffic to identify unusual host-to-host access patterns.
*   **T1071.001 (Web Protocols):**
    *   **Analytics (AN0075):** High-volume HTTP/S/WebSocket traffic from suspicious processes like `powershell.exe` or `rundll32.exe`.
    *   *Config Insight:* Monitor common web ports (80, 443) specifically when the initiating process is a LOLbin.
*   **T1572 (Protocol Tunneling):**
    *   **Analytics (AN1483):** Specifically names `plink.exe`, `ssh.exe`, and `netsh.exe` establishing outbound connections. Mentions RDP over SSH.
    *   *Config Insight:* Monitor network connections from SSH/tunneling binaries.
*   **T1041 (Exfiltration Over C2 Channel):**
    *   **Analytics (AN0988):** Suspicious volume over HTTPS, DNS, or custom TCP/UDP ports.
    *   *Config Insight:* Monitor for atypical destination ports and non-browser processes using web ports.
*   **T1567 (Exfiltration Over Web Service):**
    *   **Analytics (AN1511):** Outbound HTTPS connections from processes like Word, Excel, or PowerShell to cloud services (Dropbox, Google Drive, OneDrive).
    *   *Config Insight:* Monitor HTTPS traffic originating from Office applications and scripting engines.

### 2. Summary for Sysmon `NetworkConnect` Configuration

To cover these patterns (especially given the high EPSS value of the associated vulnerability), your configuration should focus on the following:

**A. Process-Based Filtering (Who is connecting):**
*   **Web Server Processes:** `w3wp.exe` (T1190).
*   **Living-off-the-Land Binaries (LOLbins):** `powershell.exe`, `rundll32.exe`, `certutil.exe` (T1059.001, T1071.001, T1567).
*   **Office Applications:** `winword.exe`, `excel.exe` (T1567).
*   **Tunneling Tools:** `plink.exe`, `ssh.exe`, `netsh.exe` (T1572).

**B. Port and Protocol Focus (Where/How they are connecting):**
*   **Web Traffic:** Ports 80, 443 (T1071.001, T1041, T1567).
*   **Management/Remote Access:** Port 3389 (T1021.001).
*   **DNS/Custom:** Monitor for non-standard ports used for C2 (T1041).

**C. Exclusions (Noise Reduction):**
*   Exclude known legitimate browser processes (e.g., `chrome.exe`, `firefox.exe`) from the "suspicious web traffic" alerts to reduce false positives, as suggested by AN0075.

**Note:** The patterns **T1562.001**, **T1497.001**, and **T1486** are primarily host-based (registry, file system, and system checks) and do not provide specific requirements for the `NetworkConnect` configuration.


### Time it took: 1 minutes and 21 seconds ( 15 seconds LLM + 1 min 7 seconds for context building)

---

# Wihout KAG

This set of MITRE ATT&CK techniques describes a high-criticality attack chain: it starts with an **Exploit Public Facing Application (T1190)**, moves into **Command Execution (T1059.001)**, establishes **C2 communication (T1071.001)**, and ends with **Data Exfiltration (T1041)** and **Impact/Destruction (T1486/T1572)**.

An **EPSS value of 0.988** is extremely high, indicating a near-certainty that this vulnerability is being exploited in the wild.

For the `NetworkConnect` portion of a Sysmon configuration, you need to focus on detecting the "bridge" between the vulnerable application and the external attacker. Here is the specific information you should consider:

### 1. The "Unexpected Parent" Pattern (Crucial)
The most critical detection for `T1190` (Exploit Public Facing App) is when a web server or database process suddenly initiates a network connection to an external IP.
*   **What to monitor:** Connections initiated by `w3wp.exe` (IIS), `httpd.exe` (Apache), `nginx.exe`, `sqlservr.exe`, or `tomcat.exe`.
*   **Logic:** Under normal conditions, a web server *receives* connections; it rarely *initiates* outbound connections to unknown remote ports (which would indicate a Reverse Shell or C2 beacon).

### 2. Command & Control (C2) Infrastructure (`T1071.001`, `T1021.001`)
Since the attack involves Remote Desktop (`T1021.001`) and Standard Application Layer Protocols (`T1071.001`), you must monitor for non-standard port usage.
*   **Target Ports:**
    *   **TCP 3389:** Monitor for unexpected internal lateral movement via RDP.
    *   **TCP 443/80:** While common, look for connections to IPs with no associated DNS name or connections to known "cheap" VPS hosting providers.
    *   **DNS (UDP 53):** Monitor for high-frequency connections to a single external domain (DNS Tunneling/C2).

### 3. Exfiltration Channels (`T1041`)
`T1041` involves transferring data over the network.
*   **Volume-based Monitoring:** While Sysmon doesn't track byte count, you should monitor for connections to cloud storage APIs (AWS S3, Mega.nz, Dropbox) or Pastebin-like sites originating from servers that have no business talking to those services.
*   **Protocol Mismatch:** Connections over ports that do not match the expected service (e.g., SSH over port 443).

### 4. The "Living off the Land" Networkers
Attackers often use built-in tools to move data or download payloads (`T1567`).
*   **Binary Monitoring:** Configure `NetworkConnect` to alert when the following binaries initiate a network connection:
    *   `certutil.exe` (Commonly used to download payloads)
    *   `powershell.exe` / `pwsh.exe`
    *   `bitsadmin.exe`
    *   `curl.exe` / `wget.exe`
    *   `msbuild.exe`

---

### Summary Table for Sysmon `NetworkConnect` Configuration

| Focus Area | Process/Image to Filter | Logic/Alert Trigger | MITRE Mapping |
| :--- | :--- | :--- | :--- |
| **Web/App Server** | `w3wp.exe`, `tomcat.exe`, `sqlservr.exe` | Any `DestinationPort` $\neq$ 80, 443 (Outbound) | T1190 $\rightarrow$ T1071 |
| **LOLBins** | `certutil.exe`, `powershell.exe` | Any outbound connection to external IP | T1567 $\rightarrow$ T1071 |
| **Admin Tools** | `mstsc.exe`, `plink.exe` | Unexpected internal $\rightarrow$ internal connection | T1021.001 |
| **C2 Beaconing** | All | Connection to IPs with no Reverse DNS | T1071.001 |

### Recommended Sysmon XML Logic Snippet:
When writing your config, use a **Group** that excludes known-good update services but flags the "Dangerous Binaries" list:

```xml
<NetworkConnect onmatch="include">
  <!-- Alert on Web Server initiating outbound connections -->
  <Image condition="contains">w3wp.exe</Image>
  <Image condition="contains">sqlservr.exe</Image>
  <!-- Alert on LOLBins using the network -->
  <Image condition="contains">certutil.exe</Image>
  <Image condition="contains">powershell.exe</Image>
</NetworkConnect>
```

**Final Warning:** Because the EPSS is 0.988, you should prioritize **blocking** these behaviors at the firewall/EDR level rather than just **logging** them in Sysmon, as the probability of exploitation is extremely high.

### Time it took: 0 minutes and 25 seconds



# Conclusions:


- Time is a metric to consider, building the context envolves using API's to automatically retrieve information or traverse a large DB
- The `KAG` had much more founded information, always referring the analytics or attack patterns. E.g. office applications (T1567), usage of `ssh.exe`, or `netsh.exe` (T1572) or using `rundll32` (T1071.001) that the other LLM did ont use
- Contrary of what I initially thought the large portion of context doesn't seem to affect the performance of the LLM, on the contrary
- The `no KAG` version had to be general and referred indicators of compromisse with no referencing
- The `KAG` LLM tried to exemplify a simples snippet of the NetworkConnect sysmon portion, but it could hinder the performance of the next LLM in the pipeline

# What to do now?

- Since it consumed to much context and it still improved in performance, I think I can dump more context and see how far I can get away with
- The host context must surely be considered. It can be one of two results then: (1) The AI figures out there is much information to monitor that the host does not have and so it points that out or (2) it considers that the risk is too high to take granted and monitors it anyways. 
- Seeing the effects of considering a high or low epss and percentile score.
- The threat modelling context must be considered. And I hope, when adding the vulnerabilities, the AI can notice that. I could do a scenario where confidentiality is not a concern and availability is. I would test the AI to see if, somehow, lowers the monitoring complexity of attack patterns that affect confidentiality and prioritizes attack patterns affecting availability.