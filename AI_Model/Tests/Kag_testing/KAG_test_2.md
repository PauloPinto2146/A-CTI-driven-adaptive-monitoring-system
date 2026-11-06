# Test 2 with KAG - With and without more context?


In this test I will be anlaysing the result from the LLM `gemma4:31b-cloud` with only **attack-pattern** context and other with **attack-pattern + Ioc + vulnerability (and weakness)** context.
This test is meant to answer a few questions that I consider to be relevant for this problem:
- Does adding more context hinder or enhance the final result?
- Does adding additional context makes it so the attack pattern analysis is not as accurate/deep as the attack-pattern only context?
- What is the effect on time?



# Attack-pattern only context

Based on the provided context, the following information should be considered for the `NetworkConnect` portion of a Sysmon configuration file to support the detection of these attack patterns:

### 1. Process Monitoring (What to track)
You should configure Sysmon to monitor network connections from the following processes, as they are explicitly linked to the detection analytics:
*   **Web Server/Service Processes:** `w3wp.exe` and other service processes (associated with **T1190** / AN0219).
*   **Shells and Scripting Engines:** `powershell.exe` (associated with **T1059.001** / AN1252, **T1071.001** / AN0075, and **T1567** / AN1511).
*   **System Utilities/LOLbins:** `rundll32.exe` (**T1071.001**), `plink.exe`, `ssh.exe`, and `netsh.exe` (**T1572** / AN1483).
*   **Productivity Applications:** `Excel.exe` and `Word.exe` (associated with **T1567** / AN1511).

### 2. Traffic Patterns and Destinations (What to alert/filter)
The analytics highlight specific network behaviors that require visibility via `NetworkConnect` events:
*   **C2 and Exfiltration Channels:** Connections over HTTPS, DNS, or custom TCP/UDP ports (**T1041** / AN0988 and **T1071.001** / AN0075).
*   **Web Services:** Traffic directed toward legitimate cloud storage providers such as Dropbox, Google Drive, and OneDrive (**T1567** / AN1511).
*   **Public Facing Endpoints:** Traffic interacting with `PublicVIPs` (the list of public IPs/hostnames fronting applications) to correlate request patterns (**T1190** / AN0219).
*   **Tunneling Activity:** Connections originating from tunneling tools that may exhibit port usage mismatches or asymmetric data flows (**T1572** / AN1483).

### 3. Analysis Metrics (Data to correlate)
While Sysmon's `NetworkConnect` event provides the "who" and "where," the context indicates you must correlate these events with other logs to meet the detection thresholds:
*   **Data Volume/Ratio:** Monitor for high outbound-to-inbound byte ratios (e.g., outbound > 90%) for **T1071.001**, **T1572**, **T1041**, and **T1567**.
*   **Temporal Correlation:** Use the `TimeWindow` mentioned in several analytics (e.g., 15 minutes for T1190 or 5 minutes for T1021.001) to link a network connection to a preceding process spawn or error.

***Note:** For attack patterns **T1562.001** and **T1497.001**, the provided context does not list any associated Windows analytics or network-based detection markers; these appear to be host-based activities (registry/file/process checks).*

### Time it took: 59 seconds (building context) + 8 seconds (LLM)


---

# Attack-pattern + Ioc + vulnerability (and weakness) context 

Based on the provided context, the following information should be considered for the `NetworkConnect` portion of a Sysmon configuration file to detect the specified attack patterns, indicators, and vulnerabilities:

### 1. Specific Indicators of Compromise (IoCs)
The configuration should explicitly monitor for outbound connections to the reported malicious source IPs:
*   **IP Addresses:** `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`.

### 2. Process-to-Network Correlations (Attack Pattern Mapping)
Several analytics describe specific processes that should be monitored when initiating network connections:

*   **C2 and Exfiltration (T1071.001, T1041, T1567):**
    *   Monitor `powershell.exe` and `rundll32.exe` initiating network connections (per **AN0075** and **AN1511**).
    *   Identify connections from processes that "normally do not initiate network communications" (e.g., `WinWord.exe`, `Excel.exe`) toward common web services like Dropbox, Google Drive, or OneDrive.

*   **Exploitation and Post-Exploit Egress (T1190 / CVE-2023-48788):**
    *   Monitor the network activity of the server process (e.g., `w3wp.exe` or the FortiClientEMS service) specifically after a shell or LOLbin has been spawned (per **AN0219**).
    *   Since CVE-2023-48788 allows unauthorized code execution via the network, monitoring any unexpected outbound connections from the affected application is critical.

*   **Protocol Tunneling (T1572):**
    *   Monitor connections established by `plink.exe`, `ssh.exe`, and `netsh.exe` (per **AN1483**), particularly those exhibiting asymmetric data flows.

### 3. Behavioral Logic for Filtering/Alerting
While Sysmon configuration files primarily use inclusions/exclusions, the following logic should guide the `NetworkConnect` rules:

*   **Anomalous Destinations:** Flag connections to "unusual domains or IPs" that do not match known benign update services (per **AN0988** and **AN0075**).
*   **C2 Protocols:** Focus on common web protocols (HTTP/S, WebSockets) and custom TCP/UDP ports used for C2 (T1071.001, T1041).

### Summary Table for Configuration Implementation

| Sysmon Field | Value / Logic to Include | Associated Attack Pattern / Vulnerability |
| :--- | :--- | :--- |
| `DestinationIp` | The 7 listed malicious IPs | General IoC / C2 |
| `Image` | `powershell.exe`, `rundll32.exe`, `plink.exe`, `ssh.exe`, `netsh.exe`, `w3wp.exe` | T1071.001, T1572, T1190 |
| `Image` | Office Apps (`winword.exe`, `excel.exe`) | T1567 (Exfiltration) |
| `DestinationPort` | 80, 443, and custom C2 ports | T1071.001, T1041 |

### Time it took: 1min and 26 seconds (building context) + 14 seconds (LLM)


# Questions answered:

- **Does adding more context hinder or enhance the final result?**
A.: Yes, it added specific IP addresses to consider network connections to and it added the CVE-2023-48788 part where it specifically says to monitor unauthorized code execution via the network, enriching the LLM analysis

- Does adding additional context makes it so the attack pattern analysis is not as accurate/deep as the attack-pattern only context?
A.: Not at all, the `all context` approach considered everything the other did (in terms of indicators of compromise linked to attack pattern) and, contrary to the `attack-pattern context`, it did ont add additional information outside of the sysmon monitoring theme (the first approach tried to suggest data correlation which is outside of the problem's scope). Additionally it made a table resuming all the information that could be actionable.

- What is the effect on time?
A.: It takes ~1.5x more time but (almost 1.5x in context building and 2x LLM processing) 


Overall, this test shows that the context can hold very much information still

# What to do next

- I will try to introduce even more context, namely the current host context
- Try to introduce the LLM that produces the sysmon config file portion to see real result
- Start developing a way to introduce threat and risk context, namely what is the function of the host, the impact it has with its downfall and the security properties it is most sensible to (for example a database prioritizes integrity and confidentiality but it may not prioritize availability)
- Probably do some prompt engineering since it has been just a dump of information until this point