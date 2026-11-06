# Test 6.1

I started to notice that the context has been bigger and bigger and I can feel that the first improvements are not so impactful anymore and I asked myself "The first prompt is given to the second LLM as chat history, does it have any effect on the final result?"

So, this intermidiate test have two use cases:

  - The second LLM has chat history
  - The second LLM does NOT have chat history

To see if the context of the first prompt has any effect on the final sysmon configuration file.
To make it fair, I will be giving both second LLMs the same security analysis.

I will be answering:

1. Does the LLM without chat history has any good effects on the final result?
2. What LLM produces a more accurate representation of the security analysis?
3. Does the LLM with chat history seem to have a better knowledge of the situation that the one without?


----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Based on the provided attack patterns, IoCs, and vulnerability context, the following elements must be monitored via Sysmon **Event ID 3 (NetworkConnect)** to detect the identified threats on a high-exposure server:

### 1. High-Priority Indicator Matching (Direct Threat)
Monitor for any `DestinationIp` matching the reported IoCs. These connections indicate direct communication with known malicious infrastructure:
*   **Target IPs:** `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`.

### 2. Exploit-Driven Network Activity (T1190 & CVE-2023-48788)
Since the server is highly exposed and vulnerable to CVE-2023-48788 (SQL Injection leading to RCE), monitor for anomalous network connections initiated by the application process:
*   **Source Process:** `w3wp.exe` or the specific FortiClientEMS service process.
*   **Behavior:** Outbound connections to any external IP immediately following the exploitation of the public-facing vulnerability (Post-exploit egress).

### 3. Living-off-the-Land (LotL) & C2 Communication (T1059.001, T1071.001, T1572)
Monitor for network connections initiated by processes that should not typically generate external web traffic:
*   **Suspicious Processes:** `powershell.exe`, `rundll32.exe`, `cmd.exe`, `certutil.exe`, `plink.exe`, `ssh.exe`, `netsh.exe`.
*   **Destination Ports:** `443` (HTTPS), `80` (HTTP), and high-numbered ports used for tunneling or C2.
*   **Behavior:** Establish a baseline for these processes; any connection to an external IP not in a known-good list should be flagged.

### 4. Data Exfiltration (T1041, T1567)
Monitor for high-volume data transfers or connections to legitimate cloud storage services initiated by non-standard processes:
*   **Target Domains/IPs:** Connections to known web services (e.g., Dropbox, Google Drive, OneDrive).
*   **Source Processes:** `powershell.exe`, `Excel.exe`, `Word.exe` (indicating potential macro-based exfiltration).
*   **Metric:** Correlate `NetworkConnect` events with high outbound byte counts relative to inbound traffic.

### 5. Remote Access & Lateral Movement (T1021.001)
Monitor for inbound/outbound RDP traffic originating from or destined for unusual internal/external segments:
*   **Destination Port:** `3389`.
*   **Context:** Correlate these connections with subsequent `ProcessCreate` events involving `cmd.exe` or `powershell.exe`.



#### Time it took: 0 minutes and 7 seconds

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# With chat history

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Security_Analysis_Network_Monitoring" groupRelation="or">
      <!--
      Include: High-Priority IoCs
      Directly matching reported malicious IP addresses
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
      Include: Living-off-the-Land (LotL) Binaries
      Monitoring processes that should not typically initiate external connections
      T1059.001 (PowerShell), T1071.001 (Web Protocols), T1572 (Tunneling), T1218 (Proxy Execution)
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
      Include: Remote Access & Management
      T1021.001 (RDP) and others used for lateral movement or remote C2
      -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">22</DestinationPort>
      </NetworkConnect>

      <!--
      Exclude: Known Benign Application Traffic
      Reducing noise from installed software identified in the host state
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">OneDrive.exe</Image> <!-- Microsoft OneDrive -->
        <Image condition="image">firefox.exe</Image> <!-- Mozilla Firefox -->
        <Image condition="image">msedge.exe</Image> <!-- Microsoft Edge -->
        <Image condition="image">ollama.exe</Image> <!-- Ollama AI -->
        <Image condition="image">zotero.exe</Image> <!-- Zotero -->
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
ANALYSIS SUMMARY:
1. INCLUSIONS:
   - IoCs: Added a direct filter for the 7 reported malicious source IPs to catch any connection to known threat infrastructure.
   - LotL Binaries: Included powershell.exe, rundll32.exe, certutil.exe, and cmd.exe as they are primary vectors for T1059.001 and T1071.001.
   - Tunneling Tools: Included plink.exe and ssh.exe to detect T1572 (Protocol Tunneling).
   - Remote Ports: Monitored 3389 (T1021.001) and 22 (SSH) due to the high-exposure nature of the server.

2. EXCLUSIONS:
   - Browser/Cloud Noise: Excluded firefox.exe, msedge.exe, and OneDrive.exe. Since the server has high network exposure, these generate massive volumes of legitimate HTTPS traffic (Port 443) which would mask the "needle" of C2 traffic.
   - Host-Specific Apps: Excluded Ollama and Zotero to prevent noise from legitimate application updates or API calls.

3. NOISE REDUCTION:
   - Avoided generic port-only includes (like 8080) to prevent flagging every web-service communication.
   - Focused on "Process + Network" correlations by prioritizing suspicious images over common ports.
-->
```



#### Time it took: 0 minutes and 18 seconds

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# NO chat history 

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Threat_Detection_Network" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- 1. High-Priority IoC Matching: Direct communication with known malicious infrastructure -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>

        <!-- 2. Living-off-the-Land Binaries (LotL) performing network activity (T1059.001, T1218, T1071.001) -->
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>

        <!-- 3. Remote Access & Lateral Movement (T1021.001) -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Services" condition="is">22</DestinationPort>

        <!-- 4. Non-Standard C2 Ports (T1571) -->
        <DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is any">4444;31337;6667;5555;5353</DestinationPort>

        <!-- 5. Suspicious Execution Paths (T1036 - Masquerading) -->
        <!-- Monitoring binaries executing from Temp or User AppData making network connections -->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Roaming\</Image>
      </NetworkConnect>
    </RuleGroup>

    <RuleGroup name="Noise_Reduction" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <!-- Excluding legitimate installed software based on host state to reduce noise -->
        <Image condition="image">OneDrive.exe</Image> <!-- Installed: Microsoft OneDrive -->
        <Image condition="image">firefox.exe</Image> <!-- Installed: Mozilla Firefox -->
        <Image condition="image">msedge.exe</Image> <!-- Installed: Microsoft Edge -->
        <Image condition="image">ollama.exe</Image> <!-- Installed: Ollama -->

        <!-- Exclude local loopback noise for common application services -->
        <Rule groupRelation="and">
          <DestinationIp condition="is">127.0.0.1</DestinationIp>
          <DestinationPort condition="is any">11434;58897;58898;56152</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
EXPLANATION OF CONFIGURATION:
1. INCLUSIONS:
   - IoCs: Explicitly included the list of malicious IPs provided in the analysis to detect immediate threats.
   - LotL Binaries: Included processes like powershell.exe and certutil.exe because they are frequently used for C2 communication or downloading second-stage payloads (T1071.001).
   - Remote Access: Monitored port 3389 (RDP) and 22 (SSH) to detect potential lateral movement or unauthorized external access (T1021.001).
   - Non-Standard Ports: Included common exploit/C2 ports (e.g., 4444 for Metasploit) to catch reverse shells (T1571).
   - Masquerading: Targeted binaries running from Temp and AppData folders, as these are high-entropy paths for malware delivery (T1036).

2. EXCLUSIONS:
   - Validated Software: Excluded browser (Firefox, Edge) and OneDrive traffic to prevent flooding the logs with standard HTTPS traffic.
   - Local Traffic: Based on the host's 'ESTABLISHED' ports, there is significant loopback traffic on ports like 11434 (Ollama) and 58897. These were excluded using an 'and' rule to ensure we only ignore local traffic and still alert if these ports are accessed externally.
-->
```


#### Time it took: 1 minutes and 17 seconds

---


# Questions answered

IMPORTANT NOTE before going into questions.
Just noticed that some security reports mention "non-standard ports" in a section with "(T1572 / T1021.001)". There is a technique "T1571 - Non-Standard Port", but it was not reported. I feel like the LLM producing the security analysis itself is starting to become more and more confused. Additionally some LLMs add section unrelated with sysmon, like detection mechanisms and tips do correlate information, while sysmon is just a tool that is meant to capture information. I'm starting to feel like the context window may be reaching a limit

1. Does the LLM without chat history has any good effects on the final result?
A.: It was more creative, or rather, tried to fill gaps that it did not have context such as monitoring common C2 ports (4444, 31337, 5555) that are generic and can be useful in a threat hunting scenario. Also, the "no history" version introduced:

- T1571 (Non-Standard Port)
- T1036 (Masquerading)
- Temp/AppData monitoring
- Loopback exclusions

None of these were mentioned in the security analysis, but are mentioned in the examples. It seems as if it has no context of before it tries to mimic some of the answers seen in the examples given only meant to syntax.

2. What LLM produces a more accurate representation of the security analysis?
A.: The LLM with chat history produced the more accurate representation. The LLM without it produced rules that were directly associated with the examples given

3. Does the LLM with chat history seem to have a better knowledge of the situation that the one without?
A.: Yes. The version with chat history appears to understand that the objective is to convert a previous threat analysis into a Sysmon configuration rather than generate a generic detection engineering proposal.

# Conclusions and future steps

- The examples created by Olaf Hartong are confusing the LLMs. The idea was just to be a syntax example, but many times it uses, e.g., T1571 to seek for an attack pattern that was not reported. So the next step may be to reform the way I give examples to it, so it only includes reported techniques in 2 ways:
    - Reduce the number of examples I give;
    - **Be explicit about it can only make rules for the reported techniques and nothing more.**

- The chat history seems to have better consistency and adherence to the analyst's intent. So I will not try to remove the first prompt from the chat history.
- For the dissertation, this is actually a valuable result because it suggests that context accumulation can improve situational awareness while simultaneously increasing semantic drift, creating a trade-off between contextual understanding and analytical precision. That's a much stronger research finding than simply "chat history is better" or "chat history is worse."

May be worth to test 4 different scenarios:

| Test case | Examples | Explicit restriction instruction |
| --------- | -------- | -------------------------------- |
| A         | Various  | No                               |
| B         | Various  | Yes                              |
| C         | Few      | No                               |
| D         | Few      | Yes                              |

This would certainly tell me if the problem is really having too much examples or just not handling the problem by prompt engineering.

- Another thing I noticed was that both LLMs included and then excluded. Which is redundant in their examples. The included information is the only thing logged, the exclusion rules would not have any effect by logic. Probably was because I asked it to explain the inclusion and exclusions that he made, but never meant the inclusion and exclusion of sysmon. That is a thing to note.