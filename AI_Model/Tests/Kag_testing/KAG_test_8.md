# Test 8

I divided the workload once between different types of sysmon monitoring tags (NetworkConnect, ProcessCreate, etc) and always thought to (if necessary) divide even further, in this case, each attack pattern would have an especialized LLM to produce a snipet of the whole rule. 
In this test I will try to consider a handfull of techniques and have 4 use cases:

The attack pattern descriptions and detections strategies are
- **A**: Just dumped and used as context for the NetworkConnect rule 
- **B**: Divided and processed by one specialized LLM that creates a portion of the whole NetworkConnect rule
- **C**: Number 1 BUT with CAPEC related attack patterns of the CVE
- **D**: Number 2 BUT with CAPEC related attack patterns of the CVE
The CVE can be mapped into CWE's (the weaknesses associated with the vulnerability) and each CWE can be mapped further into related CAPEC attack patterns, which can be helpful to implement monitoring sensors specifically for the CVE at hand.

As I asked the LLM to identify the rule names by the techniques used I hope to be able to compare each implementation of an attack pattern. Besides quality of the rule I will also be considering the overall time taken and balance the impact of diving the workload even further.

As always I will be answering some question to evaluate this test:

- Does the "divide & conquer" strategy made better rules for each technique?
- Is the IoCs used in any different way on the many LLM responses?
- What is comparison of time?
- Does adding more context with CAPEC-related techniques helped the final result? 


----------------------------------------------------

# A. Dumping the context for NetworkConnect Rule (['T1190', 'T1021.001', 'T1071.001', 'T1572', 'T1041', 'T1567'])

```
Monitor NetworkConnect events for the following specific criteria to detect potential exploitation and post-compromise activity:

1. Source IP Filtering
Monitor all inbound and outbound connections involving the following suspicious source IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. Exploit Public-Facing Application (T1190) / CVE-2023-48788
Monitor for network connections established by server processes (e.g., w3wp.exe or other service-specific binaries) following an inbound request from the listed suspicious IPs, specifically focusing on:
- New outbound connections immediately following a request that resulted in high 4xx/5xx errors.
- Outbound callbacks from processes that typically do not initiate network traffic.

3. Command and Control & Exfiltration (T1071.001, T1041, T1567)
Monitor for abnormal network connections to known web services (Google Drive, Dropbox, OneDrive) or unusual remote addresses (e.g., 52.123.144.190, 4.207.247.139, 34.107.243.93, 34.36.133.15) initiated by:
- Non-browser processes (e.g., powershell.exe, rundll32.exe, cmd.exe).
- Processes with high outbound-to-inbound data volume ratios.

4. Protocol Tunneling (T1572)
Monitor for outbound connections on common ports (443, 80) initiated by binaries associated with tunneling or remote administration:
- plink.exe
- ssh.exe
- netsh.exe

5. Remote Access (T1021.001)
Monitor for RDP-related network connections (Port 3389) originating from the reported suspicious IPs or unusual source hosts, particularly when correlated with the subsequent execution of suspicious processes (cmd.exe, powershell.exe).
```
#### Time it took: 0 minutes and 11 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Network Analysis" groupRelation="or">
      <!-- T1190 & CVE-2023-48788: Exploit Public-Facing Application -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
          <Image condition="is not">C:\Windows\System32\lsass.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- T1071.001, T1041, T1567: Web Protocols, Exfiltration Over C2/Web Service -->
      <NetworkConnect onmatch="include">
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\powershell.exe;C:\Windows\System32\rundll32.exe;C:\Windows\System32\certutil.exe</Image>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>
        <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
          <Image condition="image">python.exe</Image>
          <DestinationIp condition="is any">52.123.144.190;4.207.247.139;34.107.243.93;34.36.133.15;142.251.27.93;52.112.100.65</DestinationIp>
        </Rule>
      </NetworkConnect>

      <!-- T1572: Protocol Tunneling -->
      <NetworkConnect onmatch="include">
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="and">
          <Image condition="is any">plink.exe;ssh.exe;netsh.exe</Image>
          <DestinationPort condition="is any">443;80;22</DestinationPort>
        </Rule>
      </NetworkConnect>

      <!-- T1021.001: Remote Desktop Protocol -->
      <NetworkConnect onmatch="include">
        <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Implementation Detail:
- Used: Suspicious Source IPs from IoCs context for T1190 and T1021.001 to correlate inbound threats.
- Used: High-risk LOLbins (cmd, powershell, rundll32, certutil) connecting via port 443 to detect T1071.001/T1041.
- Used: Python.exe (present in running processes) communicating with flagged remote addresses to detect T1567.
- Used: Tunneling binaries (plink, ssh, netsh) combined with standard ports for T1572.
- Used: Port 3389 combined with suspicious IoC IPs for T1021.001.
- Not used: General port 8080/1080 monitoring to avoid noise as requested.
- Not used: Broad "begin with C:\Users" rules to maintain focus strictly on the provided attack patterns and identified indicators.
-->
```

#### Time it took: 0 minutes and 21 seconds

----------------------------------------------------

# B. Divide & Conquer

## T1190 
```
Monitor Sysmon Event ID 3 (NetworkConnect) for the following conditions to detect attack pattern T1190 via exploitation of CVE-2023-48788:

1. Destination IP Addresses: Monitor for any network connections established by the server to the known malicious source IPs (acting as C2 or exfiltration endpoints): 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, 206.123.145.13.

2. Source Image Process: Filter for NetworkConnect events where the Image field corresponds to the FortiClientEMS process or common web-facing service processes (e.g., w3wp.exe). Specifically, monitor for these processes initiating outbound connections, as this indicates a potential post-exploit callback or reverse shell following the SQL injection.

3. Anomalous Outbound Ports: Monitor for connections from the FortiClientEMS service to non-standard ports or common C2 ports, correlating with the "optional outbound callback" described in the T1190 detection chain.

4. Correlation Logic: A NetworkConnect event is highly suspicious if it occurs within a 15-minute window (TimeWindow) following a process spawn event (Event ID 1) where the parent process is a web-facing application and the child process is a shell (cmd.exe, powershell.exe) or a LOLbin.
```
#### Time it took: 0 minutes and 8 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="T1190_Exploit_Public_Facing_Application" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- CVE-2023-48788: Monitor for callbacks to known malicious IoCs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>

        <!-- T1190: Monitor for shells or LOLbins initiating outbound network connections post-exploit -->
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1218,technique_name=Regsvr32" condition="image">regsvr32.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
Security Analysis Implementation Details:
- Used DestinationIp: Implemented 'is any' condition for the specific IoCs provided in the context to catch C2/egress callbacks.
- Used Image: Included cmd.exe, powershell.exe, and common LOLbins (msbuild, rundll32, mshta, regsvr32) as these are identified in the T1190 detection chain as typical child processes spawned by a compromised server process (like w3wp.exe) to establish a shell.
- Not Used:
    - General port monitoring (e.g., 8080, 4444): Omitted to avoid noise as per instructions, focusing instead on the specific IoCs and the processes likely to be used for callbacks.
    - FortiClientEMS process monitoring: While part of the vulnerability context, the current running processes list on the host does not show the FortiClientEMS service/process active; therefore, the rule focuses on the generic T1190 post-exploit indicators.
    - NetworkConnect 'exclude' rules: No exclusion rules were added as the goal was to create a targeted detection snippet for the specified attack pattern.
-->
```


#### Time it took: 0 minutes and 18 seconds

--------------------------------------------------------------------------------

## T1021.001 

To detect attack pattern T1021.001 (Remote Desktop Protocol) using Sysmon NetworkConnect (Event ID 3) on a high-exposure server, monitor the following:
```
1. Destination Port: 3389 (Default RDP port).
2. Source IP Addresses:
    - 185.216.70.170
    - 77.90.38.170
    - 154.216.19.224
    - 154.216.17.157
    - 176.65.141.201
    - 176.65.141.232
    - 206.123.145.13
3. Process Correlation: Monitor NetworkConnect events where the Image field is 'TermService.exe' (Remote Desktop Services) and correlate these connections with subsequent Sysmon Event ID 1 (Process Creation) for suspicious binaries: cmd.exe, powershell.exe, and certutil.exe.
```
#### Time it took: 0 minutes and 5 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Remote Services" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1021.001: Remote Desktop Protocol -->
        <Rule groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>
        <Image name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="image">TermService.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Security Analysis Implementation Notes:
- Used: DestinationPort 3389 to target RDP traffic.
- Used: SourceIp list containing the specific IoCs provided in the context to reduce noise and increase precision.
- Used: Image 'TermService.exe' to monitor the RDP service process specifically for this attack pattern.
- Not Used: CVE-2023-48788 (SQL Injection) as it is not related to the T1021.001 RDP attack pattern requested.
- Not Used: Generic monitoring of cmd.exe, powershell.exe, or certutil.exe within NetworkConnect, as these are typically monitored via Process Creation (Event ID 1) and including them here without specific destination ports would create excessive noise on a high-exposure server.
-->
```
#### Time it took: 0 minutes and 7 seconds

--------------------------------------------------------------------------------

## T1071.001 
```
Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific criteria to detect attack pattern T1071.001 (Web Protocols) in the context of the provided threats:

1. Destination IP Addresses:
Filter for outbound connections to the following reported IoC IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. Suspicious Process Execution:
Monitor NetworkConnect events where the SourceImage (process) is not a standard web browser or legitimate network utility. Specifically flag connections initiated by:
- powershell.exe
- rundll32.exe
- cmd.exe
- wscript.exe / cscript.exe
- mshta.exe

3. Port and Protocol Alignment:
Monitor connections on DestinationPort 80, 443, or ports associated with WebSockets, especially when originating from the suspicious processes listed above.

4. Target Correlation (Vulnerability Context):
Since CVE-2023-48788 allows remote code execution via SQL injection on FortiClientEMS, monitor for the FortiClientEMS process initiating unexpected outbound network connections to the IoC IPs or external cloud providers (Azure, Google, Cloudflare), as this indicates a successful exploitation leading to a C2 callback.
```
#### Time it took: 0 minutes and 8 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="T1071.001_Web_Protocols" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Detection of Web Protocol-Based C2 (T1071.001) targeting known IoC IPs -->
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- Detection of Web Protocol-Based C2 (T1071.001) via LOLBins on web ports -->
        <Rule groupRelation="and">
          <Image condition="is any">powershell.exe;rundll32.exe;cmd.exe;wscript.exe;cscript.exe;mshta.exe</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- Detection of post-exploitation callback following CVE-2023-48788 execution -->
        <!-- Monitoring for unexpected network activity from the target vulnerable application -->
        <Rule groupRelation="and">
          <Image condition="image">FortiClientEMS.exe</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Security Analysis Implementation Notes:
- Used: DestinationIp filtering for all 7 reported IoC IPs associated with the Medium threat level.
- Used: Image filtering for the identified LOLBins (powershell, rundll32, cmd, wscript, cscript, mshta) specifically when connecting via ports 80/443 to reduce noise.
- Used: Image filtering for 'FortiClientEMS.exe' to catch callbacks resulting from CVE-2023-48788.
- Used: DestinationPort constraints (80, 443) to strictly align with T1071.001 (Web Protocols).
- Not Used: General port 8080 or other non-standard ports to avoid noise, as per instructions.
- Not Used: Broad 'begin with' path rules (e.g., C:\Users) to maintain focus strictly on the specific attack pattern and provided IoCs.
-->
```

#### Time it took: 0 minutes and 29 seconds

--------------------------------------------------------------------------------

## T1572 

```
To detect the attack pattern T1572 (Protocol Tunneling) on a high-exposure server, monitor Sysmon Event ID 3 (NetworkConnect) for the following specific criteria:

1. Source Process Identification:
Monitor connections initiated by tools typically used for tunneling or shell redirection, specifically:
- plink.exe
- ssh.exe
- netsh.exe

2. Destination IP Filtering:
Cross-reference all outbound connections against the identified malicious IoC source IPs, as these may act as tunnel endpoints:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

3. Traffic Pattern Anomalies (Data Flow):
Analyze the NetworkConnect events for:
- Port usage mismatches: Connections where the destination port does not align with the standard protocol associated with the process (e.g., SSH process connecting to a non-standard port or an HTTP port).
- Asymmetric data flows: Large volumes of data sent versus received, indicating encapsulated traffic being tunneled out.

4. Vulnerability Correlation:
Given the high network exposure and the presence of CVE-2023-48788 (SQL Injection leading to remote code execution in FortiClientEMS), monitor for any NetworkConnect events where the SourceImage is associated with the FortiClientEMS process, especially if it initiates outbound connections to the listed IoC IPs or unusual ports, as this may indicate a successful exploit being used to establish a tunnel.
```
#### Time it took: 0 minutes and 5 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Protocol Tunneling Detection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1572: Monitor processes commonly used for tunneling -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1572: Correlation with reported malicious IoC endpoints -->
        <Rule groupRelation="or">
          <DestinationIp condition="is">185.216.70.170</DestinationIp>
          <DestinationIp condition="is">77.90.38.170</DestinationIp>
          <DestinationIp condition="is">154.216.19.224</DestinationIp>
          <DestinationIp condition="is">154.216.17.157</DestinationIp>
          <DestinationIp condition="is">176.65.141.201</DestinationIp>
          <DestinationIp condition="is">176.65.141.232</DestinationIp>
          <DestinationIp condition="is">206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1572 & CVE-2023-48788: Monitor FortiClientEMS for outbound tunneling activity following potential exploit -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="contains">FortiClientEMS</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
Analysis Implementation Details:
- Used: Monitored specific tunneling binaries (plink.exe, ssh.exe, netsh.exe) as identified in the attack pattern analysis.
- Used: Implemented a list of DestinationIp checks based on the provided Medium threat level IoCs.
- Used: Included the FortiClientEMS process to correlate potential RCE from CVE-2023-48788 leading to established tunnels.
- Not Used: Generic port monitoring (e.g., 8080, 443) was excluded to avoid noise, as the server has high network exposure and legitimate traffic on those ports.
- Not Used: Data asymmetry (bytes sent/received) and time-window correlation cannot be implemented via XML filtering rules as they require a SIEM/Analytics engine to process the event stream.
-->
```

#### Time it took: 0 minutes and 10 seconds
----------------------------------------------------

## T1041 
``` 
To detect the attack pattern T1041 (Exfiltration Over C2 Channel) on a high-exposure server, Sysmon NetworkConnect (Event ID 3) must be monitored for the following specific criteria:

1. Destination IP Addresses: Monitor for any outbound connections to the known C2 indicators: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, and 206.123.145.13.

2. Process Correlation: Filter for NetworkConnect events triggered by processes that do not typically generate network traffic. Specifically, monitor for processes that have recently accessed sensitive files or databases (indicative of the impact of CVE-2023-48788) and are now initiating outbound connections.

3. Protocol and Port Analysis: Focus on traffic over HTTPS (Port 443), DNS (Port 53), or custom TCP/UDP ports, as these are the primary vectors for encoding stolen data into C2 channels.

4. Traffic Volume and Frequency: Monitor for a high frequency of NetworkConnect events to the same destination where the cumulative data volume exceeds the typical C2 heartbeat (e.g., monitoring for outbound transfers >1MB within a 5-minute window).

5. Vulnerability Linkage: Prioritize monitoring of the FortiClientEMS process or any child processes spawned by the service, as CVE-2023-48788 allows unauthorized code execution which can lead to the establishment of the C2 channel used for exfiltration.
```

#### Time it took: 0 minutes and 7 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="T1041_Exfiltration_Over_C2_Channel" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Detect connections to known C2 infrastructure associated with the attack pattern T1041 -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>

        <!-- Monitor high-risk processes often used for C2/Exfiltration via Living off the Land, following potential exploitation of CVE-2023-48788 -->
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>

        <!-- Monitor processes initiating connections from suspicious temporary or user-writable directories typical of staged C2 binaries -->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\ProgramData\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
  Security Analysis implementation details:
  - Used: DestinationIp check for all provided IoCs to directly catch the C2 channel.
  - Used: Image monitoring for common proxy execution binaries (certutil, rundll32, mshta) and powershell, as these are frequently used to implement the encoding and transmission logic mentioned in T1041.
  - Used: Path monitoring for Temp and ProgramData directories to detect non-standard process locations communicating externally.
  - Not used: General port monitoring (e.g., 443, 8080) as this would generate excessive noise on a server with HIGH network exposure.
  - Not used: Data volume thresholds, as Sysmon Event ID 3 provides connection metadata but not cumulative byte counts (which requires a SIEM/log analyzer).
  - Not used: Exclusion of benign processes, as the 'include' logic already limits the scope to high-risk indicators.
-->
```
#### Time it took: 0 minutes and 11 seconds

----------------------------------------------------
## T1567 

```
Monitor Sysmon Event ID 3 (NetworkConnect) for the following criteria to detect T1567 (Exfiltration Over Web Service):

1. Destination IP Addresses:
Cross-reference DestinationIp with known legitimate web service ranges (Microsoft Azure, Google Cloud, GitHub, Cloudflare) as identified in the environment's network context, specifically targeting ports 443 and 80.

2. Source Process Correlation:
Monitor NetworkConnect events where the Image (process) is not a standard browser or system update service, but is instead an application like Word, Excel, PowerShell, or a process associated with FortiClientEMS (due to CVE-2023-48788 potential for unauthorized code execution).

3. Data Volume Analysis:
Track the bytes sent in the NetworkConnect stream. Flag anomalies where the outbound-to-inbound data ratio is high, exceeding the environment's ExfilVolumeThreshold within the defined TimeWindow.

4. High-Risk Indicators:
Alert on any NetworkConnect events where the DestinationIp matches the reported IoCs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, or 206.123.145.13.
```
#### Time it took: 0 minutes and 6 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Exfiltration Over Web Service" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1567: Monitoring anomalous processes initiating connections to common web services (Cloud/Web) -->
        <Rule groupRelation="and">
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\powershell.exe;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Users\Paulo\AppData\Local\Python\pythoncore-3.14-64\python.exe</Image>
          <DestinationPort condition="is any">443;80</DestinationPort>
        </Rule>

        <!-- T1567: Specifically monitoring tools often used for exfiltration in high-exposure environments -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">bitsadmin.exe</Image>

        <!-- T1567: Monitoring connections to reported malicious IoCs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Security Analysis Implementation Details:
1. Used: DestinationIp filtering for the provided IoC list to catch direct exfiltration to known malicious actors.
2. Used: Correlation between high-risk processes (cmd.exe, powershell.exe, python.exe) and common web ports (443, 80) to detect non-standard processes communicating with web services as described in AN1511.
3. Used: Monitoring of 'certutil.exe' and 'bitsadmin.exe' as these are common LOLBins used to facilitate the transfer of data to web services.
4. Not Used: Data volume thresholds (ExfilVolumeThreshold) and TimeWindow, as these are telemetry-level aggregation metrics that cannot be defined within a static Sysmon XML filter.
5. Not Used: General 'exclude' rules for OneDrive/Dropbox to avoid noise, as the request specified focusing on the attack pattern T1567 and avoiding noise-generating isolation rules.
6. Not Used: CVE-2023-48788 specific process monitoring for FortiClientEMS, as that software was not listed in the host's installed programs or running processes.
-->
```

#### Time it took: 0 minutes and 32 seconds


----------------------------------------------------

# C. Dumping the context for NetworkConnect Rule + CAPEC-related techniques

Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific criteria:

1. Target IP Address Matching:
Filter for outbound connections where the Destination IP matches the reported IoCs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, and 206.123.145.13.

2. Process-to-Network Correlation for T1190 (Exploit Public-Facing Application):
Monitor for network connections initiated by web server processes (e.g., w3wp.exe) or service-specific binaries associated with FortiClientEMS. Flag any outbound connection following the exploitation of CVE-2023-48788 (SQL Injection), specifically looking for egress to the listed IoC IPs or unusual external ports.

3. C2 and Exfiltration Detection (T1071.001, T1041, T1567):
Identify outbound connections to the listed IoC IPs or common cloud storage services (Dropbox, OneDrive, Google Drive) initiated by non-browser processes such as:
- powershell.exe
- cmd.exe
- rundll32.exe
- certutil.exe
- msbuild.exe

4. Protocol Tunneling Identification (T1572):
Monitor for outbound network connections initiated by tunneling tools such as:
- plink.exe
- ssh.exe
- netsh.exe
Specifically, look for these processes connecting to the listed IoC IPs or anomalous destination ports that indicate encapsulated traffic.

5. RDP Post-Access Activity (T1021.001):
Correlate network connections occurring immediately after an RDP session login, specifically those initiated by shells (cmd.exe, powershell.exe) targeting internal or external IPs.



#### Time it took: 0 minutes and 6 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Monitor for outbound connections from suspected exploited processes -->
        <Rule groupRelation="and">
          <Image condition="image">w3wp.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1071.001, T1041, T1567: C2 and Exfiltration from suspicious processes to known IoCs -->
        <Rule groupRelation="and">
          <Image condition="is any">powershell.exe;cmd.exe;rundll32.exe;certutil.exe;msbuild.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1572: Protocol Tunneling using specific tools to IoC IPs -->
        <Rule groupRelation="and">
          <Image condition="is any">plink.exe;ssh.exe;netsh.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1021.001: Post-RDP session network activity from shells -->
        <Rule groupRelation="and">
          <Image condition="is any">cmd.exe;powershell.exe</Image>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Implementation Notes:
- Used: Correlated specific suspicious images (powershell.exe, cmd.exe, rundll32.exe, certutil.exe, msbuild.exe, plink.exe, ssh.exe, netsh.exe) with the provided DestinationIp IoC list to satisfy T1071.001, T1041, T1567, and T1572.
- Used: Created a correlation between web server process (w3wp.exe) and IoC IPs to detect post-exploit egress for T1190/CVE-2023-48788.
- Used: Monitored shell processes initiating connections on RDP port 3389 to capture lateral movement/post-access activity for T1021.001.
- Not Used: Generic port monitoring (e.g., port 8080 or 443) without process/IP correlation to avoid noise.
- Not Used: Monitoring for cloud storage domains (Dropbox/OneDrive) via DestinationHostname as the specific IoC IPs were prioritized for high-fidelity detection.
-->
```

#### Time it took: 0 minutes and 40 seconds

----------------------------------------------------

# D. Divide & Conquer + CAPEC-related techniques

### T1190

Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific indicators:

1. Source IP Correlation:
Monitor for any network connections where the Source IP matches the reported IoCs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, 206.123.145.13.

2. Process-to-Network Mapping:
Monitor for network connections initiated by the Fortinet FortiClientEMS process or associated web server processes (e.g., w3wp.exe) that deviate from established baselines. Specifically, look for:
- Connections initiated by the server process immediately following a request from the listed IoC IPs.
- Outbound connections to external IPs (egress) originating from the application process, which may indicate a reverse shell or data exfiltration following the exploitation of CVE-2023-48788.

3. Vulnerability-Specific Traffic:
Since CVE-2023-48788 is a SQL injection vulnerability leading to unauthorized code execution, monitor for NetworkConnect events where the initiating process is a database engine or a web service spawning a connection to an external destination, correlating with the "post-exploit egress" signal of DET0080.




#### Time it took: 0 minutes and 4 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Exploit Public-Facing Application" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190: Exploit Public-Facing Application -->
        <!-- Correlation with reported IoC source IPs -->
        <Rule name="T1190_Known_Attacker_IPs" groupRelation="or">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>

        <!-- T1190 & CVE-2023-48788: Monitoring for post-exploitation egress (reverse shells/callbacks) -->
        <!-- Monitor for shells or LOLbins initiating outbound connections -->
        <Rule name="T1190_PostExploit_Egress" groupRelation="or">
          <Image condition="image">cmd.exe</Image>
          <Image condition="image">powershell.exe</Image>
          <Image condition="image">python.exe</Image>
          <Image condition="image">bash.exe</Image>
          <Image condition="image">regsvr32.exe</Image>
          <Image condition="image">rundll32.exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Implementation Details:
1. IoCs: Included all reported source IPs in a single 'is any' rule to detect incoming connections from known malicious actors associated with the attack pattern.
2. CVE-2023-48788 & T1190 Behavior: The security analysis highlighted the "request -> error -> post-exploit process/egress" chain. Since the host is high-exposure, I focused on the egress phase. I included processes found in the running process list (cmd.exe, powershell.exe, python.exe) and common LOLbins (regsvr32.exe, rundll32.exe) that would indicate a successful exploit resulting in a reverse shell or command execution.
3. Exclusions: Did not include generic "Discovery" or "Service" image rules from the examples to avoid excessive noise, focusing strictly on the critical execution/egress paths identified in the security analysis.
4. Host Context: Used the actual running processes (like python.exe and powershell.exe) identified in the host state to ensure the monitoring is relevant to the environment.
-->
```

#### Time it took: 0 minutes and 10 seconds
-------------------------------------------------------

### T1021.001

Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific criteria to detect T1021.001 and potential exploitation of CVE-2023-48788:

1. Source IP Filtering:
Monitor for any outbound or inbound connections involving the following high-threat source IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. RDP Traffic Analysis (T1021.001):
Identify NetworkConnect events where the DestinationPort is 3389 (default RDP). Correlate these connections with the source IPs listed above to identify unauthorized remote desktop attempts.

3. CVE-2023-48788 Exploitation (FortiClientEMS):
Monitor for NetworkConnect events involving the FortiClientEMS process. Specifically, look for unusual outbound connections originating from the EMS service to the listed threat IPs or unknown external destinations, which may indicate a reverse shell or data exfiltration following the SQL injection and unauthorized command execution described in the vulnerability.

4. High Exposure Server Context:
Given the high network exposure, prioritize filtering for NetworkConnect events where the Image represents system binaries (e.g., cmd.exe, powershell.exe, certutil.exe) initiating network connections immediately following an RDP session establishment from the identified malicious IPs.




#### Time it took: 0 minutes and 3 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Remote Access and Vulnerability Monitoring" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Monitoring for T1021.001: Remote Desktop Protocol -->
        <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- Monitoring for potential post-exploitation activity related to T1021.001 and CVE-2023-48788 -->
        <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="and">
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\certutil.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Explanation:
- Used: Combined DestinationPort 3389 with the specific high-threat IoC IP list to monitor for unauthorized RDP access (T1021.001) while minimizing noise from internal traffic.
- Used: Correlated suspicious processes (cmd.exe, powershell.exe, certutil.exe) initiating network connections to the identified threat IPs, as this indicates post-login activity or reverse shells resulting from either T1021.001 or the exploitation of CVE-2023-48788.
- Not Used: Broad monitoring of all port 3389 traffic or all activity from the listed IPs without process/port correlation, as the host is a high-exposure server and such rules would generate excessive noise.
- Not Used: Specific FortiClientEMS image monitoring because the provided "running processes" list did not show the EMS service active on the host, although the logic remains in the process-based rule.
-->
```

#### Time it took: 0 minutes and 10 seconds
-------------------------------------------------------
### T1071.001

Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific telemetry:

1. Destination IP Addresses:
Filter for any outbound connections to the known malicious IPs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, and 206.123.145.13.

2. Process Correlation (T1071.001):
Identify network connections initiated by suspicious processes that do not typically perform web requests, specifically:
- PowerShell.exe
- Rundll32.exe
- Any process associated with Fortinet FortiClientEMS (targeted by CVE-2023-48788).

3. Protocol and Port Monitoring:
Focus on connections over ports 80 (HTTP) and 443 (HTTPS) that originate from the aforementioned suspicious processes.

4. Behavioral Anomalies:
Flag connections from the FortiClientEMS process to the identified malicious IPs, which could indicate a successful SQL injection (CVE-2023-48788) leading to command execution and subsequent C2 communication via web protocols.




#### Time it took: 0 minutes and 2 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1071.001: Web Protocols - Monitor suspicious processes initiating web traffic -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <Image condition="is any">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\rundll32.exe</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- CVE-2023-48788: Monitoring FortiClientEMS processes for C2 communication -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <Image condition="contains">FortiClientEMS</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- T1071.001: Monitor known malicious C2 infrastructure -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
  Analysis Summary:
  - Used: DestinationIp list provided in IoCs for precise matching of malicious C2 nodes.
  - Used: DestinationPorts 80 and 443 to align with the 'Web Protocols' attack pattern (T1071.001).
  - Used: Process images (powershell.exe and rundll32.exe) found in the running process list and security analysis as they are common for C2 proxying.
  - Used: 'contains FortiClientEMS' for the Image condition to capture potential exploitation of CVE-2023-48788 regardless of the specific installation path.
  - Not Used: Broad directory monitoring (e.g., \Temp, \AppData) to avoid noise on a high-exposure server, focusing instead on specific high-fidelity indicators (IPs and Process/Port combinations).
-->
```



#### Time it took: 0 minutes and 9 seconds
-------------------------------------------------------
### T1572

Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific indicators:

1. Source Process Monitoring:
Track outbound network connections initiated by tunneling-capable binaries:
- plink.exe
- ssh.exe
- netsh.exe

2. Network Destination Monitoring:
Alert on any NetworkConnect events where the DestinationIp matches the following known malicious sources:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

3. Protocol Tunneling Indicators (T1572):
Identify anomalous network behavior associated with the processes listed above:
- Connections to non-standard ports or port usage mismatches (e.g., SSH processes communicating over ports typically reserved for other services).
- Large asymmetric data flows (significant imbalance between bytes sent and received) indicating encapsulated traffic.

4. Vulnerability Correlation (CVE-2023-48788):
Given the high network exposure and the risk of remote code execution via SQL injection in FortiClientEMS, monitor for any NetworkConnect events originating from the FortiClientEMS process that establish new outbound connections to the listed malicious IPs, which would indicate a successful exploit followed by the establishment of a C2 tunnel (CAPEC-470).




#### Time it took: 0 minutes and 4 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Protocol Tunneling Detection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1572: Protocol Tunneling - Monitor for binaries commonly used to encapsulate traffic -->
        <Image condition="image">plink.exe</Image>
        <Image condition="image">ssh.exe</Image>
        <Image condition="image">netsh.exe</Image>

        <!-- T1572: Monitor for connections to known malicious infrastructure associated with the campaign -->
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- CVE-2023-48788: Correlation with potential shell/tunnel creation after FortiClientEMS exploitation -->
        <!-- Monitoring for any outbound connection from the specific vulnerability surface to the malicious IPs -->
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="and">
          <Image condition="contains">FortiClientEMS</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  Analysis Implementation Notes:
  - Used: Tool-based monitoring for plink.exe, ssh.exe, and netsh.exe as specified in the detection strategy (AN1483) for T1572.
  - Used: DestinationIp filtering to alert on all provided high-threat IoCs.
  - Used: A combined Rule (and) to correlate the vulnerability surface (FortiClientEMS) with the malicious IPs, addressing the risk of a tunnel being established after a successful CVE-2023-48788 exploit.
  - Not Used: "DataAsymmetryThreshold" and "TimeWindow" because these are behavioral metrics that cannot be filtered within a static Sysmon XML configuration file; they require a SIEM/EDR for post-processing.
  - Not Used: Port-based "Non-Standard Port" rules to avoid noise, as the host is highly exposed and already has several established high-port connections. Focus was kept strictly on known malicious IPs and tunneling binaries.
-->
```



#### Time it took: 0 minutes and 11 seconds
-------------------------------------------------------
### T1041

Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific conditions:

1. Destination IP Addresses:
Filter for outbound connections to the following reported IoC IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. Process Correlation (CVE-2023-48788):
Monitor NetworkConnect events originating from processes associated with Fortinet FortiClientEMS. Specifically, look for network connections initiated by the EMS service processes immediately following the execution of unauthorized commands or abnormal child process creation (indicative of the SQL injection exploit leading to RCE).

3. Exfiltration Pattern (T1041):
Monitor for outbound connections over common C2 protocols (HTTPS/443, DNS/53, or custom TCP/UDP ports) where the Image (process) typically does not generate network activity. Flag connections where the outbound data volume exceeds the DataVolumeThreshold (e.g., >1MB in <5min) to the aforementioned IoC IPs, while excluding KnownBenignProcesses.




#### Time it took: 0 minutes and 2 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1041: Exfiltration Over C2 Channel & CVE-2023-48788 -->
        <Rule name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" groupRelation="or">
          <!-- Monitoring outbound connections to reported IoC IPs -->
          <DestinationIp condition="is">185.216.70.170</DestinationIp>
          <DestinationIp condition="is">77.90.38.170</DestinationIp>
          <DestinationIp condition="is">154.216.19.224</DestinationIp>
          <DestinationIp condition="is">154.216.17.157</DestinationIp>
          <DestinationIp condition="is">176.65.141.201</DestinationIp>
          <DestinationIp condition="is">176.65.141.232</DestinationIp>
          <DestinationIp condition="is">206.123.145.13</DestinationIp>
        </Rule>

        <!-- Monitoring for RCE/Exfiltration from FortiClientEMS context (CVE-2023-48788) -->
        <!-- Since EMS is not in running processes, we monitor for potential shell spawners connecting to C2 -->
        <Rule name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" groupRelation="and">
          <Image condition="is any">cmd.exe;powershell.exe;conhost.exe</Image>
          <DestinationPort condition="is any">443;53</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
Analysis Implementation Notes:
1. Used: Specific IoC IP addresses identified in the threat report as high-priority destinations.
2. Used: Common C2 protocols (HTTPS/443 and DNS/53) filtered against common shell processes (cmd, powershell) to detect potential post-exploitation exfiltration resulting from CVE-2023-48788.
3. Not Used: Generic 'Image' paths like AppData or Temp. Although useful, these generate excessive noise on high-exposure servers and were excluded to maintain focus on the specific attack pattern and IoCs provided.
4. Not Used: DataVolumeThreshold logic, as Sysmon XML filtering does not support volumetric analysis (this must be handled by the SIEM/Log Analytics layer).
5. Not Used: KnownBenignProcesses exclusions for OneDrive/Edge as they were not specifically requested for this targeted IoC match.
-->
```



#### Time it took: 0 minutes and 10 seconds
-------------------------------------------------------
### T1567

Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific indicators:

1. Destination IP Addresses (RemoteAddress):
Filter for outbound connections to the following reported IoC IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. Process Correlation (Image):
Monitor for NetworkConnect events where the initiating process is not a standard web browser or system service, specifically focusing on:
- FortiClientEMS processes (due to CVE-2023-48788 vulnerability).
- Office applications (Word, Excel).
- Scripting interpreters (PowerShell, cmd.exe).
- Unexpected processes initiating HTTPS (Port 443) connections to known web services (Dropbox, Google Drive, OneDrive).

3. Traffic Volume and Destination (RemotePort & Destination):
- Track outbound connections on Port 443 to Microsoft Corporation (AS8075), Cloudflare (AS13335), and GitHub (AS36459) that originate from the FortiClientEMS process or unauthorized shell processes.
- Flag high outbound-to-inbound data ratios associated with these destinations, correlating the NetworkConnect event with the data volume sent.




#### Time it took: 0 minutes and 9 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Exfiltration Over Web Service" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1567: Exfiltration Over Web Service - Monitor outbound connections to reported IoC IPs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>

        <!-- T1567: Exfiltration Over Web Service - Monitor anomalous processes communicating with web services on port 443 -->
        <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
          <DestinationPort condition="is">443</DestinationPort>
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\dllhost.exe</Image>
        </Rule>

        <!-- CVE-2023-48788: Monitor FortiClientEMS for potential command execution resulting in network activity -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">FortiClientEMS.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Explanation:
- Used: DestinationIp filter for the provided IoC list to detect direct communication with known malicious infrastructure.
- Used: A combined Rule (AND) for Port 443 and common LOLBins (cmd.exe, powershell.exe, dllhost.exe) to identify non-browser processes initiating HTTPS connections to legitimate web services (T1567).
- Used: Specifically included FortiClientEMS.exe as the target of CVE-2023-48788, as an exploit resulting in remote code execution would likely trigger a network connection for data exfiltration.
- Not Used: General "begin with" rules for C:\Users or C:\Temp to avoid high noise on a server with high network exposure, as these frequently produce false positives.
- Not Used: Broad destination hostname filtering for Microsoft/Cloudflare as the host already has established connections to these, which would generate excessive noise.
-->
```



#### Time it took: 0 minutes and 10 seconds
----------




# Questions answered

- Does the "divide & conquer" strategy made better rules for each technique?
A.: Let's analyse each case:


### T1190
- Dump version
```xml
<!-- T1190 & CVE-2023-48788: Exploit Public-Facing Application -->
<NetworkConnect onmatch="include">
  <Rule groupRelation="and">
    <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
    <Image condition="is not">C:\Windows\System32\lsass.exe</Image>
  </Rule>
</NetworkConnect>
```
- Chunk version
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="T1190_Exploit_Public_Facing_Application" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- CVE-2023-48788: Monitor for callbacks to known malicious IoCs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>

        <!-- T1190: Monitor for shells or LOLbins initiating outbound network connections post-exploit -->
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1218,technique_name=Regsvr32" condition="image">regsvr32.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

1. The chunk version used `msbuild.exe`, an indicator mentioned in `AN0219` that the dump version did not consider 
2. `mshta.exe` and `regsvr32.exe` came from the examples (again...) 
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
### T1021.001
- Dump version

```xml
<NetworkConnect onmatch="include">
  <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="and">
    <DestinationPort condition="is">3389</DestinationPort>
    <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
  </Rule>
</NetworkConnect>
```
- Chunk version

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Remote Services" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1021.001: Remote Desktop Protocol -->
        <Rule groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>
        <Image name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="image">TermService.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```
1. Both implementations are very similar. However, the chunk version additionally uses the TermService.exe image, which is the Windows service responsible for Remote Desktop Services. If Sysmon reports RDP connections through this process, the additional filter could reduce noise by limiting detections to the legitimate RDP service. However, this assumption may not always hold, as attackers may use different processes or tools to establish RDP-related connections, potentially bypassing this filter.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### T1071.001
  - Dump version
  ```xml
  <!-- T1071.001, T1041, T1567: Web Protocols, Exfiltration Over C2/Web Service -->

    <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
      <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\powershell.exe;C:\Windows\System32\rundll32.exe;C:\Windows\System32\certutil.exe</Image>
      <DestinationPort condition="is">443</DestinationPort>
    </Rule>
  ```
  - Chunked version
  ```xml
  <NetworkConnect onmatch="include">
    <!-- Detection of Web Protocol-Based C2 (T1071.001) targeting known IoC IPs -->
    <Rule groupRelation="and">
      <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      <DestinationPort condition="is any">80;443</DestinationPort>
    </Rule>

    <!-- Detection of Web Protocol-Based C2 (T1071.001) via LOLBins on web ports -->
    <Rule groupRelation="and">
      <Image condition="is any">powershell.exe;rundll32.exe;cmd.exe;wscript.exe;cscript.exe;mshta.exe</Image>
      <DestinationPort condition="is any">80;443</DestinationPort>
    </Rule>

    <!-- Detection of post-exploitation callback following CVE-2023-48788 execution -->
    <!-- Monitoring for unexpected network activity from the target vulnerable application -->
    <Rule groupRelation="and">
      <Image condition="image">FortiClientEMS.exe</Image>
      <DestinationPort condition="is any">80;443</DestinationPort>
    </Rule>
  </NetworkConnect>
  ```

  1. Both versions used the same images (dump version with paths) and 443 port
  2. Chunked version correlated the IP addresses with using web protocol while the dump version used it as the following rule "Monitor these IP addresses if it does not come from the `lsass.exe` image" which could create more noise
  3. The chunked version correalted the CVE with the attack pattern and implemented a rule that monitors network connections of `FortiClientEMS.exe` in http ports
  4. The chunked version did not use rule names as I would like but that is just a minor detail

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### T1572

- Dump version
```xml
<!-- T1572: Protocol Tunneling -->
<NetworkConnect onmatch="include">
  <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="and">
    <Image condition="is any">plink.exe;ssh.exe;netsh.exe</Image>
    <DestinationPort condition="is any">443;80;22</DestinationPort>
  </Rule>
</NetworkConnect>
```

- Chunk version
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Protocol Tunneling Detection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1572: Monitor processes commonly used for tunneling -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1572: Correlation with reported malicious IoC endpoints -->
        <Rule groupRelation="or">
          <DestinationIp condition="is">185.216.70.170</DestinationIp>
          <DestinationIp condition="is">77.90.38.170</DestinationIp>
          <DestinationIp condition="is">154.216.19.224</DestinationIp>
          <DestinationIp condition="is">154.216.17.157</DestinationIp>
          <DestinationIp condition="is">176.65.141.201</DestinationIp>
          <DestinationIp condition="is">176.65.141.232</DestinationIp>
          <DestinationIp condition="is">206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1572 & CVE-2023-48788: Monitor FortiClientEMS for outbound tunneling activity following potential exploit -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="contains">FortiClientEMS</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

1. I think this is the first example where having all the information dumped at the same time may be more benefitial. The dump version knows by T1567 that the attacker does Exfiltration through web services, which use ports 443 and 80.
2. The dump version, additionally added port 22, typical default port for SSH used for T1021 and T1572 which the cunk version also did not use.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
### T1041 - C2 exfiltration

```xml
<!-- T1071.001, T1041, T1567: Web Protocols, Exfiltration Over C2/Web Service -->
<NetworkConnect onmatch="include">
  <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
    <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\powershell.exe;C:\Windows\System32\rundll32.exe;C:\Windows\System32\certutil.exe</Image>
    <DestinationPort condition="is">443</DestinationPort>
  </Rule>
  <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
    <Image condition="image">python.exe</Image>
    <DestinationIp condition="is any">52.123.144.190;4.207.247.139;34.107.243.93;34.36.133.15;142.251.27.93;52.112.100.65</DestinationIp>
  </Rule>
</NetworkConnect>
...
- Used: High-risk LOLbins (cmd, powershell, rundll32, certutil) connecting via port 443 to detect T1071.001/T1041.
```

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="T1041_Exfiltration_Over_C2_Channel" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Detect connections to known C2 infrastructure associated with the attack pattern T1041 -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>

        <!-- Monitor high-risk processes often used for C2/Exfiltration via Living off the Land, following potential exploitation of CVE-2023-48788 -->
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>

        <!-- Monitor processes initiating connections from suspicious temporary or user-writable directories typical of staged C2 binaries -->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\ProgramData\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
  - Used: Image monitoring for common proxy execution binaries (certutil, rundll32, mshta) and powershell, as these are frequently used to implement the encoding and transmission logic mentioned in T1041.
  - Used: Path monitoring for Temp and ProgramData directories to detect non-standard process locations communicating externally.
  - Not used: General port monitoring (e.g., 443, 8080) as this would generate excessive noise on a server with HIGH network exposure.
  - Not used: Data volume thresholds, as Sysmon Event ID 3 providel.s connection metadata but not cumulative byte counts (which requires a SIEM/log analyzer).
  - Not used: Exclusion of benign processes, as the 'include' logic already limits the scope to high-risk indicators.
-->
```

1. This technique is C2 exfiltration so it is reasonable not to have something besides known IP addresses.
2. The first LLM could relate the techniques and know that, most likely the C2 exfiltration would be done over web protocols and/or web services, a correlation that the second LLM couldn't make

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
### T1567 - Exfiltration through web service

- Dump version

```xml
<!-- T1071.001, T1041, T1567: Web Protocols, Exfiltration Over C2/Web Service -->
<NetworkConnect onmatch="include">
  <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
    <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\powershell.exe;C:\Windows\System32\rundll32.exe;C:\Windows\System32\certutil.exe</Image>
    <DestinationPort condition="is">443</DestinationPort>
  </Rule>
  <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
    <Image condition="image">python.exe</Image>
    <DestinationIp condition="is any">52.123.144.190;4.207.247.139;34.107.243.93;34.36.133.15;142.251.27.93;52.112.100.65</DestinationIp>
  </Rule>
</NetworkConnect>
...
- Used: Python.exe (present in running processes) communicating with flagged remote addresses to detect T1567.
```

- Chunk version
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Exfiltration Over Web Service" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1567: Monitoring anomalous processes initiating connections to common web services (Cloud/Web) -->
        <Rule groupRelation="and">
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\powershell.exe;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Users\Paulo\AppData\Local\Python\pythoncore-3.14-64\python.exe</Image>
          <DestinationPort condition="is any">443;80</DestinationPort>
        </Rule>

        <!-- T1567: Specifically monitoring tools often used for exfiltration in high-exposure environments -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">bitsadmin.exe</Image>

        <!-- T1567: Monitoring connections to reported malicious IoCs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Security Analysis Implementation Details:
1. Used: DestinationIp filtering for the provided IoC list to catch direct exfiltration to known malicious actors.
2. Used: Correlation between high-risk processes (cmd.exe, powershell.exe, python.exe) and common web ports (443, 80) to detect non-standard processes communicating with web services as described in AN1511.
3. Used: Monitoring of 'certutil.exe' and 'bitsadmin.exe' as these are common LOLBins used to facilitate the transfer of data to web services.
4. Not Used: Data volume thresholds (ExfilVolumeThreshold) and TimeWindow, as these are telemetry-level aggregation metrics that cannot be defined within a static Sysmon XML filter.
5. Not Used: General 'exclude' rules for OneDrive/Dropbox to avoid noise, as the request specified focusing on the attack pattern T1567 and avoiding noise-generating isolation rules.
6. Not Used: CVE-2023-48788 specific process monitoring for FortiClientEMS, as that software was not listed in the host's installed programs or running processes.
-->
```

1. The analytic AN1511 says specifically "Processes that normally do not initiate network communications suddenly making outbound HTTPS connections with high outbound-to-inbound data ratios. Defender view: correlation between process creation logs (e.g., Word, Excel, PowerShell) and subsequent anomalous network traffic volumes toward common web services (Dropbox, Google Drive, OneDrive)." but none of them really seemed to justify why they did not monitor specific images for this. 
Examples of host running  that could've been that was given to the LLM are: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_6477ac83bad98f87\\RtkAudUService64.exe', 'C:\\Windows\\System32\\wininit.exe', 'C:\\Windows\\System32\\services.exe', 'C:\\Windows\\System32\\LsaIso.exe', 'C:\\Windows\\System32\\lsass.exe', 'C:\\Program Files\\Sublime Text\\plugin_host-3.8.exe', 'C:\\Program Files\\Sublime Text\\crash_handler.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\dtt_sw.inf_amd64_5ecafabf5082a9c7\\ipfsvc.exe', etc.
2. Dump version ignored port 80 for some unjustified reason
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

- Is the IoCs used in any different way on the many LLM responses?
A.: No, generally is used in combination with ports, sometimes as DestinationIp or SourceIp

- What is comparison of time?
A.:
| Dump | Chunk | Dump + CAPEC | Chunk + CAPEC |
| -----| ----- | ------------ | ------------- |
| 32s  | 146s  | 46s          | 84s           |


- Does adding more context with CAPEC-related techniques helped the final result? 
A.: It seemed to be much more aware of the vulnerability at hand and was more included in the final result, I would say yes, it helped


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Conclusions

- The LLMs seem to not really care about the running processes. Maybe I have to simplify that or use a CoT strategy  
- The chunk version does not seem to have a better result than the dump version. Correlating the attack patterns is a advantage that the dump LLM could take.