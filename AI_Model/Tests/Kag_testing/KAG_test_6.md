# Test 6

On the last test I noticed that my host IP context was being ignored (or at least excluded without any explanaiton), so in this test I will try to improve this gap by:

- Adding IP context of the CTI and host IP's seen via IP API
- Ask explicitely that the LLM explains why it did not consider information gave to it.


Questions to answer:

1. Was the IP context used in any way?
2. Did the IP context improve the final result?
3. Did the IP context harmed the final result in any way? 

As an example of the context given by the IP API, this was the host IP context given:

```js
Ip context:  
[
	{
		'raddr': '34.120.208.123', 
		'org': 'Google Cloud', 
		'AS': 'AS396982 Google LLC', 
		'port': 443
	},
	{
		'raddr': '35.240.39.145', 
		'org': 'Google Cloud (europe-west1)', 
		'AS': 'AS396982 Google LLC', 
		'port': 443
	}, 
	{
		'raddr': '104.18.38.47', 
		'org': 'Cloudflare, Inc.', 
		'AS': 'AS13335 Cloudflare, Inc.', 
		'port': 443
	}, 
	{
		'raddr': '34.107.243.93', 
		'org': 'Google Cloud', 
		'AS': 'AS396982 Google LLC', 
		'port': 443
	}, 
	{
		'raddr': '2603:1063:12::2f6', 
		'org': 'Microsoft Azure Cloud (francecentral)', 
		'AS': 'AS8075 Microsoft Corporation', 
		'port': 443
	}, 
	{
		'raddr': '34.78.13.176', 
		'org': 'Google Cloud (europe-west1)', 
		'AS': 'AS396982 Google LLC', 
		'port': 8925
	}, 
	{
		'raddr': '2a00:1450:400c:c0c::5b', 
		'org': 'Google Public DNS (bru)', 
		'AS': 'AS15169 Google LLC', 
		'port': 443
	}, 
	{
		'raddr': '140.82.114.25', 
		'org': 'GitHub, Inc.', 
		'AS': 'AS36459 GitHub, Inc.', 
		'port': 443
	}, 
	{
		'raddr': '2603:1020:5:9::402', 
		'org': 'Microsoft Azure Cloud (northeurope)', 
		'AS': 'AS8075 Microsoft Corporation', 
		'port': 443
	}, 
	{
		'raddr': '2a00:1450:400c:c0c::79', 
		'org': 'Google Public DNS (bru)', 
		'AS': 'AS15169 Google LLC', 
		'port': 443
	}, 
	{
		'raddr': '208.95.112.1', 
		'org': 'Total Uptime Technologies, LLC', 
		'AS': 'AS53334 Total Uptime Technologies, LLC', 
		'port': 80
	}, 
	{
		'raddr': '2606:4700:78::90:0:182', 
		'org': 'Cloudflare, Inc.', 
		'AS': 'AS13335 Cloudflare, Inc.', 
		'port': 443
	}, 
	{
		'raddr': '13.69.116.109', 
		'org': 'Microsoft Azure One Ds Collector (westeurope)', 
		'AS': 'AS8075 Microsoft Corporation', 
		'port': 443
	}
]
```

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# With IP context


To monitor the provided attack patterns, IoCs, and vulnerabilities via Sysmon **NetworkConnect** events for a high-exposure server, focus on the following telemetry:

### 1. Known Malicious Infrastructure (IoC Correlation)
Monitor any `NetworkConnect` events where the `DestinationIp` matches the reported threat actor infrastructure:
*   **IP Addresses:** `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`.

### 2. Exploit-Driven Egress (T1190 & CVE-2023-48788)
Given the high network exposure and the risk of SQL injection (CVE-2023-48788) leading to remote code execution, monitor for:
*   **Process-to-Network Correlation:** Outbound connections initiated by public-facing application processes (e.g., `w3wp.exe`, `FortiClientEMS` related binaries) to external IPs.
*   **Post-Exploit Shells:** `NetworkConnect` events where the `Image` is a shell or LOLbin (e.g., `cmd.exe`, `powershell.exe`, `certutil.exe`, `rundll32.exe`) immediately following a request to a public VIP.

### 3. Command & Control (C2) and Tunneling (T1071.001, T1572)
Monitor for anomalous protocol behavior and tunneling tools:
*   **Suspicious Images:** Outbound connections from `powershell.exe`, `plink.exe`, `ssh.exe`, or `netsh.exe`.
*   **Protocol Mismatches:** Connections to ports 443, 80, or 8925 (identified in port context) initiated by processes that do not typically perform web traffic.
*   **Data Asymmetry:** High volume of outbound bytes compared to inbound bytes for processes mimicking browser traffic.

### 4. Exfiltration Pathways (T1041, T1567)
Monitor for unauthorized data movement to external services:
*   **Cloud Service Egress:** `NetworkConnect` events to known web storage/service IPs (e.g., Google Cloud, Azure, Cloudflare) initiated by non-browser processes (e.g., `powershell.exe`, `Excel.exe`, `Word.exe`).
*   **C2 Channel Exfiltration:** Unexpected outbound volume spikes from processes typically used for C2.

### 5. Lateral Movement (T1021.001)
Monitor for RDP-related network activity:
*   **Internal RDP Shifts:** `NetworkConnect` events on TCP port 3389, specifically when initiated by users or service accounts that do not typically perform administrative RDP sessions.



#### Time it took: 0 minutes and 6 seconds
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- 1. Known Malicious Infrastructure (IoC Correlation) -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!-- 2. Exploit-Driven Egress & Post-Exploit Shells (T1190 / CVE-2023-48788) -->
      <NetworkConnect onmatch="include">
        <Rule name="Post-Exploit Shells" groupRelation="or">
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
          <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- 3. Command & Control (C2) and Tunneling (T1071.001, T1572, T1571) -->
      <NetworkConnect onmatch="include">
        <Rule name="C2 Tunneling Tools" groupRelation="or">
          <Image condition="image">plink.exe</Image>
          <Image condition="image">ssh.exe</Image>
          <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>
        </Rule>
        <!-- Monitoring port 8925 specifically as it was identified in the provided host's established connections (34.78.13.176:8925) and the security analysis -->
        <DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">8925</DestinationPort>
      </NetworkConnect>

      <!-- 4. Exfiltration Pathways (T1041, T1567) -->
      <!-- Monitor high-risk directories typically used for staging tools/exfiltration as seen in examples -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\wwwroot\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\htdocs\</Image>
      </NetworkConnect>

      <!-- 5. Lateral Movement (T1021.001) -->
      <NetworkConnect onmatch="include">
        <Rule name="Unauthorized RDP" groupRelation="and">
          <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
          <!-- Exclude typical system processes if necessary, but generally monitor for non-standard images initiating RDP -->
          <Image condition="is not">C:\Windows\System32\svchost.exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
EXPLANATION OF EXCLUSIONS:
1. Port 8080/1080/3128: I did not include a general "include" for these proxy ports because they are common in development environments (like Docker and Python 3.14 installed on this host) and would generate excessive noise.
2. Generic Port 443/80 monitoring: Since the host is a high-exposure server, almost every legitimate process (Firefox, Edge, Teams, OneDrive) uses these ports. Monitoring them without a specific Image or DestinationIp correlation would be impractical.
3. Broad "C:\Users" monitoring: I prioritized the Temp and Webroot directories for exfiltration monitoring over the general Users directory to reduce noise from legitimate user-space application traffic.
-->
```

#### Time it took: 1 minutes and 21 seconds


----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# NO IP context 
Based on the provided attack patterns, IoCs, and the critical vulnerability (CVE-2023-48788), monitoring for the `NetworkConnect` event in Sysmon should focus on the following specific correlations to minimize noise:

### 1. Immediate Threat Indicators (IoC Matching)
Monitor any `NetworkConnect` event where the `DestinationIp` matches the known malicious sources:
*   **Target IPs:** `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`.

### 2. Exploitation of Public-Facing Application (T1190 & CVE-2023-48788)
Given the high network exposure and the SQL injection vulnerability in FortiClientEMS, monitor for anomalous outbound connections originating from web-facing service processes:
*   **Source Processes:** `w3wp.exe`, `forticlientems.exe` (or related service binaries).
*   **Behavior:** Outbound connections to external IPs immediately following the delivery of crafted HTTP/S requests (correlation with web logs for `union select`, `cmd=`, etc.).

### 3. Post-Exploit Execution and C2 (T1059.001, T1071.001, T1567)
Monitor `NetworkConnect` events where the `Image` is a living-off-the-land binary (LOLbin) or script interpreter, specifically those associated with command execution:
*   **Suspicious Processes:** `powershell.exe`, `pwsh.exe`, `cmd.exe`, `rundll32.exe`, `mshta.exe`.
*   **Context:** Connections to external IPs, especially those mimicking web traffic (HTTP/S) or targeting known cloud storage services (Dropbox, Google Drive, OneDrive) for exfiltration.

### 4. Protocol Tunneling and Lateral Movement (T1572, T1021.001)
Monitor for tunneling tools or RDP-related network activity that deviates from the established baseline:
*   **Tunneling Binaries:** `plink.exe`, `ssh.exe`, `netsh.exe`.
*   **RDP Activity:** Outbound connections on TCP 3389 from non-administrative users or unexpected source-destination pairs.

### 5. Data Exfiltration (T1041)
Monitor for asymmetric data flows (high outbound volume) where the `Image` is not a recognized browser or legitimate update service:
*   **Filter:** Exclude known benign update processes.
*   **Trigger:** Outbound connections from processes that typically do not generate network activity, especially following file access events.



#### Time it took: 0 minutes and 10 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!--
      RULE GROUP 1: Immediate Threat Indicators (IoCs)
      Monitoring outbound connections to known malicious IPs associated with the threat actor.
    -->
    <RuleGroup name="Threat_IoC_Matching" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>

    <!--
      RULE GROUP 2: Living-off-the-land Binaries (LOLBins)
      Monitoring suspicious processes initiating network connections, focusing on those that can be used for C2 or exfiltration.
    -->
    <RuleGroup name="LOLBin_Network_Activity" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">regsvr32.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!--
      RULE GROUP 3: Anomalous Process Locations (Masquerading)
      Detecting network connections originating from temp or user directories, common for dropped malware.
    -->
    <RuleGroup name="technique_id=T1036,technique_name=Masquerading" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="begin with">C:\Windows\Temp\</Image>
        <Image condition="begin with">C:\Users\Public\</Image>
        <Image condition="contains">\AppData\Local\Temp\</Image>
        <Image condition="contains">\AppData\Roaming\</Image>
      </NetworkConnect>
    </RuleGroup>

    <!--
      RULE GROUP 4: Remote Services and Tunneling
      Monitoring for unexpected RDP, SSH, or VNC activity.
    -->
    <RuleGroup name="technique_id=T1021,technique_name=Remote Services" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">22</DestinationPort> <!-- SSH -->
        <DestinationPort condition="is">3389</DestinationPort> <!-- RDP -->
        <Image condition="image">vnc.exe</Image>
        <Image condition="image">plink.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!--
      RULE GROUP 5: Noise Reduction (Exclusions)
      Excluding legitimate traffic from installed software (OneDrive, Edge, Firefox) to reduce false positives.
    -->
    <RuleGroup name="Noise_Reduction" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="image">OneDrive.exe</Image>
        <Image condition="image">firefox.exe</Image>
        <Image condition="image">msedge.exe</Image>
        <!-- Exclude Kerberos traffic from LSASS -->
        <Rule groupRelation="and">
          <Image condition="is">C:\Windows\System32\lsass.exe</Image>
          <DestinationPort condition="is">88</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  EXPLANATION OF EXCLUSIONS/OMISSIONS:
  1. FortiClientEMS / CVE-2023-48788: I did not create a specific 'include' rule for forticlientems.exe or w3wp.exe because these binaries were not found in the provided 'running processes' or 'installed programs' list for this specific host. Monitoring a process that isn't present would be ineffective.
  2. Port 8080/1080/3128: As per the instructions, I avoided isolating common proxy ports in a general include box to prevent excessive noise from legitimate web traffic.
  3. High Volume Data Exfiltration: Monitoring for "asymmetric data flows" (volume) cannot be done via Sysmon XML configuration filters, as Sysmon filters on the occurrence of the event, not the byte-count of the payload. This requires a SIEM/Traffic Analysis tool.
  4. Python/Ollama: While present on the host and capable of networking, they are legitimate installed tools. I have relied on the "Masquerading" rule (Rule Group 3) to detect them if they are executed from suspicious temp paths.
-->
```



#### Time it took: 0 minutes and 18 seconds

---

# Questions answered

1. Was the IP context used in any way?
A.: Yes, it was used pretty well, connecting the T1571 (Non-standard ports) and the host port shown. HOWEVER, something I did notive was that T1571 was not in the given context. It was given in the examples to learn from. The LLM probably took it from there and it is not supposed to, since it was not reported directly.

2. Did the IP context improve the final result?
A.: It would've been if it was a reported technique. IF it was, he wouldn't have gone for a blind guess on ports like 22 like the second LLM did.

3. Did the IP context harmed the final result in any way?
A.: Only the time taken, which can be variable. I had executions which was the opposite time. Not really relevant.

# Conclusions

The main thing I take form this test is that the LLM, with IP context can make more informed decisions, which is good. But with the current state I sense that the LLM is taking the examples too literally, I only wanted it to understand the syntax, not copy the examples. So I may have to come up with possible solutions:

- Divide the problem into the many contexts. See if the main problem here is the context window that is becoming too narrow
- Be more explicit about sysmon syntax and give less examples.