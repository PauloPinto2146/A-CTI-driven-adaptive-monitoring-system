=========== Test case NORMAL ===========
Monitor NetworkConnect events for the following specific patterns:

1. Inbound connections from the following source IPs to any public-facing application ports (e.g., 443, 80, or FortiClientEMS specific ports):
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. Outbound connections originating from web server processes (e.g., w3wp.exe) or database processes, especially following a request from the aforementioned IPs, to indicate post-exploitation callbacks or C2 establishment (T1190, T1071.001).

3. Outbound connections from non-standard network processes (e.g., cmd.exe, powershell.exe, rundll32.exe, certutil.exe) to any external IP, specifically monitoring for high outbound-to-inbound data ratios indicative of exfiltration (T1041, T1567).

4. Network connections established by tunneling tools (e.g., plink.exe, ssh.exe, netsh.exe) to external destinations, identifying asymmetric data flows or port mismatches (T1572).

5. Inbound RDP connections (TCP 3389) from the identified malicious source IPs (T1021.001).

6. Outbound HTTPS connections from common productivity applications (e.g., Word, Excel) to known web services (Dropbox, Google Drive, OneDrive) used for data exfiltration (T1567).


#### Time it took: 0 minutes and 22 seconds

## Normal sysmon config production

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190: Exploit Public-Facing Application & CVE-2023-48788 -->
        <Rule groupRelation="and">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- T1021.001: Remote Desktop Protocol -->
        <Rule groupRelation="and">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- T1071.001 & T1041: C2 and Exfiltration via unusual processes -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="or">
          <Image condition="image">cmd.exe</Image>
          <Image condition="image">powershell.exe</Image>
          <Image condition="image">rundll32.exe</Image>
          <Image condition="image">certutil.exe</Image>
        </Rule>

        <!-- T1572: Protocol Tunneling -->
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="or">
          <Image condition="image">plink.exe</Image>
          <Image condition="image">ssh.exe</Image>
          <Image condition="image">netsh.exe</Image>
        </Rule>

        <!-- T1567: Exfiltration Over Web Service -->
        <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\powershell.exe</Image>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Summary:
- Implemented:
    1. Correlation of reported malicious source IPs with public ports (T1190 / CVE-2023-48788).
    2. Correlation of malicious source IPs with RDP port 3389 (T1021.001).
    3. Monitoring of Living-off-the-Land Binaries (LoLBins) making network connections for C2 and Exfiltration (T1071.001, T1041).
    4. Specific tunneling binaries mentioned in the analysis (T1572).
    5. Outbound HTTPS from shell processes to detect web service exfiltration (T1567).
- Not Implemented:
    1. Broad port monitoring (e.g., 8080, 4444) as it was explicitly requested to avoid noise/isolated rules that do not map directly to the provided IoCs or analysis.
    2. Monitoring of Word/Excel processes as they were not present in the "running processes" list of the host state.
    3. General "ProgramData" or "Temp" path monitoring to keep the result strictly focused on the specified attack patterns and provided analysis.
-->
```



#### Time it took: 0 minutes and 59 seconds
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## "Host-after" sysmon config production

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Monitoring for Exploitation, C2, Tunneling, and Exfiltration patterns -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190: Exploit Public-Facing Application - Monitor inbound from known malicious IPs -->
        <Rule groupRelation="and">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>

        <!-- T1021.001: Remote Desktop Protocol - Monitor RDP connections from identified malicious IPs -->
        <Rule groupRelation="and">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- T1071.001 & T1041: Web Protocols / Exfiltration Over C2 - Monitor LOLBins making outbound connections -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" condition="image">cmd.exe</Image>

        <!-- T1572: Protocol Tunneling - Monitor tools used for encapsulated traffic -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1567: Exfiltration Over Web Service - Monitor productivity apps making network connections -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">winword.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">excel.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
ANALYSIS SUMMARY:
- Implemented:
    * Source IP filtering for T1190 and T1021.001 to track the specific malicious actors identified in the IoCs.
    * Image-based monitoring for T1071.001 and T1041 using common LOLBins (powershell, rundll32, certutil) to reduce noise compared to monitoring all port 80/443 traffic.
    * Explicit tool monitoring for T1572 (plink, ssh, netsh) as per the security analysis.
    * Application monitoring for T1567 (Word, Excel) to detect anomalous outbound web service connections.
- Not Implemented:
    * Specific data volume thresholds (e.g., >1MB) or outbound-to-inbound ratios, as Sysmon NetworkConnect event logs do not provide byte counts/volume metrics in the XML filter itself.
    * Specific "w3wp.exe" rules were merged into general LOLBin monitoring to prioritize the processes typically spawned *after* the exploit (T1190 post-exploit).
-->
```



#### Time it took: 0 minutes and 12 seconds


Based on the host's state, I have identified several critical factors:
1. **Exposed Surface:** The host is listening on ports **80** and **443** (0.0.0.0 and ::), confirming it is a public-facing server, making it highly susceptible to **T1190** (Exploit Public-Facing Application) and **CVE-2023-48788**.
2. **Tooling:** The presence of **Docker**, **WSL**, and **Python** increases the likelihood of adversaries using container escape or script-based C2 channels.
3. **Current Activity:** There are established connections to various Cloud IPs (AWS, Google, Microsoft), which is normal for a modern server but provides cover for **T1071.001** (Web Protocols) and **T1567** (Exfiltration Over Web Service).
4. **Living-off-the-Land:** `cmd.exe` and `OpenConsole.exe` (Windows Terminal) are currently running, which are primary targets for post-exploitation command execution.

I have updated the configuration to include specific binaries found in the running processes and installed software that correlate with the attack patterns.

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & T1021.001: Monitoring inbound from known malicious IPs to public ports (80, 443, 3389) -->
        <Rule groupRelation="and">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>

        <!-- T1071.001 & T1041: C2/Exfiltration via Shells and Interpreters found in running processes -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">python.exe</Image>
        <Image name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" condition="image">certutil.exe</Image>

        <!-- T1572: Protocol Tunneling - Monitoring networking tools and WSL connectivity -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">wsl.exe</Image>

        <!-- T1567: Exfiltration Over Web Service - Monitor OneDrive and Office apps known to be installed -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">OneDrive.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">winword.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">excel.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
MODIFICATIONS BASED ON HOST STATE:
- Added 'python.exe' to T1071.001/T1041 monitoring because Python is installed and a common vector for C2 scripts.
- Added 'wsl.exe' to T1572 monitoring because Windows Subsystem for Linux is installed and can be used to run SSH/tunneling tools outside of standard Windows binaries.
- Added 'OneDrive.exe' specifically to T1567 as it is explicitly installed and running on the host, making it a high-probability channel for "living-off-the-cloud" exfiltration.
- Maintained the malicious Source IP list to target the specific threats associated with CVE-2023-48788 and T1190, given the server is confirmed to be listening on ports 80/443.
-->
```



#### Time it took: 0 minutes and 44 seconds











------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Run #2

=========== Test case NORMAL ===========
Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific triggers:

1. Source IP Correlation:
Monitor for any outbound connections where the DestinationIp matches the known IoCs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, 206.123.145.13.

2. Exploit Public-Facing Application (T1190) & CVE-2023-48788:
Monitor for outbound network connections initiated by the FortiClientEMS process or its child processes, especially those spawning shells or LOLbins (e.g., cmd.exe, powershell.exe) following the exploitation of the SQL injection vulnerability.

3. Command and Control & Exfiltration (T1071.001, T1041, T1567):
Monitor for high-volume outbound data transfers or connections to common web services (Dropbox, Google Drive, OneDrive) initiated by non-browser processes (e.g., PowerShell, rundll32, Word, Excel). Focus on destination ports 443 and 80.

4. Protocol Tunneling (T1572):
Monitor for outbound network connections established by tunneling tools such as plink.exe, ssh.exe, or netsh.exe, specifically looking for asymmetric data flows or non-standard port usage.

5. Remote Desktop Protocol (T1021.001):
Monitor for network connections associated with RDP activity (port 3389) that correlate with unusual process execution on the host.



#### Time it took: 0 minutes and 11 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Monitoring outbound connections from shells/LOLbins often spawned after public-facing app exploitation -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">certutil.exe</Image>

        <!-- T1021.001: Remote Desktop Protocol activity -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>

        <!-- T1572: Protocol Tunneling tools -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1071.001, T1041, T1567: C2 and Exfiltration via Web Protocols/Services -->
        <!-- Monitoring processes that typically don't initiate network traffic but are used for exfiltration -->
        <Rule groupRelation="and">
          <Image condition="is any">powershell.exe;rundll32.exe;winword.exe;excel.exe</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- IoC Correlation: Specific malicious source IPs -->
        <DestinationIp name="IoC_Correlation" condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
ANALYSIS SUMMARY:
- Used:
    * T1190/CVE-2023-48788: Included common LOLbins (cmd, powershell, etc.) that act as post-exploit markers.
    * T1021.001: Specifically targeted the RDP default port (3389).
    * T1572: Included known tunneling binaries (plink, ssh, netsh).
    * T1071.001/T1041/T1567: Implemented a rule correlating high-risk processes (PowerShell, Office apps) with web ports (80, 443) to identify C2/Exfiltration without creating noise for browsers.
    * IoCs: Added all provided malicious IPs to the include list.
- Not Used:
    * General port 80/443 monitoring (too noisy for a high-exposure server).
    * Specific "Data Volume" or "Asymmetry" thresholds as Sysmon Event ID 3 does not provide byte-count metrics; these must be handled by a SIEM/Network monitor.
    * Generic 'Socks' or 'Tor' ports not explicitly linked to the requested attack patterns.
-->
```



#### Time it took: 0 minutes and 21 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Contextual Security Analysis" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Outbound connections from FortiClientEMS or common exploit-spawned shells -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">FortiClientEMS.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">powershell.exe</Image>

        <!-- T1021.001: Remote Desktop Protocol -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>

        <!-- T1071.001, T1041, T1567: Web-based C2 and Exfiltration via non-browser processes -->
        <Rule groupRelation="and">
          <Image condition="is any">powershell.exe;rundll32.exe;word.exe;excel.exe</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- T1572: Protocol Tunneling tools -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- IoC Correlation: Destination IPs from reported threat intelligence -->
        <DestinationIp name="threat_intel_correlation" condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  Analysis Summary:
  - Implemented:
    1. DestinationIp check for all provided IoCs.
    2. Monitoring for FortiClientEMS and shell processes to detect post-exploitation of CVE-2023-48788 (T1190).
    3. RDP port 3389 monitoring (T1021.001).
    4. A combined rule for T1071.001, T1041, and T1567 that flags high-risk processes (PowerShell, rundll32, etc.) connecting over web ports (80/443) to reduce noise compared to a blanket port include.
    5. Explicit monitoring of tunneling binaries (plink, ssh, netsh) for T1572.
  - Not Implemented:
    1. Generic port 80/443 include (too noisy).
    2. Generic RDP activity without process correlation (as requested to focus on NetworkConnect triggers).
    3. Data volume thresholds (not possible via Sysmon XML filtering, requires SIEM aggregation).
-->
```



#### Time it took: 0 minutes and 10 seconds


Based on the provided host state, I have refined the Sysmon configuration.

**Key changes based on host analysis:**
1.  **Process Validation:** The host is running `cmd.exe` and `OpenConsole.exe` (Windows Terminal). These are high-value targets for monitoring if they initiate outbound connections, especially since the server has high network exposure.
2.  **Application Context:** The host does **not** have `FortiClientEMS.exe` currently running in the process list, but since it is a server with high exposure and the vulnerability `CVE-2023-48788` is critical, the monitor remains as a "fail-safe" for when the service is active or installed.
3.  **RDP/WSL Context:** The host has `msrdc.exe` (Remote Desktop Client) and `wsl.exe` installed. Attackers often use WSL as a proxy or for tunneling (T1572), so `wsl.exe` has been added to the tunneling monitor.
4.  **Web Traffic:** The host is actively communicating with Google Cloud and Microsoft IPs over port 443. To avoid noise, the "Web C2/Exfiltration" rule remains restricted to specific non-browser binaries (`powershell.exe`, `rundll32.exe`) rather than monitoring the port generally.

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Contextual Security Analysis" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Outbound connections from FortiClientEMS or shell processes spawn following exploit -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">FortiClientEMS.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">OpenConsole.exe</Image>

        <!-- T1021.001: Remote Desktop Protocol monitoring -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>

        <!-- T1071.001, T1041, T1567: C2 and Exfiltration via non-browser processes -->
        <Rule groupRelation="and">
          <Image condition="is any">powershell.exe;rundll32.exe;word.exe;excel.exe</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- T1572: Protocol Tunneling tools including WSL (observed on host) -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">wsl.exe</Image>

        <!-- IoC Correlation: Destination IPs from reported threat intelligence -->
        <DestinationIp name="threat_intel_correlation" condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  Analysis Summary based on Host State:
  - Added 'OpenConsole.exe' to T1190 monitoring as it is currently running and a common target for reverse shells.
  - Added 'wsl.exe' to T1572 monitoring because WSL is installed and frequently used by adversaries to tunnel traffic or bypass Windows-native monitoring.
  - Retained FortiClientEMS.exe monitor despite not being in the current process list to protect the server against the identified CVE-2023-48788.
  - Kept the Web C2 rule (T1071.001/T1041/T1567) as a combined rule (Process + Port) to prevent noise from the legitimate browser traffic (Firefox/Edge) and Microsoft OneDrive activity observed in the host's established connections.
-->
```



#### Time it took: 0 minutes and 19 seconds



















------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Run #3

=========== Test case NORMAL ===========
Monitor Sysmon NetworkConnect events for the following specific criteria to detect the identified threats:

1. Destination IP Monitoring (C2 and Exfiltration):
Filter NetworkConnect events where the destination IP matches the reported IoCs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, 206.123.145.13.

2. Exploit Execution (T1190 / CVE-2023-48788):
Monitor for network connections initiated by the FortiClientEMS process or related web server processes (e.g., w3wp.exe) that deviate from baseline behavior, especially those following an inbound request containing SQL injection patterns (union select, etc.).

3. Protocol Tunneling and C2 (T1572, T1071.001):
Monitor NetworkConnect events initiated by tools associated with tunneling or shells, specifically:
- plink.exe
- ssh.exe
- netsh.exe
- powershell.exe
- rundll32.exe
Focus on outbound connections to uncommon ports or high-volume data transfers to the identified IoC IPs.

4. Data Exfiltration (T1041, T1567):
Monitor for high-volume outbound network connections (asymmetric data flow) originating from non-network processes such as:
- Word.exe
- Excel.exe
- PowerShell.exe
Specifically track connections to known web services (Dropbox, Google Drive, OneDrive) or the identified IoC IPs.

5. RDP-Based Lateral Movement (T1021.001):
Monitor for network connections on port 3389 originating from the server to other internal hosts, specifically when initiated by suspicious processes (cmd.exe, powershell.exe, certutil.exe) following a remote login.



#### Time it took: 0 minutes and 4 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="ThreatDetection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Exploit Public-Facing Application -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- T1021.001: Remote Desktop Protocol -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <Image name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="image">certutil.exe</certutil.exe>

        <!-- T1071.001 & T1572: Web Protocols and Protocol Tunneling -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1041 & T1567: Exfiltration Over C2 Channel / Web Service -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">Winword.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">Excel.exe</Image>

        <!-- Indicators of Compromise (IoCs) -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
ANALYSIS EXPLANATION:
- Used:
    * IoC Destination IPs: All provided source IPs from the context were added as destination IPs for monitoring.
    * T1190: Included w3wp.exe as it is the standard worker process for IIS/ASP.NET frequently targeted in public-facing exploits.
    * T1021.001: Included port 3389 and certutil.exe (identified in analysis as a post-login suspicious process).
    * T1071.001 & T1572: Included PowerShell, Rundll32, Plink, SSH, and Netsh as they are primary tools for C2 and tunneling.
    * T1041 & T1567: Included common productivity apps (Word, Excel) to detect anomalous outbound data movement.
- Not Used:
    * Generic port 80/443 inclusion: Excluded to avoid noise, as most system traffic uses these ports. Detection relies instead on the Image (process) or specific IoC IP.
    * 8080/1080/3128: Not explicitly requested in the security analysis for this specific threat profile and excluded to minimize noise.
    * Full Path for Images: Used 'image' condition (filename only) for broader coverage of the identified suspicious binaries.
-->
```

===== Test case HOST after ======

#### Time it took: 0 minutes and 19 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 / CVE-2023-48788: Exploit Public-Facing Application -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- T1071.001: Web Protocols / T1572: Protocol Tunneling -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1041 / T1567: Exfiltration Over C2 Channel / Web Service -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">Word.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">Excel.exe</Image>

        <!-- T1021.001: Remote Desktop Protocol (RDP Lateral Movement) -->
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
          <Image condition="is any">cmd.exe;powershell.exe;certutil.exe</Image>
        </Rule>

        <!-- IoC Monitoring: Known Malicious Source/Destination IPs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Implementation Details:
- Used: DestinationIp correlation for all provided IoCs.
- Used: Image monitoring for tunneling tools (plink, ssh, netsh) and C2-prone processes (powershell, rundll32) to address T1572 and T1071.001.
- Used: Monitoring of office binaries (Word, Excel) to detect anomalous exfiltration (T1567).
- Used: A combined rule for RDP (Port 3389) initiated by suspicious shells to reduce noise and specifically target T1021.001 lateral movement.
- Used: w3wp.exe monitoring to capture post-exploit network activity related to T1190 and CVE-2023-48788.
- Not Used: Generic port monitoring (e.g., 80, 443, 8080) as they produce excessive noise on a high-exposure server and were not tied to specific process/IP pairs in the security analysis.
- Not Used: Inbound request patterns (SQL injection regex) as Sysmon NetworkConnect only captures the connection layer, not the payload content.
-->
```



#### Time it took: 0 minutes and 9 seconds


Based on the host's current state, there are several critical observations:
1. **Missing Target Application**: The server does **not** have `w3wp.exe` (IIS) running, nor is there any evidence of Fortinet FortiClientEMS installed. However, the server is listening on ports **80 and 443**, confirming it is indeed a public-facing web server (likely running a different stack, possibly via Docker or WSL).
2. **High-Risk Tools Present**: The host has `Python`, `Docker`, `WSL`, and `Windows Terminal` installed. These are frequently used by adversaries for C2, tunneling, and post-exploitation.
3. **Active Environment**: There is an active Python process and several established connections to cloud infrastructure (Azure, Google Cloud, AWS), which could blend with T1071.001 (Web Protocols) or T1567 (Exfiltration).

I will modify the configuration to include `python.exe` (since it is running and used for C2/Exfil) and `wsl.exe` (as a proxy for tunneling/lateral movement), while keeping the essential IoC and RDP checks.

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190: Exploit Public-Facing Application -->
        <!-- Modified: Monitoring generic web-server-like behavior since w3wp.exe is not present but ports 80/443 are open -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">python.exe</Image>

        <!-- T1071.001: Web Protocols / T1572: Protocol Tunneling -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">wsl.exe</Image>

        <!-- T1041 / T1567: Exfiltration Over C2 Channel / Web Service -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">Word.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">Excel.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">python.exe</Image>

        <!-- T1021.001: Remote Desktop Protocol (RDP Lateral Movement) -->
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
          <Image condition="is any">cmd.exe;powershell.exe;certutil.exe</Image>
        </Rule>

        <!-- IoC Monitoring: Known Malicious Source/Destination IPs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Changes based on host state:
- Added 'python.exe': The host is running Python 3.14.5. Adversaries often use Python for custom C2 (T1071.001) and exfiltration (T1041).
- Added 'wsl.exe': Windows Subsystem for Linux is installed and running. This is a prime candidate for protocol tunneling (T1572) to bypass Windows-based network monitoring.
- Removed 'w3wp.exe': This process was not found in the running processes list, though the server is listening on ports 80/443.
- Retained RDP rule: Even though port 3389 is not currently listening, the security analysis requires monitoring for outbound RDP attempts (Lateral Movement).
- Retained IoC list: Critical for detecting known threat actor infrastructure regardless of the process used.
-->
```



#### Time it took: 0 minutes and 16 seconds














------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Run #4

=========== Test case NORMAL ===========
Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific telemetry:

1. T1190 (Exploit Public-Facing Application) / CVE-2023-48788:
- Monitor for outbound connections initiated by web server processes (e.g., w3wp.exe) or FortiClientEMS processes.
- Focus on connections to the reported malicious IPs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, 206.123.145.13.
- Specifically look for process-to-network relationships where a service process spawns a shell (cmd.exe, powershell.exe) which then establishes a network connection.

2. T1071.001 (Web Protocols) and T1567 (Exfiltration Over Web Service):
- Monitor for outbound connections on port 443 to known web service providers (Dropbox, Google Drive, OneDrive) or the listed malicious IPs.
- Flag connections initiated by non-standard processes (e.g., PowerShell, rundll32) rather than legitimate browsers.

3. T1572 (Protocol Tunneling):
- Monitor for outbound connections from tunneling tools such as plink.exe, ssh.exe, or netsh.exe.
- Watch for asymmetric data flows or port mismatches (e.g., RDP traffic encapsulated over SSH/HTTPS).

4. T1041 (Exfiltration Over C2 Channel):
- Monitor for high-volume outbound data transfers to the listed malicious IPs, especially following file access activity.

5. T1021.001 (Remote Desktop Protocol):
- Monitor for inbound RDP connections (port 3389) from the reported malicious source IPs.



#### Time it took: 0 minutes and 4 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Monitor potential shells or agents communicating with malicious IPs -->
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">cmd.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">powershell.exe</Image>
        </Rule>

        <!-- T1021.001: Remote Desktop Protocol inbound from known malicious IPs -->
        <Rule groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>

        <!-- T1071.001 & T1567: Web Protocol C2 and Exfiltration via unusual processes -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <DestinationPort condition="is">443</DestinationPort>
          <Image condition="image">rundll32.exe</Image>
        </Rule>
        <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
          <DestinationPort condition="is">443</DestinationPort>
          <Image condition="image">powershell.exe</Image>
        </Rule>

        <!-- T1572: Protocol Tunneling using known tunneling tools -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1041: Exfiltration Over C2 Channel to malicious IPs -->
        <Rule name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="is not">firefox.exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
Analysis Implementation Note:
- Used: Malicious IPs list correlated with shell processes (T1190/CVE-2023-48788), RDP port with malicious sources (T1021.001), and specific LoLBins (rundll32, powershell) over port 443 (T1071.001/T1567).
- Used: Explicit image monitoring for tunneling tools (plink, ssh, netsh) as per T1572.
- Used: Destination IP filtering for T1041 exfiltration, excluding the browser to reduce noise.
- Not Used: Broad port 8080/1080 monitoring as it was identified as noise.
- Not Used: General "C:\Users" or "C:\Temp" path monitoring to keep the result strictly aligned with the provided attack patterns and IoCs.
-->
```



#### Time it took: 0 minutes and 18 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Group for High-Fidelity Threat Detection -->
    <RuleGroup name="Threat_Detection" groupRelation="or">

      <!-- T1190 & CVE-2023-48788: Exploit Public-Facing Application / FortiClientEMS SQLi -->
      <!-- Monitor for outbound connections to reported malicious IPs from potentially compromised processes -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">w3wp.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">cmd.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">powershell.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- T1021.001: Remote Desktop Protocol -->
      <!-- Monitor for RDP connections coming from reported malicious IPs -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>
      </NetworkConnect>

      <!-- T1071.001 & T1567: Web Protocols and Exfiltration Over Web Service -->
      <!-- Monitor for non-browser processes initiating outbound HTTPS connections to reported malicious IPs -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1071.001,technique_name=Web Protocols" condition="is">443</DestinationPort>
          <Image condition="image">powershell.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1071.001,technique_name=Web Protocols" condition="is">443</DestinationPort>
          <Image condition="image">rundll32.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- T1572: Protocol Tunneling -->
      <!-- Monitor for outbound connections from known tunneling tools -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!-- T1041: Exfiltration Over C2 Channel -->
      <!-- Monitor for high-risk processes connecting to the listed malicious infrastructure -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">certutil.exe</Image>
        </Rule>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Analysis Implementation Details:
- Used: Correlated DestinationIp/SourceIp with reported malicious IoCs for T1190, T1021.001, and T1041.
- Used: Specific tool monitoring (plink, ssh, netsh) for T1572.
- Used: Image-to-Port correlation for T1071.001 (powershell/rundll32 on 443) to reduce noise compared to monitoring all port 443 traffic.
- Not Used: Generic destination port monitoring for 443 or 3389 without IP/Image context, as this would create excessive noise on a high-exposure server.
- Not Used: Byte ratio thresholds or time windows, as these are analytical correlations and cannot be implemented within the static Sysmon XML configuration file.
- Not Used: "MonitoredServices" for T1567 (Dropbox/OneDrive) as specific domains were not provided in the IoC list, and monitoring all traffic to these services is typically too noisy for an "include" rule.
-->
```



#### Time it took: 0 minutes and 22 seconds


Based on the provided host state (installed programs, running processes, and active network connections), the previous security analysis remains valid, but we can refine the configuration to be more precise.

**Observations from Host State:**
1.  **No `w3wp.exe` found:** The server is not currently running IIS. However, it has `Sftp` or `Web` related ports listening (Port 80 and 443 are in `LISTEN` state), indicating it is indeed a public-facing server. We should maintain monitoring for `cmd.exe` and `powershell.exe` network activity, as these are the primary "post-exploit" indicators for any public-facing application (T1190).
2.  **Developer Tools Present:** The host has `Python`, `Git`, `Docker`, and `WSL` installed. These tools can be abused for protocol tunneling (T1572) or exfiltration (T1041/T1071).
3.  **No known Tunneling Binaries running:** `plink.exe` or `ssh.exe` are not in the current process list, but the monitoring rule must remain to detect their execution.
4.  **C2/Exfiltration Risk:** The presence of `certutil.exe` (standard Windows) and the use of `python.exe` (found in running processes) increases the risk of custom exfiltration scripts.

Here is the updated Sysmon configuration. I have added `python.exe` to the monitoring list for C2 and Exfiltration, as it is a running process on this specific host and a common tool for adversaries.

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Group for High-Fidelity Threat Detection -->
    <RuleGroup name="Threat_Detection" groupRelation="or">

      <!-- T1190 & CVE-2023-48788: Exploit Public-Facing Application -->
      <!-- Since port 80/443 are LISTEN, monitor for shell spawn network activity to malicious IPs -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">cmd.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">powershell.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- T1021.001: Remote Desktop Protocol -->
      <!-- Monitor for RDP connections coming from reported malicious IPs -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>
      </NetworkConnect>

      <!-- T1071.001 & T1567: Web Protocols and Exfiltration Over Web Service -->
      <!-- Monitor for high-risk interpreters initiating outbound HTTPS connections -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1071.001,technique_name=Web Protocols" condition="is">443</DestinationPort>
          <Image condition="image">powershell.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1071.001,technique_name=Web Protocols" condition="is">443</DestinationPort>
          <Image condition="image">rundll32.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationPort name="technique_id=T1071.001,technique_name=Web Protocols" condition="is">443</DestinationPort>
          <Image condition="image">python.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- T1572: Protocol Tunneling -->
      <!-- Monitor for outbound connections from tunneling tools -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!-- T1041: Exfiltration Over C2 Channel -->
      <!-- Monitor for utility-based exfiltration to malicious infrastructure -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">certutil.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <Image condition="image">python.exe</Image>
        </Rule>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
Host-State Adjustments:
- Removed w3wp.exe from T1190 rules as it is not present in the running processes, but kept shell monitoring since port 80/443 are listening.
- Added python.exe to T1071.001 and T1041 rules because it is installed and currently running on the host, representing a significant vector for C2 and data exfiltration.
- Retained T1572 tooling (plink, ssh, netsh) and T1021.001 RDP checks as they are essential for the reported threat level and the server's high network exposure.
-->
```



#### Time it took: 0 minutes and 52 seconds


















------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Run #5

=========== Test case NORMAL ===========
Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific indicators based on the identified threat landscape:

1. Source IP Correlation:
Filter for all outbound network connections where the DestinationIp matches the reported IoCs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, and 206.123.145.13.

2. Exploit and C2 Process Monitoring (T1190, T1071.001):
Monitor NetworkConnect events initiated by high-risk processes that typically do not establish outbound connections or should only communicate with internal assets. Specifically focus on:
- w3wp.exe (IIS Worker Process) establishing outbound connections to external IPs (indicating potential post-exploit callback/reverse shell following CVE-2023-48788 SQL injection).
- PowerShell.exe, cmd.exe, rundll32.exe, and certutil.exe initiating outbound connections on ports 80, 443, or uncommon ports (indicating C2 traffic).

3. Protocol Tunneling and Exfiltration (T1572, T1041, T1567):
Monitor for the following process-to-network relationships:
- plink.exe, ssh.exe, or netsh.exe establishing outbound connections to the listed IoCs or unknown external IPs (indicating RDP over SSH or other tunneling).
- Office applications (Word, Excel) or PowerShell initiating high-volume outbound HTTPS connections to common web services (Dropbox, Google Drive, OneDrive) for data exfiltration.

4. Vulnerability-Specific Traffic (CVE-2023-48788):
Given the SQL injection nature of the vulnerability in FortiClientEMS, monitor for any network connections originating from the database service process or the EMS application process to external IPs, as this indicates successful remote code execution (RCE) and subsequent beaconing.



#### Time it took: 0 minutes and 5 seconds

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Post-exploit callback from web-facing processes -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- T1071.001 & T1041: C2 communication and Exfiltration via LOLBins -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">certutil.exe</Image>

        <!-- T1572: Protocol Tunneling Tools -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1567: Exfiltration Over Web Service via high-risk apps -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">excel.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">winword.exe</Image>

        <!-- Correlation with reported IoC Destination IPs -->
        <Rule groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!--
Security Analysis implementation details:
- USED: IoC IP list mapped to DestinationIp for direct threat detection.
- USED: w3wp.exe for T1190/CVE-2023-48788 to detect reverse shells from the web server.
- USED: PowerShell, cmd, rundll32, and certutil for T1071.001 (C2) and T1041 (Exfiltration) based on the "suspicious processes" list.
- USED: plink, ssh, and netsh for T1572 (Protocol Tunneling) as specified in the analysis.
- USED: Word/Excel images for T1567 to monitor anomalous outbound data flow to web services.
- NOT USED: Broad port monitoring (e.g., port 80/443) because the host has high network exposure and this would generate excessive noise.
- NOT USED: T1021.001 (RDP) as it primarily involves inbound authentication/logins rather than outbound NetworkConnect events initiated by the host, unless combined with specific tunneling tools already covered by T1572.
-->
```


#### Time it took: 0 minutes and 19 seconds


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Rule Group for High-Exposure Server Network Monitoring -->
    <RuleGroup name="" groupRelation="or">

      <!-- T1190: Exploit Public-Facing Application & CVE-2023-48788 -->
      <!-- Monitor web worker process spawning outbound connections (Post-exploit callback) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>
      </NetworkConnect>

      <!-- T1071.001: Web Protocols / T1041: Exfiltration Over C2 Channel -->
      <!-- Monitor LOLbins initiating network connections for C2 or Exfiltration -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">certutil.exe</Image>
      </NetworkConnect>

      <!-- T1572: Protocol Tunneling / T1021.001: Remote Desktop Protocol -->
      <!-- Monitor tunneling tools potentially used to encapsulate RDP or other traffic -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!-- T1021.001: Remote Desktop Protocol -->
      <!-- Direct monitoring of RDP port for suspicious activity -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
      </NetworkConnect>

      <!-- T1567: Exfiltration Over Web Service -->
      <!-- Monitor Office apps making network connections to external services -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">winword.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">excel.exe</Image>
      </NetworkConnect>

      <!-- IoC Correlation: Monitor all outbound traffic to reported malicious IPs -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  Security Analysis Implementation Summary:
  - Used:
    * DestinationIp for all reported IoCs.
    * Image 'w3wp.exe' to detect post-exploit callbacks related to T1190 and CVE-2023-48788.
    * LOLbins (powershell, cmd, rundll32, certutil) to detect T1071.001 (C2) and T1041 (Exfil).
    * Tunneling tools (plink, ssh, netsh) to detect T1572.
    * Port 3389 for T1021.001.
    * Office binaries for T1567.
  - Not Used:
    * Generic high-volume data ratio monitoring: Sysmon NetworkConnect does not provide byte counts/volume, which is required for the "DataVolumeThreshold" mentioned in the analysis; this must be handled by a SIEM/Traffic analyzer.
    * Wide-range port monitoring (e.g., 80, 443) without process context: Excluded to avoid noise on a high-exposure server.
-->
```



#### Time it took: 0 minutes and 20 seconds


Based on the host's state (installed programs, services, and running processes), I have refined the Sysmon configuration.

**Key adjustments made based on the host's state:**
1.  **Removal of `w3wp.exe`**: The host is not running an IIS worker process (`w3wp.exe` is not in the running processes list, and no IIS service is active). Monitoring it would be useless for this specific machine.
2.  **Addition of `python.exe`**: The host has Python 3.14.5 installed and running. Python is a primary tool for C2 beacons, reverse shells, and exfiltration scripts, mapping to **T1071.001** and **T1041**.
3.  **Addition of `docker.exe` / `com.docker.backend.exe`**: The host is running Docker Desktop. In the context of **T1190**, if a containerized application is exploited, the adversary may attempt to interact with the Docker API or escape to the host.
4.  **Addition of `wsl.exe`**: The host is running Windows Subsystem for Linux (WSL). Adversaries frequently use WSL to execute Linux-based tunneling tools or network scanners to evade Windows-native detections (**T1572**).
5.  **Confirmation of Office Apps**: Microsoft 365 Apps are installed, justifying the inclusion of `winword.exe` and `excel.exe` for **T1567**.

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Rule Group for High-Exposure Server Network Monitoring -->
    <RuleGroup name="" groupRelation="or">

      <!-- T1190: Exploit Public-Facing Application -->
      <!-- Monitor Docker/WSL processes for unexpected outbound traffic following potential container/API exploitation -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">docker.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">com.docker.backend.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">wsl.exe</Image>
      </NetworkConnect>

      <!-- T1071.001: Web Protocols / T1041: Exfiltration Over C2 Channel -->
      <!-- Monitor LOLbins and Python (installed on host) initiating network connections for C2 or Exfiltration -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">python.exe</Image>
      </NetworkConnect>

      <!-- T1572: Protocol Tunneling / T1021.001: Remote Desktop Protocol -->
      <!-- Monitor tunneling tools and WSL (used as a bridge for Linux tunneling tools) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">wsl.exe</Image>
      </NetworkConnect>

      <!-- T1021.001: Remote Desktop Protocol -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
      </NetworkConnect>

      <!-- T1567: Exfiltration Over Web Service -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">winword.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">excel.exe</Image>
      </NetworkConnect>

      <!-- IoC Correlation: Monitor all outbound traffic to reported malicious IPs -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  Changes based on Host State:
  - Removed: 'w3wp.exe' (Not found in running processes or installed services).
  - Added: 'python.exe' (Confirmed installed and running; critical for C2/Exfil monitoring).
  - Added: 'docker.exe', 'com.docker.backend.exe' (Confirmed installed; relevant for T1190 container exploitation).
  - Added: 'wsl.exe' (Confirmed installed/running; relevant for both T1190 and T1572).
  - Kept: Office binaries and RDP port as they align with installed software and attack patterns.
-->
```



#### Time it took: 0 minutes and 26 seconds