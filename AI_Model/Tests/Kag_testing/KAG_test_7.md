# Test 7

In the last test (6 and 6.1.) I noticed that the LLM was being influenced by the examples given in test 5 a little too much, in the sense that the LLM was implementing monitoring rules that were meant for unreported attack patterns (present in the examples but not in the CTI).

In this test I will be analysing 4 different scenarios:

| Test case | Examples | Explicit restriction instruction |
| --------- | -------- | -------------------------------- |
| A         | Various  | No                               |
| B         | Various  | Yes                              |
| C         | Few      | No                               |
| D         | Few      | Yes                              |


This test will hopefully answer the following questions:

- Does the test case A still uses the examples "too much"?
- Does the test case C work? If yes does it seem that giving various examples is the problem? 
- Was being explicit that the only attack patterns to analyse were the reported worked?
- Was giving few examples and being explicit about the restrictions good? (As this would be the best scenario)
- Is giving more examples (test case B) is better than few (test case D) when being explicit?
- What seems the better strategy?

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Security analysis

To monitor for the specified attack patterns and indicators on a high-exposure server, focus **Sysmon NetworkConnect (Event ID 3)** monitoring on the following high-fidelity triggers:

### 1. Direct IoC Matching
Monitor for any outbound connection where the `DestinationIp` matches the reported malicious source IPs (acting as C2 or exfiltration endpoints):
*   **Target IPs:** `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`.

### 2. Exploit & Post-Exploitation Process Correlation (T1190 $\rightarrow$ T1059.001/T1071.001)
Since the server has high network exposure and is vulnerable to **CVE-2023-48788** (SQL Injection leading to unauthorized code execution), monitor for network connections initiated by processes that should not typically perform outbound networking:
*   **Suspicious Source Processes:** `w3wp.exe`, `sqlservr.exe`, or any service process associated with FortiClientEMS.
*   **Anomalous Process Spawns:** Network connections originating from `powershell.exe`, `cmd.exe`, `rundll32.exe`, or `mshta.exe` immediately following a request to a public-facing endpoint.

### 3. C2 and Exfiltration Detection (T1071.001, T1041, T1567)
Monitor for outbound traffic on ports 80/443 that deviates from the server's baseline:
*   **Protocol Tunneling (T1572):** Connections from `plink.exe`, `ssh.exe`, or `netsh.exe` to external IPs.
*   **Exfiltration (T1567):** High-volume outbound data transfers to known web services (e.g., OneDrive, Dropbox, Google Drive) initiated by non-browser processes (e.g., PowerShell).
*   **C2 Patterns:** Connections to unusual domains or IPs using non-standard User-Agents (correlated with process name).

### 4. Remote Access Abuse (T1021.001)
Monitor for network activity originating from the server toward other internal hosts immediately following an RDP logon session:
*   **Pattern:** `SourceIp` (External/VPN) $\rightarrow$ `DestinationIp` (Server) via port 3389, followed by the server initiating new outbound connections to internal assets (Lateral Movement).

### Summary Monitoring Table for Sysmon Event ID 3

| Monitor Element | Value/Condition | Related Pattern/CVE |
| :--- | :--- | :--- |
| **DestinationIp** | `185.216.70.170`, `77.90.38.170`, etc. | IoC Match |
| **Image** | `powershell.exe`, `cmd.exe`, `rundll32.exe` | T1059.001, T1071.001 |
| **Image** | `w3wp.exe`, `sqlservr.exe` $\rightarrow$ Outbound | T1190 / CVE-2023-48788 |
| **Image** | `plink.exe`, `ssh.exe`, `netsh.exe` | T1572 |
| **DestinationPort**| `443`, `80` (from unexpected processes) | T1071.001, T1567 |



#### Time it took: 0 minutes and 12 seconds


(It is supposed to monitor only 'T1190', 'T1059.001', 'T1021.001', 'T1562.001', 'T1497.001', 'T1071.001', 'T1572', 'T1041', 'T1486', 'T1567')
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Test case A answer - Various examples, not explicit (the default)

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Security Analysis Correlation" groupRelation="or">
      <!-- 1. High Fidelity IoC Matching: Monitor outbound connections to known malicious IPs -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!-- 2. Post-Exploitation & LOLBins: Monitor common shells and proxy tools initiating network connections (T1059.001, T1071.001, T1572) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!-- 3. Vulnerability Correlation (CVE-2023-48788): Monitor for outbound traffic from processes associated with web/SQL services (T1190) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">sqlservr.exe</Image>
      </NetworkConnect>

      <!-- 4. Remote Access & Lateral Movement: Monitor for RDP and WinRM activity (T1021.001) -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5985</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5986</DestinationPort>
      </NetworkConnect>

      <!-- 5. Exfiltration and C2: Monitor for non-standard port usage and high-risk tool behavior (T1041, T1567) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
ANALYSIS SUMMARY:
- USED:
    - DestinationIp: Directly mapped the 7 reported IoCs to catch C2/Exfil traffic.
    - Image (Shells/LOLBins): Included powershell.exe, cmd.exe, rundll32.exe, and mshta.exe to detect post-exploitation activity following the T1190 exploit.
    - Image (Tunneling): Included plink.exe, ssh.exe, and netsh.exe to monitor for Protocol Tunneling (T1572).
    - Image (Service): Included w3wp.exe and sqlservr.exe to detect anomalous outbound traffic originating from the vulnerable application surface (CVE-2023-48788).
    - DestinationPort: Monitored 3389, 5985, 5986 to detect RDP and WinRM abuse (T1021.001).
    - Image (Proxy Execution): Included certutil.exe and msbuild.exe as they are common for T1041/T1567 exfiltration.

- NOT USED:
    - Port 8080/1080/3128: Excluded as "include" rules for common proxy ports on a high-exposure server would generate excessive noise.
    - Specific Web Service Domains (OneDrive/Dropbox): Not included in 'include' list to avoid noise; monitoring is instead focused on the suspicious processes (PowerShell/Certutil) initiating those connections.
    - General User Paths (C:\Users\): Excluded to focus on the specific attack patterns and IoCs provided rather than broad behavioral anomalies.
-->
```


#### Time it took: 0 minutes and 35 seconds
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Test case B answer - Various examples, explicit

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Direct IoC Matching: Monitoring connections to reported malicious IPs -->
        <Rule name="Malicious_IoC_IPs" groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1059.001 & T1071.001: Monitoring shells and living-off-the-land binaries initiating network connections -->
        <Rule name="technique_id=T1059.001,technique_name=PowerShell" groupRelation="or">
          <Image condition="image">powershell.exe</Image>
          <Image condition="image">cmd.exe</Image>
          <Image condition="image">rundll32.exe</Image>
          <Image condition="image">mshta.exe</Image>
        </Rule>

        <!-- T1572: Protocol Tunneling via common tunneling tools -->
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="or">
          <Image condition="image">plink.exe</Image>
          <Image condition="image">ssh.exe</Image>
          <Image condition="image">netsh.exe</Image>
        </Rule>

        <!-- T1021.001: Monitoring for RDP activity (Port 3389) -->
        <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="or">
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- T1190 & CVE-2023-48788: Monitoring for outbound connections from web-facing/service processes (Post-Exploit) -->
        <!-- Note: Focused on images typically associated with web/DB services mentioned in the analysis -->
        <Rule name="technique_id=T1190,technique_name=Exploit Public-Facing Application" groupRelation="or">
          <Image condition="image">w3wp.exe</Image>
          <Image condition="image">sqlservr.exe</Image>
        </Rule>

        <!-- T1567 & T1041: Exfiltration via Web Services/C2. Monitoring non-browser processes connecting via HTTPS -->
        <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
          <DestinationPort condition="is">443</DestinationPort>
          <Image condition="excludes any">firefox.exe;msedge.exe;OneDrive.exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
SECURITY ANALYSIS IMPLEMENTATION SUMMARY:

IMPLEMENTED:
- IoC Matching: All provided malicious source IPs were added via 'is any' to catch direct C2/Exfiltration.
- T1059.001/T1071.001: Monitored PowerShell, CMD, and proxy binaries (rundll32, mshta) which are high-fidelity indicators of post-exploitation C2.
- T1572: Included plink, ssh, and netsh to detect potential protocol tunneling.
- T1021.001: Explicitly monitored DestinationPort 3389 for RDP access.
- T1190/CVE-2023-48788: Monitored w3wp.exe and sqlservr.exe for abnormal outbound connections, aligning with the vulnerability context (SQLi/Remote Code Execution).
- T1567/T1041: Created a rule for Port 443 that excludes legitimate browsers (Firefox, Edge) and OneDrive (present in installed apps) to highlight anomalous process-to-web traffic.

NOT IMPLEMENTED / EXCLUDED:
- T1562.001 (Disable Security Tools) and T1497.001 (System Checks): These patterns typically involve local process/registry activity and do not generate unique NetworkConnect events.
- T1486 (Data Encrypted for Impact): Ransomware encryption is a file-system event; network indicators are limited to C2, which is already covered by the T1071.001/T1567 rules.
- Generic Port 8080/1080: Excluded to avoid noise, as requested, focusing instead on process-based anomalies and specific IoCs.
-->
```

#### Time it took: 0 minutes and 30 seconds
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Test case C answer - Few examples, not explicit

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">

      <!-- 1. Direct IoC Matching: Monitoring for reported malicious IPs -->
      <NetworkConnect onmatch="include">
        <DestinationIp name="IoC_Match" condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!-- 2. Post-Exploitation Execution: Shells and LOLBins initiating network connections (T1059.001, T1071.001) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">cmd.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">mshta.exe</Image>
      </NetworkConnect>

      <!-- 3. Protocol Tunneling: Monitoring specific tools used for encapsulation (T1572) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!-- 4. Exploit Correlation: Vulnerable process patterns (CVE-2023-48788 / T1190) -->
      <!-- Monitoring outbound connections from web/SQL services which should typically only be listeners -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">sqlservr.exe</Image>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  ANALYSIS IMPLEMENTATION NOTES:

  USED:
  - IoC Match: All 7 provided malicious IPs were included via 'is any' to detect C2/Exfiltration.
  - T1059.001 & T1071.001: Monitored powershell.exe, cmd.exe, rundll32.exe, and mshta.exe. These are high-fidelity indicators when they initiate outbound network connections on a server.
  - T1572: Specifically targeted plink, ssh, and netsh as these are common tools for protocol tunneling.
  - T1190 / CVE-2023-48788: Monitored w3wp.exe and sqlservr.exe. Since the analysis highlighted a high-exposure server vulnerable to SQLi, any outbound connection from these processes is highly suspicious.

  NOT USED:
  - T1021.001 (RDP): This is primarily handled by logon events and process spawning. Monitoring all port 3389 traffic in NetworkConnect without a specific destination IoC would be too noisy for a high-exposure server.
  - T1567 (Exfiltration over Web Service): I did not include a generic "Port 443" rule because the host has a high volume of legitimate HTTPS traffic (as seen in the ports context). This is better handled by correlating the "Image" (like powershell.exe) with the destination, which is already covered by the LOLbins rules.
  - T1486 & T1562.001: These are host-based activities (file encryption/disabling tools) that do not manifest as unique NetworkConnect events.
  - T1497.001: System checks are local discovery and do not typically generate a specific unique network signature.
-->
```

#### Time it took: 0 minutes and 25 seconds
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Test case D answer - Few examples, explicit
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- 1. Direct IoC Matching: Monitor connections to known malicious IPs -->
      <NetworkConnect onmatch="include">
        <DestinationIp name="IoC_Match" condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!-- 2. Exploitation and Command Execution: Monitor shells and interpreters initiating network connections -->
      <!-- This covers T1059.001 (PowerShell) and T1190 (Post-exploit shells) -->
      <NetworkConnect onmatch="include">
        <Image name="T1059.001,PowerShell" condition="image">powershell.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="T1190,Exploit Public-Facing Application" condition="image">cmd.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="T1071.001,Web Protocols" condition="image">rundll32.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="T1071.001,Web Protocols" condition="image">mshta.exe</Image>
      </NetworkConnect>

      <!-- 3. Protocol Tunneling: Monitor tools typically used for encapsulation -->
      <!-- Refers to T1572 -->
      <NetworkConnect onmatch="include">
        <Image name="T1572,Protocol Tunneling" condition="image">plink.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="T1572,Protocol Tunneling" condition="image">ssh.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image name="T1572,Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!-- 4. Exfiltration over Web Services: Monitor non-browser processes talking to common ports -->
      <!-- This targets T1567 and T1041 by focusing on common exfiltration ports (443) from sensitive images -->
      <!-- We exclude known browsers like firefox.exe and msedge.exe to reduce noise -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="T1567,Exfiltration Over Web Service" condition="is">443</DestinationPort>
      </NetworkConnect>
      <NetworkConnect onmatch="exclude">
        <Image name="Noise_Reduction" condition="image">firefox.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="exclude">
        <Image name="Noise_Reduction" condition="image">msedge.exe</Image>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!--
  SECURITY ANALYSIS IMPLEMENTATION NOTES:

  USED:
  - IoC Matching: Implemented via DestinationIp for all provided malicious IPs.
  - T1190 / CVE-2023-48788: Monitored the execution of shells (cmd.exe) and living-off-the-land binaries (rundll32, mshta) that would likely be spawned after a successful SQL injection exploit.
  - T1059.001: Specifically targeted powershell.exe network activity.
  - T1572: Added monitoring for plink.exe, ssh.exe, and netsh.exe.
  - T1071.001 / T1567 / T1041: Monitored port 443. To prevent noise on a high-exposure server, I used "exclude" rules for the installed browsers (Firefox and Edge), ensuring that any other process (like a hijacked service or script) communicating over HTTPS is flagged.

  NOT USED:
  - T1562.001 (Disable/Modify Tools) and T1497.001 (System Checks): These are primarily host-based activities (registry/process/file) and do not generate specific NetworkConnect events.
  - T1486 (Data Encrypted for Impact): This is a file-system activity (ransomware) and does not have a unique network signature other than C2, which is already covered.
  - T1021.001 (RDP): While RDP uses network connections, monitoring port 3389 on a server typically results in too much noise. The analysis recommended correlating the logon with subsequent activity; since this is a NetworkConnect snippet, I focused on the "outbound" lateral movement phase by monitoring shells initiating connections.
-->
```

#### Time it took: 0 minutes and 40 seconds

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Questions answered


- Does the test case A still uses the examples "too much"?
A.: Yes, it used `WinRM`, `certutil.exe`, `T1218` and `msbuild.exe` not mentioned in the security analysis but present in the examples given to him.

- Does the test case C work? If yes does it seem that giving various examples is the problem? 
A.: Yes, it did not use `T1102 -  Web Service`, the only example given (and of course not any of the things test case A used), also the example resulted on a valid syntax. HOWEVER, test case B used Rules with much more precision.

- Was being explicit that the only attack patterns to analyse were the reported worked?
A.: Yes, the test case B, compared to A, did not use any of the things test case A used outside of the security analysis scope. 

- Was giving few examples and being explicit about the restrictions good? (As this would be the best scenario)
A.: Yes! It did not use Rules as cleverly as the test case B but it is valid.

- Is giving more examples (test case B) is better than few (test case D) when being explicit?
A.: Only in terms of rule making.

- What seems the better strategy?
A.: Test case B seems like the better strategy. It benefits from "example dumping" but is not contaminated by them.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# What to do next?

I would like to test two different implementations:
	1. Giving attack patterns individually and ask for monitoring rules for each specific attack pattern 
	2. Dump all attack patterns (as it is being done now).
I would also like to add CAPEC related attack patterns of vulnerabilities which provide indicators.

So, given these two things to still test, I think there is still two more tests to do.