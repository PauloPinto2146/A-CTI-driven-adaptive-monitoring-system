# Test 4

This quick test will evaluate the impact of adding the host's state into the prompt, namely:

- The services running
- The network state (ports state)
- The installed programs

And additionally I will be adding them in two different scenarios:
- In the first prompt (where the security analysis is done)
- In the second prompt (where the sysmo config file creation is done)

Moreover, learning from experience in the last test, I added a brief sysmon context, where it explains all the relevant parameters in monitoring 

And as always will be answering a couple of questions:
- Did adding the host's state make it better than the last test?
- Which of the two approaches was the best?
- Did the security analysis in the first approach consider the host's state?
- Was adding the explanation of the sysmon NetworkConnect beneficial?
- Did the second answer from the LLM respect the first security analysis?



------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 
# Host's state first


Based on the provided attack patterns, indicators of compromise, and host configuration, the following specific telemetry should be monitored within Sysmon **Event ID 3 (NetworkConnect)**:

### 1. High-Priority IoC Matching
Monitor all outbound connections where the `DestinationIp` matches the known malicious source IPs:
*   `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`.

### 2. Process-to-Network Correlation (C2 & Exfiltration)
Monitor network connections initiated by processes that typically do not generate network traffic or are associated with the provided attack patterns (**T1071.001, T1041, T1567, T1059.001**):
*   **PowerShell Abuse:** `powershell.exe` establishing any outbound connection (specifically monitoring for high outbound-to-inbound data ratios).
*   **Living-off-the-Land Binaries (LOLbins):** `rundll32.exe`, `certutil.exe`, or `mshta.exe` initiating network connections.
*   **Unexpected System Processes:** `WmiPrvSE.exe` or `svchost.exe` (where the service is unusual) connecting to external IPs.
*   **Office/Productivity Apps:** `excel.exe`, `winword.exe`, or `outlook.exe` making HTTPS connections to external web services (e.g., Dropbox, Google Drive, OneDrive).

### 3. Protocol Tunneling & Service Abuse
Monitor for anomalous port/process pairings associated with **T1572**:
*   **Tunneling Tools:** `plink.exe`, `ssh.exe`, or `netsh.exe` initiating outbound connections.
*   **Port Mismatches:** Any process establishing connections over non-standard ports or using encapsulated protocols (e.g., RDP traffic over SSH/HTTPS).

### 4. Post-Exploit Egress (T1190)
Since the server has HIGH network exposure and a critical SQL injection vulnerability (**CVE-2023-48788**), monitor for:
*   **Web Server Egress:** Outbound connections initiated by the web server process (e.g., `w3wp.exe` or any process handling public-facing APIs) immediately following a shell spawn or the loading of a non-standard module.

### 5. Summary of Key Fields for Filtering
*   **Image:** Focus on `powershell.exe`, `rundll32.exe`, `certutil.exe`, `plink.exe`, `ssh.exe`, and web service processes.
*   **DestinationPort:** `443` (C2/Exfil), `22` (Tunneling), and any high-range ports associated with the reported IoCs.
*   **DestinationIp:** Cross-reference with the provided IoC list.

#### Time it took: 0 minutes and 18 seconds

```xml
<Sysmon subnet="NetworkConnect">
  <EventFiltering>
    <!-- 1. High-Priority IoC Matching: Direct detection of known malicious IPs -->
    <Rule group="level" name="IoC_Malicious_IPs" state="include">
      <DestinationIp>185.216.70.170</DestinationIp>
      <DestinationIp>77.90.38.170</DestinationIp>
      <DestinationIp>154.216.19.224</DestinationIp>
      <DestinationIp>154.216.17.157</DestinationIp>
      <DestinationIp>176.65.141.201</DestinationIp>
      <DestinationIp>176.65.141.232</DestinationIp>
      <DestinationIp>206.123.145.13</DestinationIp>
    </Rule>

    <!-- 2. PowerShell Abuse (T1059.001, T1071.001): Monitor outbound connections from PowerShell -->
    <Rule group="level" name="PowerShell_Network_Activity" state="include">
      <Image>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
      <Initiated condition="is">true</Initiated>
    </Rule>

    <!-- 3. Protocol Tunneling & LOLbins (T1572, T1071.001): Monitor tools used for encapsulation and C2 -->
    <Rule group="level" name="Tunneling_and_LOLbins" state="include">
      <Image condition="contains">plink.exe</Image>
      <Image condition="contains">ssh.exe</Image>
      <Image condition="contains">netsh.exe</Image>
      <Image condition="contains">certutil.exe</Image>
      <Image condition="contains">rundll32.exe</Image>
      <Image condition="contains">mshta.exe</Image>
      <Initiated condition="is">true</Initiated>
    </Rule>

    <!-- 4. Post-Exploit Egress (T1190): Monitor web-facing processes initiating outbound traffic -->
    <!-- Including w3wp.exe as a standard for IIS; the analyst should add specific API/web-service binaries here -->
    <Rule group="level" name="Web_Service_Egress" state="include">
      <Image condition="contains">w3wp.exe</Image>
      <Initiated condition="is">true</Initiated>
    </Rule>

    <!-- 5. Exfiltration via Office Apps (T1567): Monitor productivity apps making external connections -->
    <Rule group="level" name="Office_Exfiltration" state="include">
      <Image condition="contains">excel.exe</Image>
      <Image condition="contains">winword.exe</Image>
      <Image condition="contains">outlook.exe</Image>
      <Initiated condition="is">true</Initiated>
      <DestinationPort>443</DestinationPort>
    </Rule>
  </EventFiltering>
</Sysmon>
```
#### Time it took: 0 minutes and 10 seconds

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Host's state second


To monitor the high-exposure server for the specified attack patterns and indicators, Sysmon **NetworkConnect** (Event ID 3) should be filtered and monitored for the following specific telemetry:

### 1. High-Confidence Indicators (Direct IOCs)
*   **Destination IP Address:** Monitor for any outbound connections to:
    `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`.

### 2. Process-Network Correlation (T1190, T1059.001, T1071.001, T1567)
Monitor `NetworkConnect` events where the `Image` (process) is an atypical network initiator, specifically:
*   **Web Server Processes:** `w3wp.exe` (IIS) spawning outbound connections (indicative of post-exploit shells/callbacks following CVE-2023-48788 exploitation).
*   **Scripting/Shells:** `powershell.exe`, `pwsh.exe`, `cmd.exe`.
*   **Living-off-the-Land Binaries (LOLBins):** `rundll32.exe`, `mshta.exe`, `certutil.exe`.
*   **Office Applications:** `winword.exe`, `excel.exe` (potential T1567 exfiltration).

### 3. Protocol & Tunneling Anomalies (T1572, T1071.001, T1041)
Monitor `NetworkConnect` for specific binaries used for tunneling or C2:
*   **Tunneling Tools:** `plink.exe`, `ssh.exe`, `netsh.exe`.
*   **C2 Patterns:** Outbound connections on non-standard ports or high-volume HTTPS/DNS traffic initiated by the processes listed in Section 2.

### 4. Contextual Filtering for High-Exposure Servers
*   **Sourcing:** Focus on outbound connections (`DestinationIp`) originating from the server's public-facing application pools to identify the "post-exploit egress" phase of DET0080.
*   **Exfiltration:** Flag high-frequency `NetworkConnect` events to common web services (Dropbox, Google Drive, OneDrive) when initiated by `powershell.exe` or `w3wp.exe`.



#### Time it took: 0 minutes and 19 seconds

```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" groupID="3">
      <!--
        1. DIRECT IOC MATCHING
        Monitor any connection to the known malicious IP addresses reported.
        Correlates with: Reported IOCs (Medium threat level)
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp>185.216.70.170</DestinationIp>
        <DestinationIp>77.90.38.170</DestinationIp>
        <DestinationIp>154.216.19.224</DestinationIp>
        <DestinationIp>154.216.17.157</DestinationIp>
        <DestinationIp>176.65.141.201</DestinationIp>
        <DestinationIp>176.65.141.232</DestinationIp>
        <DestinationIp>206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        2. SUSPICIOUS PROCESS NETWORK ACTIVITY
        Monitor outbound connections from processes that should not typically
        initiate network traffic or are common vectors for post-exploit shells/C2.
        Correlates with: T1190 (Post-exploit egress), T1059.001 (PowerShell abuse),
        T1071.001 (Web C2), and T1567 (Web Service Exfiltration).
      -->
      <NetworkConnect onmatch="include">
        <!-- PowerShell is running on this host (PID 5488) and is a high-risk initiator -->
        <Image>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
        <!-- Common LOLBins used for tunneling or downloading second stage payloads -->
        <Image>C:\Windows\System32\rundll32.exe</Image>
        <Image>C:\Windows\System32\certutil.exe</Image>
        <Image>C:\Windows\System32\mshta.exe</Image>
        <!-- Tunneling tools specified in T1572 analysis -->
        <Image>plink.exe</Image>
        <Image>ssh.exe</Image>
        <Image>netsh.exe</Image>
        <!-- Web server process (w3wp.exe) initiating outbound traffic is highly suspicious -->
        <Image>w3wp.exe</Image>
      </NetworkConnect>

      <!--
        3. EXFILTRATION & C2 MONITORING
        Focus on outbound activity from the user's productivity tools that could be
        abused for T1567 (Exfiltration over Web Services).
      -->
      <NetworkConnect onmatch="include">
        <!-- Monitoring OneDrive as it is installed and used for exfiltration (T1567) -->
        <Image>C:\Program Files\Microsoft OneDrive\OneDrive.exe</Image>
        <Image>C:\Program Files\Microsoft OneDrive\26.088.0510.0004\OneDrive.Sync.Service.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 0 minutes and 11 seconds	
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Questions answered:

- Did adding the host's state make it better than the last test?
A.: Partially. In terms of precision on the paths, demonstrating that the LLM really considered the host's state (mostly in the second case). However, as showned in the first answer, there is room for halucination still.

- Which of the two approaches was the best?
A.: Definitely adding in the second prompt. Since in the first one it was not even considered the paths or services running.

- Did the security analysis in the first approach consider the host's state?
A.: Does not seem to

- Was adding the explanation of the sysmon NetworkConnect beneficial?
A.: It would've been in the first one if the syntax was not wrong, since it utilized the `Initiated` parameter. On the second one, seems to have little effect

- Did the second answer from the LLM respect the first security analysis?
A.:

| Use case | Did it respect the analysis? | What failed? | Time spent building the XML | 
|:--------:|:----------------------------:|:------------:|:---------------------------:|
| #1 | Partially | It ignored the port `22` referred. It ignored the `powershell.exe` that was on the summary of the analysis. Services `WmiPrvSE.exe` and `svchost.exe` were ignored. | 10 seconds |
| #2 | Partially | It did not use the `pwsh.exe` and `cmd.exe` indicated (and instead monitored the `OneDrive.exe`. Ignored the `excel.exe` and `windowd.exe` | 11 seconds |



# Conclusions

- This test makes it even more clear the one conclusion made in test 3: There is a necessity of examplifing what a sysmon configuration file looks like.
- Adding the host's state did something, but not as much as I expected.


# What to do next:
- I've seen this repository: https://github.com/olafhartong/sysmon-modular/ that seems to have great examples on how to configure sysmon. May try to use ICL with these.
- Be more explicit about the necessity of balancing risk and computational overhead
- May need to ask the first LLM to be less noisy and direct.
- May be beneficial to first ask for a security analysis, then ask for something like "Knowing these attack patterns and this attack, choose the services/programs/ports that must be monitored"