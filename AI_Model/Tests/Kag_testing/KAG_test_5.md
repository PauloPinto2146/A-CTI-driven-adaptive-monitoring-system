# Test 5

This test will evaluate the impact of adding examples of sysmon configuration files, namely from https://github.com/olafhartong/sysmon-modular.
I will be demonstrating two use cases:
- With examples in the second prompt
- Without examples in the second prompt
Both first prompts will be describing the host as a `server` with `HIGH` network exposure.
ADDITIONALLY, I will run 20 times the test to see how much valid sysmon configuration file are produced in each use case.

First prompt:
```
Consider:
These attack patterns: {attack_pattern_names_from_event}
These indicators of compromise: {ioc_dict}
These vulnerabilities: {cves}

The host's: 
  installed programs: {host_dict.get("programs")}
  services: {host_dict.get("services")}
  running processes: {host_dict.get("running_processes")}
  ports: {host_dict.get("ports")}

 
Create a contexted security analysis that details what information to monitor with sysmon, sepcifically for the NetworkConnect snippet.
Do NOT introduce anything that does not have to do with monitoring that could be noise, since your result will be used by another LLM.
Consider that the host being monitored is a server with HIGH network exposure.
``` 

And second prompt which uses: 
- A description of each parameter of `NetworkConnect`(https://networkforensic.dk/Sysmon/Files/Sysmon-Cheatsheet.pdf) 
- A description ofevery condition (https://learn.microsoft.com/pt-pt/sysinternals/downloads/sysmon)
- Examples (or not) of well-structured sysmon configuration files (https://github.com/olafhartong/sysmon-modular)
- The host network state, using functions from psutil (https://psutil.readthedocs.io/stable/) and window_tools library (https://pypi.org/project/windows-tools-installed-software/)

```
Use the following context:
{sysmon_context}

Learn from these examples of portions of NetworkConnect:
{get_network_connect_examples()}

Instruction:
Based on the security analysis previously done before and the host state:
{host_state}

Provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements. 
Try to avoid isolate rules that can produce a lot of noise, like isolating port 8080 in an open include box.
Follow the example format and populate the name attribute of the tags with the corresponding technique_id and technique_name whenever applicable.
Use the xml comment syntax to explain your choices.
```


And as always will be answering a couple of questions:
- Which of the two approaches was the best? With or Without examples?
- Does the example affect the second LLM respecting the security analysis?
- How many times did the two LLMs produced valid sysmon configuration files?
As well as taking conclusions and a comparative table between the two approaches.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# The security analysis done

### 1. Known Malicious Infrastructure (IOCs)
Monitor for any outbound connection where the destination IP matches the reported source list:
*   **Destination IP:** `185.216.70.170`, `77.90.38.170`, `154.216.19.224`, `154.216.17.157`, `176.65.141.201`, `176.65.141.232`, `206.123.145.13`

### 2. Exploit-Driven Egress (T1190 / CVE-2023-48788)
Since CVE-2023-48788 allows unauthorized code execution via SQL injection in FortiClientEMS, monitor for network connections initiated by the application process (or its children) that deviate from baseline behavior:
*   **Image:** Monitor `w3wp.exe` or the specific FortiClientEMS service process initiating outbound connections to external IPs, especially following the arrival of crafted packets.

### 3. Command and Control & Exfiltration (T1071.001, T1041, T1567, T1572)
Focus on processes that typically do not initiate network connections or use unusual protocols:
*   **Suspicious Images:** `powershell.exe`, `rundll32.exe`, `cmd.exe`, `certutil.exe`, `plink.exe`, `ssh.exe`, `netsh.exe`.
*   **Anomalous Destinations:** Connections from the above images to common web services (Dropbox, Google Drive, OneDrive) or unusual external ports (Protocol Tunneling).
*   **Behavioral Trigger:** Outbound connections from these images occurring shortly after a `ProcessCreate` event involving encoded commands or shell execution.

### 4. Post-Exploitation & Lateral Movement (T1021.001)
*   **RDP Activity:** Monitor for network connections on port 3389 (TCP/UDP) where the source is an internal IP but the subsequent activity involves the same host initiating new outbound connections to other internal assets (Lateral Movement).

### Summary of Monitoring Fields for `NetworkConnect`:
*   **DestinationIp:** Match against IOC list.
*   **Image:** Filter for `powershell.exe`, `rundll32.exe`, `w3wp.exe`, `cmd.exe`, `plink.exe`, `ssh.exe`.
*   **DestinationPort:** Monitor 80, 443 (Web C2/Exfil), 3389 (RDP), and non-standard ports used by tunneling tools.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# With examples


```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Monitor for connections to known malicious infrastructure (IOCs) -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!-- Monitor for Living off the Land binaries initiating network connections (C2, Exfil, Lateral Movement) -->
      <NetworkConnect onmatch="include">
        <Rule name="Suspicious Process Networking" groupRelation="or">
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
          <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
          <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- Monitor for critical remote access and management ports associated with lateral movement -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">22</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5985</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5986</DestinationPort>
      </NetworkConnect>

      <!-- Monitor for network activity from highly suspicious directories (Masquerading/Staging) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Public\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\wwwroot\</Image>
      </NetworkConnect>

      <!-- Specific monitor for CVE-2023-48788 / T1190: Monitoring application processes that shouldn't normally initiate external requests -->
      <NetworkConnect onmatch="include">
        <Rule name="App-Pool Egress" groupRelation="and">
          <Image condition="image">w3wp.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```


#### Time it took: 0 minutes and 26 seconds

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# No examples 

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <RuleGroup name="NetworkConnectMonitoring" groupid="3">
      <!--
        T1190: Exploit Public-Facing Application / CVE-2023-48788
        Monitoring for outbound connections from the system shell or potential
        entry points on a high-exposure server.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">cmd.exe</Image>
        <Image condition="image">powershell.exe</Image>
      </NetworkConnect>

      <!--
        T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service)
        Detects suspicious processes initiating outbound web traffic.
        Includes python.exe and rundll32.exe based on analysis of C2/Exfil patterns.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">python.exe</Image>
        <Image condition="image">rundll32.exe</Image>
        <Image condition="image">certutil.exe</Image>
        <DestinationPort condition="is">443</DestinationPort>
        <DestinationPort condition="is">80</DestinationPort>
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling
        Monitoring known tunneling tools or processes creating connections
        that could encapsulate other protocols.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">plink.exe</Image>
        <Image condition="image">ssh.exe</Image>
        <Image condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
        T1021.001: Remote Desktop Protocol
        Monitor for outbound RDP connections from the server to other hosts,
        indicating lateral movement.
      -->
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">3389</DestinationPort>
      </NetworkConnect>

      <!--
        IOC Match: Specific Malicious Infrastructure
        Directly monitoring the reported malicious IP addresses.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Noise Reduction:
        Exclude common legitimate browser traffic from known installed apps
        (Edge, Firefox) to avoid flooding logs on a high-exposure server.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">msedge.exe</Image>
        <Image condition="image">firefox.exe</Image>
        <Image condition="image">msedgewebview2.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 0 minutes and 45 seconds

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Questions answered

- Which of the two approaches was the best? With or Without examples?
A.: The one with examples seems better.
Positives:
  - it uses Rule names which can be helpful for analysis
  - it uses paths which can be more specific
  - it used knowledge from the Olaf Hartong data to enhance the T1021 monitoring
  - It created a rule specifically for the pair CVE-2023-48788 and AN0219
  - Unlike the second result, the first one did not ignore the w3wp.exe indicator of the CVE, and even added the Initiated tag as true to reduce some noise
  - Unlike the second result, the first one is a valid sysmon configuration file, the `group_id` parameter used in the second case makes it **invalid**
Negatives:
  - Unlike the second result, the first one did not try to reduce noise as I asked. May be because the examples do not have noise reduction?

- Does the example affect the second LLM respecting the security analysis?
A.: I don't really know why it ignored completely the recommendation of monitoring port 80 and 443, but besides that, seems fine.

- How many times did the two LLMs produced valid sysmon configuration files?
A.:
(see detailed results in file `KAG_test_5_20_exec_results.md`)

| Use case | How many valid? | How many invalid? | Average time building the XML | 
|:--------:|:---------------:|:-----------------:|:-----------------------------:|
| WITH examples | 20 | 0 | 25.5 seconds |
| WITHOUT examples | 0 | 20 | 25.75 seconds |


# Conclusions

Adding examples on the second prompt seems like a great idea. It is more organized and has less risk of being wrong (some outputs I got without examples were not correctly formed). However I am afraid that the examples could be outdated, eventhough they seem promissing in terms of quality.

# What to do next

- Probably ask the LLM to have a rule set for each attack pattern.
- Be more explicit of the necessity of being careful with the noise.
- Try to make risk assessment more prevalent. Try to ask him to make rules based on the risk. Maybe a third LLM could make changes to reduce noise.
- May try to make the first LLM split the security analysis into the different attack patterns