# Execution number 1

=========== WITH example (exec number 1) ===========
```xml
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <RuleGroup name="Contextual_Security_Analysis" groupRelation="or">
      <!--
           Include rules to capture high-risk activity based on the security analysis.
           We prioritize monitoring shell processes, tunneling tools, and known IOCs.
      -->
      <NetworkConnect onmatch="include">
        <!-- T1059.001: PowerShell and T1059.003: CMD - Monitoring for outbound C2 or exfiltration -->
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>

        <!-- T1572: Protocol Tunneling - Monitor tunneling tools identified in analysis -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1071.001 / T1041 / T1567: C2 and Exfiltration via LOLbins -->
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>

        <!-- T1190: Exploit Public-Facing Application - Monitoring for outbound callbacks from web-related processes -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- IOC Correlation: Monitor connections to the reported high-threat source IPs -->
        <Rule groupRelation="or">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>
      </NetworkConnect>

      <!--
           Exclude rules to reduce noise from known benign software installed on this host.
           This prevents the 'include' logic from being overwhelmed by legitimate updates and cloud sync.
      -->
      <NetworkConnect onmatch="exclude">
        <!-- Benign Cloud Services installed on host -->
        <Image condition="image">OneDrive.exe</Image>
        <Image condition="image">OneDrive.Sync.Service.exe</Image>

        <!-- Benign Browser traffic (High noise) -->
        <Image condition="image">firefox.exe</Image>
        <Image condition="image">msedge.exe</Image>

        <!-- Local LLM/Dev Tools frequently making local network calls -->
        <Image condition="image">ollama.exe</Image>
        <Image condition="image">python.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 32 seconds
=========== WITHOUT example (exec number 1) ===========
```xml
<Sysmon xmlns="http://www.microsoft.com/sysmonv2">
  <EventFiltering>
    <!--
      Event ID 3: Network connection monitoring
      Targeting high-exposure server assets based on identified attack patterns (T1190, T1059.001, T1071.001, T1572, T1041, T1567)
    -->
    <RuleGroup name="NetworkConnect" group="NetworkConnect">

      <!--
        T1190 & CVE-2023-48788:
        Monitor for outbound connections initiated by typical web server processes
        or unexpected shells spawning from them.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">w3wp.exe</Image>
        <Image condition="image">cmd.exe</Image>
        <Image condition="image">powershell.exe</Image>
      </NetworkConnect>

      <!--
        T1059.001, T1071.001, T1041, T1567:
        Monitor for network activity from shells, LOLbins, and productivity apps
        that can be used for C2, exfiltration, or arbitrary execution.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">rundll32.exe</Image>
        <Image condition="image">certutil.exe</Image>
        <Image condition="image">python.exe</Image>
        <Image condition="image">Excel.exe</Image>
        <Image condition="image">WinWord.exe</Image>
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling
        Monitor tools used for encapsulation/tunneling.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">plink.exe</Image>
        <Image condition="image">ssh.exe</Image>
        <Image condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
        IOC Correlation:
        Explicitly monitor connections to known high-threat IPs.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
      </NetworkConnect>

      <!--
        Noise Reduction:
        Exclude legitimate browsers and system updates to focus on suspicious process-to-network relationships.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">firefox.exe</Image>
        <Image condition="image">msedge.exe</Image>
        <Image condition="image">msedgewebview2.exe</Image>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 0 minutes and 58 seconds
#### With : Valid / Without : **Invalid** (xmlns ??)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 2

=========== WITH example (exec number 2) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Security Analysis Correlation" groupRelation="or">
      <!--
        T1071.001, T1041, T1567: Monitoring outbound connections from LOLBins and shells
        that are currently running on the host and are known to be used for C2 and Exfiltration.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
      </NetworkConnect>

      <!--
        IOC Correlation: Monitor any network activity involving the reported malicious IPs.
        Using 'is any' to capture the specific list of high-threat indicators.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        T1021.001: Monitoring RDP traffic.
        Since this is a high-exposure server, we monitor connections to port 3389
        to correlate with subsequent unusual process activity.
      -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
      </NetworkConnect>

      <!--
        T1190 & CVE-2023-48788: Monitor for abnormal outbound connections from the web-facing application.
        While w3wp.exe is not currently in the process list, it is the primary target for this exploit.
        We also monitor python.exe as it is running and often used in post-exploit payloads.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">python.exe</Image>
      </NetworkConnect>

      <!--
        T1036: Monitoring network connections from suspicious directories.
        Based on the host state, monitoring connections from AppData and Temp is critical for
        detecting dropped payloads from the listed vulnerabilities.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\AppData\\Local\\Temp\\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\AppData\\Roaming\\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\Temp\\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 1 minutes and 18 seconds

=========== WITHOUT example (exec number 2) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="NetworkConnect_Security_Analysis" group_id="1">
      <NetworkConnect onmatch="include">
        <!--
          T1071.001, T1041, T1567: Monitoring outbound C2 and Exfiltration.
          Correlation of known malicious IPs reported in the context.
        -->
        <Query name="T1071.001_Web_Protocols_IOCs">
          DestinationIp is any 185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13
        </Query>

        <!--
          T1190: Exploit Public-Facing Application.
          Since the host is high-exposure and vulnerable to CVE-2023-48788 (SQLi/RCE),
          we monitor the web server process initiating outbound connections.
        -->
        <Query name="T1190_Exploit_Public_Facing_Application">
          image is w3wp.exe
        </Query>

        <!--
          T1059.001: PowerShell Abuse.
          Monitoring PowerShell initiating network connections, a high-fidelity indicator of
          staged payloads or C2 communication.
        -->
        <Query name="T1059.001_PowerShell">
          image is powershell.exe
        </Query>

        <!--
          T1071.001, T1567: Monitoring common LOLBins used for network tunneling or data exfiltration.
        -->
        <Query name="T1071.001_LOLBins_Network">
          image is any rundll32.exe;cmd.exe
        </Query>

        <!--
          T1572: Protocol Tunneling.
          Monitoring specific tunneling tools listed in the analysis.
        -->
        <Query name="T1572_Protocol_Tunneling">
          image is any plink.exe;ssh.exe;netsh.exe
        </Query>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 0 minutes and 6 seconds
#### With : Valid / Without : **Invalid** (`<Query name="T1572_Protocol_Tunneling">`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 3

=========== WITH example (exec number 3) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Threat_Detection_NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Monitor connections to reported IOC IPs (Medium Threat Level) -->
        <Rule groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1059.001: PowerShell abuse for C2 or Exfiltration -->
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>

        <!-- T1071.001 & T1567: Web-based C2 and Exfiltration via suspicious processes -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>

        <!-- T1572: Protocol Tunneling tools -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1190: Exploit Public-Facing Application - Monitoring callbacks from the web server process -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- T1021.001: RDP based remote logins (Lateral Movement) -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>

        <!-- T1562.001: Monitoring network activity from tools used to disable security tools -->
        <Image name="technique_id=T1562.001,technique_name=Disable or Modify Tools" condition="image">taskkill.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 17 seconds
=========== WITHOUT example (exec number 3) ===========
```xml
<Sysmon schemaversion="4.8H">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" groupid="3">
      <!--
        T1071.001, T1572, T1041: Monitor outbound connections to known malicious IPs.
        Covers Command and Control and Exfiltration channels.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>

      <!--
        T1059.001, T1071.001, T1567: Detect PowerShell initiating network connections.
        PowerShell should not typically be making outbound HTTPS calls to web services on a server unless specifically configured.
      -->
      <NetworkConnect onmatch="include">
        <Image image="powershell.exe" />
      </NetworkConnect>

      <!--
        T1071.001: Detect rundll32.exe making network connections, often used for loading malicious DLLs for C2.
      -->
      <NetworkConnect onmatch="include">
        <Image image="rundll32.exe" />
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling.
        Monitor tools specifically mentioned in the analysis for encapsulating traffic (SSH, Plink, Netsh).
      -->
      <NetworkConnect onmatch="include">
        <Image contains any="plink.exe;ssh.exe;netsh.exe" />
      </NetworkConnect>

      <!--
        T1190 & CVE-2023-48788: Monitor for post-exploitation egress.
        Detecting the web server process (w3wp.exe) or other public-facing service processes
        initiating outbound connections, which is indicative of a reverse shell or callback after SQLi.
      -->
      <NetworkConnect onmatch="include">
        <Image image="w3wp.exe" />
      </NetworkConnect>

      <!--
        Noise Reduction: Exclude known legitimate browser traffic to prevent alerts
        from standard user activity (Firefox and Edge).
      -->
      <NetworkConnect onmatch="exclude">
        <Image contains any="firefox.exe;msedge.exe" />
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```


#### Time it took: 0 minutes and 8 seconds
#### With : Valid / Without : **Invalid** (`<Sysmon schemaversion="4.8H">`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 4

=========== WITH example (exec number 4) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!--
        C2 and Exfiltration Monitoring (T1071.001, T1567, T1041)
        Monitor network connections from high-risk LOLbins and shells.
        These processes should not typically initiate outbound connections on a production server.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>
      </NetworkConnect>

      <!--
        Protocol Tunneling and Remote Services (T1572, T1021.001)
        Monitor for RDP, SSH, and WinRM activity, and tools typically used for tunneling.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is any">5985;5986</DestinationPort>
        <DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">22</DestinationPort>
      </NetworkConnect>

      <!--
        Known IoC Correlation (Medium Threat Level)
        Specifically monitoring for the reported malicious source IPs.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Exploit Public-Facing Application (T1190 / CVE-2023-48788)
        Monitoring the worker process for abnormal outbound activity following a potential exploit.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>
      </NetworkConnect>

      <!--
        Masquerading and Suspicious Paths (T1036)
        Connections originating from temporary or user-writable directories.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Public\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 33 seconds
=========== WITHOUT example (exec number 4) ===========
```xml
<Sysmon SchemaVersion="4.8">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" groupCommit="false">
      <NetworkConnect onmatch="include">
        <!--
          T1071.001 / T1567: Monitor high-risk processes initiating outbound connections.
          Covers PowerShell (T1059.001) and common LOLbins used in C2/Exfiltration.
        -->
        <Image condition="image">powershell.exe</Image>
        <Image condition="image">rundll32.exe</Image>
        <Image condition="image">mshta.exe</Image>
        <Image condition="image">cmd.exe</Image>
        <Image condition="image">python.exe</Image>

        <!--
          T1572: Protocol Tunneling.
          Monitoring common tunneling binaries.
        -->
        <Image condition="image">plink.exe</Image>
        <Image condition="image">ssh.exe</Image>
        <Image condition="image">netsh.exe</Image>

        <!--
          T1567: Exfiltration over Web Service.
          Monitoring Office apps initiating network connections (as per security analysis).
        -->
        <Image condition="contains any">winword.exe;excel.exe</Image>
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          T1190 / CVE-2023-48788: Direct IoC matching for reported malicious IPs.
          These are specific high-fidelity indicators.
        -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          T1021.001: Remote Desktop Protocol.
          Monitoring for RDP (3389) activity to detect unauthorized remote access.
        -->
        <DestinationPort condition="is">3389</DestinationPort>
      </NetworkConnect>

      <NetworkConnect onmatch="exclude">
        <!--
          Noise Reduction: Exclude legitimate browser traffic to avoid flood of events,
          as the focus is on anomalous process-to-network relationships.
        -->
        <Image condition="image">firefox.exe</Image>
        <Image condition="image">msedge.exe</Image>
        <Image condition="image">msedgewebview2.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 0 minutes and 8 seconds
#### With : Valid / Without : **Invalid** (`groupCommit="false"`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 5

=========== WITH example (exec number 5) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Threat_Analysis_Correlation" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC Correlation: Monitor connections to identified high-threat IPs -->
        <Rule groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1190: Exploit Public-Facing Application - Monitor web server/service outbound callbacks -->
        <!-- Correlates with potential RCE from CVE-2023-48788 on high-exposure server -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- T1059.001 & T1567: PowerShell Abuse and Exfiltration over Web Services -->
        <!-- Monitoring powershell.exe for any outbound connection to identify C2 or cloud exfil -->
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>

        <!-- T1572: Protocol Tunneling - Monitor common tunneling tools -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>

        <!-- T1021.001: Remote Desktop Protocol - Monitor RDP outbound activity -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>

        <!-- T1071.001 & T1041: Web Protocols and Exfiltration Over C2 Channel -->
        <!-- Monitoring LOLbins that should not typically initiate outbound network connections -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" condition="image">regsvr32.exe</Image>

        <!-- T1562.001: Disable or Modify Tools - Monitoring network activity from taskkill (Remote process kill) -->
        <Image name="technique_id=T1562.001,technique_name=Disable or Modify Tools" condition="image">taskkill.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 22 seconds
=========== WITHOUT example (exec number 5) ===========
```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <!--
      Event ID 3: Network connection.
      This configuration focuses on the high-exposure server's risk profile:
      - Monitoring for identified IOC IPs.
      - Monitoring LOLbins and high-risk processes initiating outbound connections (T1190, T1071.001, T1572, T1567).
      - Monitoring for RDP lateral movement and tunneling (T1021.001).
    -->
    <RuleGroup name="NetworkConnect" group="networkconnect">
      <NetworkConnect onmatch="include">
        <!--
          Detection of connections to reported Medium threat IOC IPs.
          Covers multiple attack patterns (T1190, T1071.001, T1041, T1567)
        -->
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          T1059.001: PowerShell Abuse.
          Monitoring PowerShell outbound connections for C2 or Exfiltration (T1071.001, T1567, T1041).
        -->
        <Image image="powershell.exe" />
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          T1572: Protocol Tunneling and T1071.001: Web Protocols.
          Monitoring tools often used for tunneling or executing remote payloads.
        -->
        <Image contains any="ssh.exe;plink.exe;netsh.exe;rundll32.exe;certutil.exe" />
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          T1190: Exploit Public-Facing Application.
          Monitoring for a server process (like w3wp.exe or service hosts) making
          outbound connections, which is highly anomalous for a stable web app.
        -->
        <Image contains any="w3wp.exe;svchost.exe" />
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          T1021.001: Remote Desktop Protocol.
          Monitoring outbound connections on RDP port to detect lateral movement
          from this server to others in the network.
        -->
        <DestinationPort is="3389" />
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 12 seconds
#### With : Valid / Without : **Invalid** (`<DestinationPort is="3389" />`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 6


=========== WITH example (exec number 6) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Security Analysis Correlation" groupRelation="or">
      <!--
        Include: Monitor for known malicious IPs reported in IOCs.
        This directly addresses the identified threat actors.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Include: Monitor for Living-off-the-Land binaries (LOLbins) and shells
        initiating network connections, as identified in the security analysis for C2 and Exfiltration.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="Suspicious Process Networking" groupRelation="or">
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
          <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
          <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        </Rule>
      </NetworkConnect>

      <!--
        Include: Monitor for anomalous network activity from common application paths
        used in T1190 (Exploit Public-Facing Application) post-exploit callbacks.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>
      </NetworkConnect>

      <!--
        Include: Monitor for high-risk ports associated with Remote Services and Tunneling,
        excluding standard internal traffic where applicable to reduce noise.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="High Risk Ports" groupRelation="or">
          <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
          <DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">22</DestinationPort>
          <DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">23</DestinationPort>
        </Rule>
      </NetworkConnect>

      <!--
        Exclude: Filter out known legitimate traffic from installed software
        to reduce noise, specifically the high-volume cloud sync services present on the host.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">OneDrive.exe</Image>
        <Image condition="image">OneDriveStandaloneUpdater.exe</Image>
        <Image condition="end with">OneDrive.Sync.Service.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 19 seconds
=========== WITHOUT example (exec number 6) ===========
```xml
<Sysmon xmlns="http://www.microsoft.com/sysmonv3">
  <EventFiltering>
    <!-- NetworkConnect: Event ID 3 -->
    <NetworkConnect onmatch="include">

      <!--
        T1190: Exploit Public-Facing Application
        Monitor outbound callbacks from server processes (w3wp.exe)
        or system shells spawned after an exploit.
      -->
      <Rule group="T1190_Exploit_Public_Facing_Application" name="T1190">
        <Image>w3wp.exe</Image>
      </Rule>

      <!--
        T1059.001: PowerShell
        T1071.001: Web Protocols
        T1041: Exfiltration Over C2 Channel
        T1567: Exfiltration Over Web Service
        Monitor PowerShell making network connections, which is highly suspicious on a server.
      -->
      <Rule group="T1059.001_PowerShell" name="T1059.001">
        <Image>powershell.exe</Image>
      </Rule>

      <!--
        T1071.001: Web Protocols
        T1041: Exfiltration Over C2 Channel
        T1567: Exfiltration Over Web Service
        Monitor common LOLbins used for C2 or exfiltration.
      -->
      <Rule group="T1071.001_Web_Protocols" name="T1071.001">
        <Image>rundll32.exe</Image>
      </Rule>
      <Rule group="T1071.001_Web_Protocols" name="T1071.001">
        <Image>certutil.exe</Image>
      </Rule>

      <!--
        T1572: Protocol Tunneling
        Monitor tools explicitly used for tunneling (SSH/Plink)
        as specified in the security analysis.
      -->
      <Rule group="T1572_Protocol_Tunneling" name="T1572">
        <Image>plink.exe</Image>
      </Rule>
      <Rule group="T1572_Protocol_Tunneling" name="T1572">
        <Image>ssh.exe</Image>
      </Rule>
      <Rule group="T1572_Protocol_Tunneling" name="T1572">
        <Image>netsh.exe</Image>
      </Rule>

      <!--
        IOC Matching
        Directly monitor connections to known malicious source IPs
        provided in the IOC list.
      -->
      <Rule group="IOC_Malicious_IPs" name="Indicator_of_Compromise">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </Rule>

    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 8 seconds
#### With : Valid / Without : **Invalid** (`<Sysmon xmlns="http://www.microsoft.com/sysmonv3">`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 7

=========== WITH example (exec number 7) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- RuleGroup to monitor high-exposure server for specific attack patterns, IOCs, and vulnerabilities -->
    <RuleGroup name="Security_Analysis_Network_Monitoring" groupRelation="or">
      <NetworkConnect onmatch="include">

        <!-- 1. High-Priority IOCs: Monitoring connections to known malicious IPs -->
        <Rule groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- 2. PowerShell Abuse and Web C2 (T1059.001, T1071.001) -->
        <!-- Monitoring PowerShell and Shells initiating network connections -->
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">OpenConsole.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">WindowsTerminal.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>

        <!-- 3. LOLBins and Protocol Tunneling (T1071.001, T1572) -->
        <!-- Monitoring tools capable of outbound callbacks or encapsulation -->
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>

        <!-- 4. Remote Access and Lateral Movement (T1021.001) -->
        <!-- Monitoring RDP and WinRM ports -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5985</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5986</DestinationPort>

        <!-- 5. Exfiltration and Web Services (T1041, T1567) -->
        <!-- Monitoring processes that should not typically communicate with the internet -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">regedit.exe</Image>

        <!-- 6. Web Application Exploitation (T1190, CVE-2023-48788) -->
        <!-- Monitoring for outbound callbacks from potential exploit targets -->
        <!-- Note: w3wp.exe is the standard IIS worker process; adding based on analysis of T1190 -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- 7. Suspicious Path Masquerading (T1036) -->
        <!-- Monitoring network connections from temp or user-writable directories -->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\ProgramData</Image>

      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 29 seconds
=========== WITHOUT example (exec number 7) ===========
```xml
<Sysmon schemaversion="4.85">
  <EventFiltering>
    <!--
      NetworkConnect Event ID 3:
      Focused on high-exposure server monitoring for C2, Exfiltration,
      and exploitation callbacks based on provided security analysis.
    -->
    <RuleGroup name="NetworkConnect" group_id="3">

      <!-- 1. IOC Monitoring: Immediate alert for connections to known malicious source IPs -->
      <NetworkConnect onmatch="include">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>

      <!-- 2. Process-to-Network Correlation: Monitoring non-standard processes initiating outbound connections -->
      <!-- T1059.001: PowerShell Abuse & T1071.001: Web Protocols C2 -->
      <NetworkConnect onmatch="include">
        <Image image="powershell.exe" />
      </NetworkConnect>

      <!-- T1071.001 & T1572: Protocol Tunneling/C2 via LOLbins -->
      <NetworkConnect onmatch="include">
        <Image contains any="rundll32.exe;certutil.exe;netsh.exe;ssh.exe;plink.exe" />
      </NetworkConnect>

      <!-- T1190 & CVE-2023-48788: Exploitation callbacks from server-facing processes -->
      <!-- Monitoring for unexpected outbound traffic from W3WP or high-exposure apps -->
      <NetworkConnect onmatch="include">
        <Image image="w3wp.exe" />
      </NetworkConnect>

      <!-- 3. Lateral Movement: Monitoring RDP inbound for unusual activity -->
      <!-- T1021.001: Remote Desktop Protocol -->
      <NetworkConnect onmatch="include">
        <DestinationPort is="3389" />
      </NetworkConnect>

      <!-- 4. Exfiltration & Tunneling: Identifying anomalous patterns -->
      <!-- T1567: Exfiltration over Web Service (e.g., OneDrive) -->
      <!-- We monitor OneDrive.exe but focus on outbound patterns via analysis logic;
           here we include it to ensure we capture the connection for volume analysis -->
      <NetworkConnect onmatch="include">
        <Image image="OneDrive.exe" />
      </NetworkConnect>

      <!-- Noise Reduction: Exclude known legitimate high-volume browser traffic to avoid flooding logs -->
      <NetworkConnect onmatch="exclude">
        <Image contains any="firefox.exe;msedge.exe;msedgewebview2.exe" />
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 19 seconds
#### With : Valid / Without : **Invalid** (`<DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 8

=========== WITH example (exec number 8) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Security Analysis Monitoring" groupRelation="or">
      <!--
        T1190: Exploit Public-Facing Application / CVE-2023-48788
        Monitoring processes that should not initiate outbound connections.
        Since the host has high exposure, we track shells or unexpected binaries
        spawned by a potential exploit initiating network callbacks.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">rundll32.exe</Image>

        <!-- T1059.001: Abuse of PowerShell for Arbitrary Execution -->
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">OpenConsole.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">WindowsTerminal.exe</Image>

        <!-- T1071.001 / T1567: Web Protocols / Exfiltration Over Web Service -->
        <!-- Monitor LOLbins initiating outbound HTTPS connections -->
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">mshta.exe</Image>

        <!-- T1572: Protocol Tunneling -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
        IoC Monitoring: Specific malicious source IPs reported
        This catches any process communicating with the identified threat actors.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="Threat_Actor_IoC" groupRelation="or">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>
      </NetworkConnect>

      <!--
        T1021.001: Remote Desktop Protocol
        Monitoring RDP port usage by non-standard processes.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="RDP_Abuse" groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <Image condition="is not">svchost.exe</Image>
        </Rule>
      </NetworkConnect>

      <!--
        T1036: Masquerading / Suspicious Paths
        Monitoring network activity from temp folders or user app data,
        as the host is a server and legit apps should be in Program Files.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Public\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 30 seconds
=========== WITHOUT example (exec number 8) ===========
```xml
<Sysmon schemaversion="4.8">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" group="networkconnect">
      <!--
        DET0080 / T1190: Exploit Public-Facing Application.
        Monitor for outbound connections initiated by common web/service processes
        that could indicate a reverse shell or post-exploit callback following
        the exploitation of CVE-2023-48788.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains">w3wp.exe</Image>
        <Image condition="contains">FortiClientEMS</Image>
      </NetworkConnect>

      <!--
        DET0455 / T1059.001: Abuse of PowerShell for Arbitrary Execution.
        DET0027 / T1071.001: Web Protocols C2.
        DET0348 / T1041: Exfiltration Over C2 Channel.
        DET0548 / T1567: Exfiltration Over Web Service.
        Monitor PowerShell initiating network connections, which is a high-fidelity indicator
        of C2 activity or data exfiltration.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">powershell.exe</Image>
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling.
        Monitor for known tunneling tools creating outbound connections.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains any">plink.exe;ssh.exe;netsh.exe</Image>
      </NetworkConnect>

      <!--
        IoC Monitoring: Medium threat level IP addresses reported.
        Matches any network connection involving the identified suspicious source IPs.
      -->
      <NetworkConnect onmatch="include">
        <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        DET0548 / T1567: Exfiltration Over Web Service.
        Monitor for productivity software (Microsoft 365 Apps) initiating connections
        that could be used to mask exfiltration to cloud services.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains any">winword.exe;excel.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 8 seconds
#### With : Valid / Without : **Invalid** (`group="networkconnect"`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 9

=========== WITH example (exec number 9) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!--
        Sourcing monitoring from identified IOCs.
        Directly matching the reported malicious source IPs.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Monitoring for Post-Exploit Egress and Shells (T1190, T1059.001, T1071.001).
        Includes LOLbins and interpreters that should not typically initiate outbound connections on a high-exposure server.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="Suspicious Process Networking" groupRelation="or">
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
          <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        </Rule>
      </NetworkConnect>

      <!--
        Monitoring for Protocol Tunneling and Remote Access (T1572, T1021.001).
        Focuses on administrative ports when used by non-standard processes.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="Abnormal Remote Admin Traffic" groupRelation="and">
          <DestinationPort condition="is any">22;3389;5985;5986</DestinationPort>
          <Image condition="is not">C:\Windows\System32\svchost.exe</Image>
        </Rule>
      </NetworkConnect>

      <!--
        Monitoring for Masquerading and Execution from suspicious paths (T1036).
        High-exposure servers often see exploits dropping payloads into Temp or AppData.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\ProgramData\</Image>
      </NetworkConnect>

      <!--
        Exclusions to reduce noise.
        Excluding known legitimate high-volume services found in host state (Edge, Firefox, OneDrive).
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">msedge.exe</Image>
        <Image condition="image">firefox.exe</Image>
        <Image condition="image">OneDrive.exe</Image>
        <Image condition="image">ollama.exe</Image> <!-- Legitimate local LLM service found in running processes -->
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 23 seconds
=========== WITHOUT example (exec number 9) ===========
```xml
<Sysmon schemaversion="4.85">
  <EventFiltering>
    <!--
      Event ID 3: Network connection
      Focus: High-exposure server monitoring for post-exploit egress, C2, and exfiltration.
    -->
    <Rule group="networkconnect">
      <!--
        T1190: Exploit Public-Facing Application
        Monitoring for reverse shells or callbacks initiated by common web server
        worker processes or shells following a potential exploit.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains">w3wp.exe</Image>
        <Image condition="image">cmd.exe</Image>
        <Image condition="image">powershell.exe</Image>
      </NetworkConnect>

      <!--
        T1059.001: PowerShell
        T1071.001: Web Protocols
        T1567: Exfiltration Over Web Service
        Detecting PowerShell initiating network connections, which is a strong
        indicator of C2 or data exfiltration from a server context.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">powershell.exe</Image>
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling
        Monitoring tools specifically identified as being used for tunneling
        or asymmetric network traffic.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains">plink.exe</Image>
        <Image condition="contains">ssh.exe</Image>
        <Image condition="contains">netsh.exe</Image>
      </NetworkConnect>

      <!--
        T1041: Exfiltration Over C2 Channel / General Post-Exploit
        Monitoring binaries that typically should not be initiating outbound
        network connections on a production server.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">rundll32.exe</Image>
        <Image condition="image">certutil.exe</Image>
      </NetworkConnect>

      <!--
        High-Priority IOC Monitoring
        Direct match for the reported malicious source IPs.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Noise Reduction
        Excluding standard browser traffic from the high-exposure server to
        reduce false positives, focusing instead on the processes above.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="contains">firefox.exe</Image>
        <Image condition="contains">msedge.exe</Image>
      </NetworkConnect>
    </Rule>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 11 seconds
#### With : Valid / Without : **Invalid** (`group="networkconnect"`)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 10

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Threat_Analysis_Network_Monitoring" groupRelation="or">
      <!--
           T1190: Exploit Public-Facing Application.
           Monitoring for the reported malicious IPs.
           High priority due to CVE-2023-48788 vulnerability.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
           T1059.001: PowerShell & T1567: Exfiltration Over Web Service.
           Monitor PowerShell making outbound connections, as it is currently running on the host.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
      </NetworkConnect>

      <!--
           T1572: Protocol Tunneling & T1041: Exfiltration Over C2 Channel.
           Monitoring tools commonly used for tunneling/exfiltration that are native or likely to be used.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
           T1021.001: Remote Desktop Protocol.
           Monitoring for RDP outbound connections (3389) to detect lateral movement from this high-exposure host.
      -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
      </NetworkConnect>

      <!--
           T1036: Masquerading.
           Monitoring network connections from highly suspicious directories (Temp, AppData)
           to catch payloads dropped by the public-facing exploit (T1190).
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Roaming\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 18 seconds
=========== WITHOUT example (exec number 10) ===========
```xml
<Sysmon xmlns="http://www.microsoft.com/windows/configuration/sysmon">
  <EventFiltering>
    <RuleGroup name="networkconnect" groupName="networkconnect">
      <NetworkConnect onmatch="include">
        <!-- T1190 / CVE-2023-48788: Monitoring high-exposure server processes for unusual outbound connections following a potential exploit -->
        <Image name="T1190_Exploit Public-Facing Application" condition="contains any">w3wp.exe;aspnet_isapi.dll</Image>

        <!-- T1059.001 / T1567: PowerShell abuse for arbitrary execution and exfiltration to web services -->
        <Image name="T1059.001_PowerShell" condition="image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>

        <!-- T1572 / T1041: Tunneling and Exfiltration using legitimate binaries (LOLbins) -->
        <Image name="T1572_Protocol Tunneling" condition="contains any">plink.exe;ssh.exe;netsh.exe</Image>
        <Image name="T1041_Exfiltration Over C2 Channel" condition="image">C:\Windows\System32\rundll32.exe</Image>
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!-- Immediate Indicator Monitoring: Tracking reported malicious source IPs -->
        <DestinationIp name="IOC_Malicious_IPs" condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <NetworkConnect onmatch="exclude">
        <!-- Noise Reduction: Excluding standard browser traffic from installed programs to focus on process-based anomalies -->
        <Image name="Noise_Reduction_Browsers" condition="contains any">firefox.exe;msedge.exe;msedgewebview2.exe</Image>
        <!-- Noise Reduction: Excluding known benign cloud storage sync processes already established in host state -->
        <Image name="Noise_Reduction_OneDrive" condition="contains">OneDrive.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 7 seconds
#### With : Valid / Without : **Invalid** (`<Sysmon xmlns="http://www.microsoft.com/windows/configuration/sysmon">`)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 11

=========== WITH example (exec number 11) ===========
```xml
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <RuleGroup name="Security Analysis - Network Connect" groupRelation="or">
      <!--
        MATCHING IOCs:
        Monitor outbound connections to known malicious IP addresses reported.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        SHELLS AND LOLBINS (T1059.001, T1071.001, T1567):
        Detecting shells or system binaries initiating network connections,
        which is highly indicative of C2 or data exfiltration on a high-exposure server.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="Shells and LOLbins" groupRelation="or">
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
          <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        </Rule>
      </NetworkConnect>

      <!--
        PROTOCOL TUNNELING & REMOTE ACCESS (T1572, T1021.001):
        Monitoring tools typically used for SSH tunneling or RDP access.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="Tunneling and Remote Access" groupRelation="or">
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
          <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        </Rule>
      </NetworkConnect>

      <!--
        SENSITIVE PATHS (T1036):
        Network connections originating from temp or user profile directories
        instead of Program Files, indicative of payload execution.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\ProgramData</Image>
      </NetworkConnect>

      <!--
        CVE-2023-48788 & T1190:
        While FortiClientEMS is not in the current running process list,
        we monitor for any high-risk service process (like w3wp.exe)
        initiating outbound connections after a potential exploit.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 13 seconds
=========== WITHOUT example (exec number 11) ===========
```xml
<Sysmon SchemaId="4.84">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" group_id="3">
      <!--
        T1071.001, T1567, T1041: Monitor outbound C2 and Exfiltration.
        Focus on high-risk processes initiating connections to common web ports (80, 443).
        Excludes known browsers (Firefox, Edge) to reduce noise on a high-exposure server.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains any">powershell.exe;cmd.exe;rundll32.exe;certutil.exe;python.exe</Image>
        <DestinationPort condition="is any">80;443</DestinationPort>
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling.
        Detects known tunneling tools or administrative tools used for encapsulation.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains any">plink.exe;ssh.exe;netsh.exe</Image>
      </NetworkConnect>

      <!--
        T1190: Exploit Public-Facing Application.
        Monitor for post-exploit egress. Since this is a server, we track
        unusual process-to-network relationships, specifically shell spawns
        from service accounts or unusual binaries.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains">w3wp.exe</Image>
      </NetworkConnect>

      <!--
        IOC Matching: Direct monitoring for reported malicious source IPs.
        This provides high-fidelity alerts regardless of the process initiating the connection.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Noise Reduction: Exclude legitimate browser traffic to prevent flooding the logs,
        as these are expected to communicate over 80/443 on a high-exposure host.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="contains any">firefox.exe;msedge.exe;msedgewebview2.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 14 seconds
#### With : Valid / Without : **Invalid** (`<Sysmon SchemaId="4.84">`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 12

=========== WITH example (exec number 12) ===========
```xml
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <RuleGroup name="C2 and Exfiltration Detection" groupRelation="or">
      <!--
        T1190 & CVE-2023-48788: Monitor for the reported malicious IPs.
        High priority as these are known IOCs.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        T1059.001 & T1071.001: PowerShell and shells initiating network connections.
        Consistent with the current running processes (powershell.exe, cmd.exe).
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">OpenConsole.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">WindowsTerminal.exe</Image>
      </NetworkConnect>

      <!--
        T1572 & T1021.001: Protocol Tunneling and Remote Services.
        Monitoring for tunneling tools (plink, ssh) and sensitive remote ports.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
      </NetworkConnect>

      <!--
        T1567 & T1041: Exfiltration via Web Services or C2.
        Monitoring common LOTL binaries that should not typically communicate externally on a server.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
      </NetworkConnect>

      <!--
        T1036: Masquerading/Suspicious Paths.
        Filtering for network activity coming from temporary or user-profile directories.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\wwwroot\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\htdocs\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 15 seconds
=========== WITHOUT example (exec number 12) ===========
```xml
<Sysmon schemaversion="4.85">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" groupid="3">
      <!--
        1. MONITORING KNOWN MALICIOUS INFRASTRUCTURE (IOCs)
        Direct match for the provided high-threat source IPs acting as destinations.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
        <Tag name="T1071.001-Web Protocols" />
      </NetworkConnect>

      <!--
        2. POWERSHELL & SCRIPTING ABUSE (T1059.001 / T1071.001)
        Monitoring outbound connections from PowerShell, which is currently running on the host.
        Excluded common internal loopback to reduce noise.
      -->
      <NetworkConnect onmatch="include">
        <Image image="powershell.exe" />
        <DestinationIp is not="127.0.0.1" />
        <Tag name="T1059.001-PowerShell" />
        <Tag name="T1071.001-Web Protocols" />
      </NetworkConnect>

      <!--
        3. TUNNELING AND EXFILTRATION TOOLS (T1572)
        Monitoring for the execution of common tunneling binaries.
        While not currently in the 'running processes' list, they are key indicators for this attack pattern.
      -->
      <NetworkConnect onmatch="include">
        <Image contains any="plink.exe;ssh.exe;netsh.exe" />
        <Tag name="T1572-Protocol Tunneling" />
      </NetworkConnect>

      <!--
        4. EXFILTRATION VIA PRODUCTIVITY APPS (T1567)
        Monitoring network connections from Office apps (Excel, Word) and OneDrive
        which are installed on the host, as they are leveraged for data exfiltration.
      -->
      <NetworkConnect onmatch="include">
        <Image contains any="winword.exe;excel.exe;OneDrive.exe" />
        <DestinationPort is="443" />
        <Tag name="T1567-Exfiltration Over Web Service" />
      </NetworkConnect>

      <!--
        5. EXPLOIT POST-EXECUTION / ANOMALOUS PROCESSES (T1190 / CVE-2023-48788)
        Monitoring network activity from the CMD shell or Python (found in running processes),
        as these are often used for callbacks after a successful web exploit (C2).
      -->
      <NetworkConnect onmatch="include">
        <Image contains any="cmd.exe;python.exe" />
        <DestinationIp is not="127.0.0.1" />
        <Tag name="T1190-Exploit Public-Facing Application" />
        <Tag name="T1041-Exfiltration Over C2 Channel" />
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 1 minutes and 12 seconds
#### With : Valid / Without : **Invalid** (`<Tag name="T1572-Protocol Tunneling" />` for example)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 13

=========== WITH example (exec number 13) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Security Analysis Correlation" groupRelation="or">
      <!--
        C2 and Exfiltration Detection (T1071.001, T1567, T1041)
        Monitoring LOLBins and unexpected processes initiating outbound connections.
        Based on the running processes list, we specifically track PowerShell and CMD.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
      </NetworkConnect>

      <!--
        Protocol Tunneling and Remote Services (T1572, T1021.001)
        Monitoring for SSH, Telnet, and RDP outbound activity from any process.
      -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1572,technique_name=Protocol Tunneling" condition="is">22</DestinationPort>
        <DestinationPort name="technique_id=T1572,technique_name=Protocol Tunneling" condition="is">23</DestinationPort>
      </NetworkConnect>

      <!--
        IOC Matching: Known Malicious IPs
        Direct monitoring for connections to the reported threat actors.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Masquerading and Suspicious Paths (T1036)
        Monitoring network connections originating from temp or user directories,
        as these are high-exposure vectors for payloads dropped via CVE-2023-48788.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\wwwroot\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\htdocs\</Image>
      </NetworkConnect>

      <!--
        False Positive Reduction (Noise Filtering)
        Excluding legitimate high-volume traffic from installed programs to prevent alert fatigue.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">OneDrive.exe</Image> <!-- Microsoft OneDrive -->
        <Image condition="image">firefox.exe</Image> <!-- Mozilla Firefox -->
        <Image condition="image">msedge.exe</Image> <!-- Microsoft Edge -->
        <Image condition="image">ollama.exe</Image> <!-- Ollama Local AI -->
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 18 seconds
=========== WITHOUT example (exec number 13) ===========
```xml
<Sysmon xmlns="http://www.microsoft.com/sysmonv2">
  <EventFiltering>
    <!--
      NetworkConnect (Event ID 3) Monitoring Strategy
      Focus: High-exposure server protection against CVE-2023-48788 and listed attack patterns.
    -->
    <NetworkConnect onmatch="include">

      <!--
        IOC Matching: Monitor connections to known malicious IPs
        Identified as Medium threat level in reports.
      -->
      <ImageCid name="IOC_Known_Malicious_IPs">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </ImageCid>

      <!--
        T1059.001 / T1071.001: Abuse of PowerShell for C2 or arbitrary execution.
        Direct monitoring of powershell.exe making network connections.
      -->
      <ImageCid name="T1059.001_PowerShell">
        <Image image="powershell.exe" />
      </ImageCid>

      <!--
        T1071.001 / T1567: Use of LOLbins or productivity apps for C2/Exfiltration.
        Monitoring common processes that should not typically initiate external network traffic on a server.
      -->
      <ImageCid name="T1071.001_Web_Protocols_T1567_Exfil_Web_Service">
        <Image contains any="rundll32.exe;cmd.exe;certutil.exe;excel.exe;winword.exe" />
      </ImageCid>

      <!--
        T1572: Protocol Tunneling.
        Monitoring specific binaries known for tunneling/SSH encapsulated traffic.
      -->
      <ImageCid name="T1572_Protocol_Tunneling">
        <Image contains any="plink.exe;ssh.exe;netsh.exe" />
      </ImageCid>

      <!--
        T1190 / CVE-2023-48788: Exploit Public-Facing Application.
        Monitoring for outbound callbacks from web server processes or potential RCE outcomes.
        Note: w3wp.exe is the standard IIS worker process.
      -->
      <ImageCid name="T1190_Exploit_Public_Facing_App">
        <Image image="w3wp.exe" />
      </ImageCid>

    </NetworkConnect>

    <!--
      Exclusion rules to reduce noise from legitimate high-volume traffic
      based on the host's installed programs (Browsers, OS Updates).
    -->
    <NetworkConnect onmatch="exclude">
      <!-- Exclude legitimate browser traffic to avoid noise in high-exposure environments -->
      <ImageCid name="Noise_Reduction_Browsers">
        <Image contains any="firefox.exe;msedge.exe;msedgewebview2.exe" />
      </ImageCid>
      <!-- Exclude legitimate system/update processes -->
      <ImageCid name="Noise_Reduction_System">
        <Image contains any="MicrosoftEdgeUpdate.exe;OneDrive.exe;MpDefenderCoreService.exe;MsMpEng.exe" />
      </ImageCid>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```
#### Time it took: 0 minutes and 14 seconds
#### With : Valid / Without : **Invalid** (`<Sysmon xmlns="http://www.microsoft.com/sysmonv2">`)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 14

=========== WITH example (exec number 14) ===========
```xml
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <RuleGroup name="High Exposure Server Analysis" groupRelation="or">
      <!--
        Sourcing connections from typical LOLBins or shells used for C2,
        Exfiltration, and post-exploit activity following T1190/CVE-2023-48788.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
        Direct monitoring of known malicious Source IPs reported in IOCs.
        Correlates with T1071.001, T1041, and T1567.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Detection of Remote Access patterns (T1021.001) and Non-Standard Ports (T1571).
        Combined with image filters to reduce noise from legitimate system services.
      -->
      <NetworkConnect onmatch="include">
        <Rule name="Suspicious Remote Access/Tunneling" groupRelation="and">
          <DestinationPort condition="is any">3389;22;5900;5985;5986</DestinationPort>
          <Image condition="is not">C:\Windows\System32\lsass.exe</Image>
        </Rule>
      </NetworkConnect>

      <!--
        Monitoring for Masquerading (T1036) and data exfiltration from unusual paths.
        Targets common staging areas for malware and unauthorized tools.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\wwwroot\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\htdocs\</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 17 seconds
=========== WITHOUT example (exec number 14) ===========
```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" groupid="3">
      <!--
        T1071.001, T1041, T1567:
        Monitor all outbound connections to the specific high-threat IP addresses provided in the IOC list.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>

      <!--
        T1190, T1059.001:
        Monitor high-risk processes (Shells and LOLBins) initiating network connections.
        This detects post-exploitation C2 or payload delivery following a vulnerability exploit (e.g., CVE-2023-48788).
      -->
      <NetworkConnect onmatch="include">
        <Image image="powershell.exe" />
        <Image image="cmd.exe" />
        <Image image="rundll32.exe" />
        <Image image="certutil.exe" />
        <Image image="mshta.exe" />
        <Image image="python.exe" />
      </NetworkConnect>

      <!--
        T1572:
        Monitor known tunneling and proxy tools creating outbound connections.
      -->
      <NetworkConnect onmatch="include">
        <Image image="plink.exe" />
        <Image image="ssh.exe" />
        <Image image="netsh.exe" />
      </NetworkConnect>

      <!--
        T1021.001:
        Monitor for unexpected RDP activity (Port 3389) on this high-exposure server.
      -->
      <NetworkConnect onmatch="include">
        <DestinationPort is="3389" />
      </NetworkConnect>

      <!--
        Noise Reduction:
        Exclude known legitimate browsers and communication apps from general network logging
        to avoid flooding the logs, as they typically generate high volume on 80/443.
      -->
      <NetworkConnect onmatch="exclude">
        <Image image="firefox.exe" />
        <Image image="msedge.exe" />
        <Image image="ms-teams.exe" />
        <Image image="OneDrive.exe" />
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 1 minutes and 55 seconds
#### With : Valid / Without : **Invalid** (`<DestinationPort is="3389" />` for example)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 15

=========== WITH example (exec number 15) ===========
```xml
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <!--
      The following rules are designed for a high-exposure server to detect the specified
      attack patterns: T1190, T1059.001, T1021.001, T1562.001, T1497.001, T1071.001, T1572, T1041, T1486, T1567
      and monitoring for CVE-2023-48788.
    -->
    <RuleGroup name="Threat_Detection_Network_Connect" groupRelation="or">
      <NetworkConnect onmatch="include">

        <!-- Direct IOC Monitoring: Medium threat level reported IPs -->
        <Rule name="IOC_External_C2" groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- Behavioral Monitoring: Shells and Interpreters making network connections (T1059.001, T1071.001) -->
        <Rule name="technique_id=T1059.001,technique_name=PowerShell" groupRelation="or">
          <Image condition="image">powershell.exe</Image>
          <Image condition="image">cmd.exe</Image>
          <Image condition="image">python.exe</Image>
        </Rule>

        <!-- Behavioral Monitoring: LOLBins used for C2/Exfiltration/Tunneling (T1071.001, T1572, T1041, T1567) -->
        <Rule name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" groupRelation="or">
          <Image condition="image">rundll32.exe</Image>
          <Image condition="image">certutil.exe</Image>
          <Image condition="image">regsvr32.exe</Image>
          <Image condition="image">mshta.exe</Image>
        </Rule>

        <!-- Protocol Tunneling tools (T1572) -->
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="or">
          <Image condition="image">plink.exe</Image>
          <Image condition="image">ssh.exe</Image>
          <Image condition="image">netsh.exe</Image>
        </Rule>

        <!-- Remote Management and Access (T1021.001) -->
        <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="or">
          <DestinationPort condition="is">3389</DestinationPort>
          <DestinationPort condition="is">5985</DestinationPort> <!-- WinRM -->
          <DestinationPort condition="is">5986</DestinationPort> <!-- WinRM HTTPS -->
        </Rule>

        <!--
          Monitoring for CVE-2023-48788 / T1190:
          Detecting the web server process (or potential shell spawn from it) initiating outbound connections.
        -->
        <Rule name="technique_id=T1190,technique_name=Exploit Public-Facing Application" groupRelation="or">
          <Image condition="image">w3wp.exe</Image>
        </Rule>

        <!-- Monitoring for Exfiltration via common web services using non-standard processes (T1567, T1041) -->
        <!-- Note: we monitor the destination if the image is not a standard browser -->
        <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
          <DestinationHostname condition="contains any">dropbox.com;google.com;onedrive.com</DestinationHostname>
          <Image condition="is not">firefox.exe</Image>
          <Image condition="is not">msedge.exe</Image>
        </Rule>

      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 19 seconds
#### With : Valid / Without : **Invalid** (`<Sysmon SchemaId="4.84">`)


=========== WITHOUT example (exec number 15) ===========
```xml
<!--
  Sysmon Event ID 3: Network Connection Monitoring
  Target: High Network Exposure Server
  Focus: CVE-2023-48788 (SQLi/RCE), C2 Communication, and Exfiltration
-->
<Sysmon schemaversion="4.85">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" group="NetworkConnect">

      <!-- 1. Direct IOC Monitoring: High-confidence match for reported malicious IPs -->
      <NetworkConnect onmatch="include">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>

      <!-- 2. Behavioral Monitoring: Suspicious process-to-network relationships -->
      <!-- T1059.001: PowerShell abuse; T1071.001: Web Protocols C2; T1567: Exfiltration over Web Service -->
      <NetworkConnect onmatch="include">
        <Image image="powershell.exe" />
        <Image image="cmd.exe" />
        <Image image="rundll32.exe" />
        <Image image="certutil.exe" />
      </NetworkConnect>

      <!-- 3. Protocol Tunneling and Unauthorized Tooling -->
      <!-- T1572: Protocol Tunneling using SSH/Plink/Netsh -->
      <NetworkConnect onmatch="include">
        <Image image="plink.exe" />
        <Image image="ssh.exe" />
        <Image image="netsh.exe" />
      </NetworkConnect>

      <!-- 4. Exfiltration from Productivity Apps -->
      <!-- T1567: Monitoring Office apps making external connections (High risk for data theft) -->
      <NetworkConnect onmatch="include">
        <Image image="winword.exe" />
        <Image image="excel.exe" />
      </NetworkConnect>

      <!-- 5. Post-Exploit Callbacks and Vulnerability Monitoring -->
      <!-- T1190: Exploit Public-Facing Application.
           Monitoring w3wp.exe (IIS) for outbound connections which typically indicate a reverse shell
           following an exploit like CVE-2023-48788. -->
      <NetworkConnect onmatch="include">
        <Image image="w3wp.exe" />
      </NetworkConnect>

      <!-- Noise Reduction: Exclude standard internal/loopback traffic to prevent log flooding -->
      <NetworkConnect onmatch="exclude">
        <DestinationIp is="127.0.0.1" />
        <DestinationIp is="::1" />
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 27 seconds
#### With : Valid / Without : **Invalid** (`<Image image="powershell.exe" />` for example)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 16

=========== WITH example (exec number 16) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Monitor outbound connections to known malicious IPs identified in IOCs -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!-- Detect execution engines and LOLbins initiating network connections (T1059.001, T1071.001, T1567) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>
      </NetworkConnect>

      <!-- Detect Protocol Tunneling tools (T1572) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!-- Monitor for unauthorized RDP or WinRM activity (T1021.001) -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is any">5985;5986</DestinationPort>
      </NetworkConnect>

      <!-- Monitor processes running from suspicious writable directories (T1036) -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Paulo\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Roaming\</Image>
      </NetworkConnect>

      <!-- Specifically monitor for CVE-2023-48788: Outbound traffic from FortiClientEMS (T1190) -->
      <!-- Note: Assuming FortiClientEMS binary is the process to monitor for post-exploit egress -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="contains">FortiClientEMS</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 14 seconds
=========== WITHOUT example (exec number 16) ===========
```xml
<Sysmon schemaversion="4.85">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" group_id="3">
      <!--
        T1071.001 / T1567 / T1041: Detect outbound connections from processes that should not typically
        be initiating network traffic, specifically PowerShell and Python, which are present in
        the running processes and installed programs.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
        <Image condition="contains">python.exe</Image>
      </NetworkConnect>

      <!--
        T1572: Detect potential protocol tunneling using identified tools.
        Although plink/ssh are not in the current running process list, they are high-risk
        for high-exposure servers.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="contains any">plink.exe;ssh.exe;netsh.exe</Image>
      </NetworkConnect>

      <!--
        IOC Monitoring: Specifically tracking the provided malicious IP sources
        across all processes to identify C2 or exfiltration activity.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        T1190 / CVE-2023-48788: Monitor network activity from the web-facing application context.
        While w3wp.exe is the standard for IIS, we monitor for any unusual outbound connections
        from suspected service hosts or the specific vulnerability target (FortiClientEMS)
        if the binary is identified.
      -->
      <NetworkConnect onmatch="include">
        <Image condition="image">w3wp.exe</Image>
      </NetworkConnect>

      <!--
        Noise Reduction: Exclude known legitimate browser and system traffic
        to avoid flooding logs on a high-exposure server.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="contains any">firefox.exe;msedge.exe;OneDrive.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 7 seconds
#### With : Valid / Without : **Invalid** (`< ... group_id="3">`)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 17

=========== WITH example (exec number 17) ===========
```xml
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <RuleGroup name="Contextual_Security_Analysis" groupRelation="or">
      <!--
        T1190: Exploit Public-Facing Application & T1071.001: Web Protocols
        Monitor for connections involving known malicious source IPs.
      -->
      <NetworkConnect onmatch="include">
        <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        T1059.001: PowerShell & T1071.001: Web Protocols
        Detect shells or interpreters establishing network connections,
        which is highly anomalous for a server.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
      </NetworkConnect>

      <!--
        T1021.001: Remote Desktop Protocol & T1572: Protocol Tunneling
        Monitor for tunneling tools establishing outbound connections.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
        T1041: Exfiltration Over C2 Channel & T1567: Exfiltration Over Web Service
        Detect processes that should not have network activity (Living off the Land)
        initiating outbound connections.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
      </NetworkConnect>

      <!--
        T1021.001: RDP & T1571: Non-Standard Port
        Detect RDP or management protocol traffic from unusual processes.
      -->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <Image condition="is not">mstsc.exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 13 seconds
#### With : Valid / Without : **Invalid** (`<Sysmon SchemaId="4.84">`)

=========== WITHOUT example (exec number 17) ===========
```xml
<Sysmon schemaversion="4.83">
  <EventFiltering>
    <RuleGroup name="NetworkConnect">
      <!--
        T1190: Exploit Public-Facing Application & T1071.001: Web Protocols
        Monitor any connection initiated by the host that involves the known malicious IOC IPs.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <SourceIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>

      <!--
        T1059.001: PowerShell & T1071.001: Web Protocols
        Detect behavioral chains where PowerShell or shells are used for C2 or outbound callbacks.
      -->
      <NetworkConnect onmatch="include" name="T1059.001-PowerShell">
        <Image image="powershell.exe" />
      </NetworkConnect>
      <NetworkConnect onmatch="include" name="T1071.001-Web Protocols">
        <Image image="cmd.exe" />
      </NetworkConnect>
      <NetworkConnect onmatch="include" name="T1071.001-Web Protocols">
        <Image image="rundll32.exe" />
      </NetworkConnect>
      <NetworkConnect onmatch="include" name="T1071.001-Web Protocols">
        <Image image="mshta.exe" />
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling
        Monitor processes typically used for tunneling network traffic.
      -->
      <NetworkConnect onmatch="include" name="T1572-Protocol Tunneling">
        <Image image="plink.exe" />
      </NetworkConnect>
      <NetworkConnect onmatch="include" name="T1572-Protocol Tunneling">
        <Image image="ssh.exe" />
      </NetworkConnect>
      <NetworkConnect onmatch="include" name="T1572-Protocol Tunneling">
        <Image image="netsh.exe" />
      </NetworkConnect>

      <!--
        T1041: Exfiltration Over C2 Channel & T1567: Exfiltration Over Web Service
        Monitor for network activity from productivity apps that should not be initiating
        outbound connections to cloud storage or unknown external IPs.
      -->
      <NetworkConnect onmatch="include" name="T1567-Exfiltration Over Web Service">
        <Image image="winword.exe" />
      </NetworkConnect>
      <NetworkConnect onmatch="include" name="T1567-Exfiltration Over Web Service">
        <Image image="excel.exe" />
      </NetworkConnect>

      <!--
        CVE-2023-48788 Context:
        Since the host is high-exposure and specifically vulnerable via FortiClientEMS,
        we monitor the application process for abnormal outbound connections.
      -->
      <NetworkConnect onmatch="include" name="T1190-Exploit Public-Facing Application">
        <Image contains="FortiClient" />
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 0 minutes and 37 seconds
#### With : Valid / Without : **Invalid** (`<Image image="winword.exe" />` for example)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 18

=========== WITH example (exec number 18) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Security Analysis Correlation" groupRelation="or">
      <!--
        Include: High-Risk Process Network Activity
        Focuses on LOLbins and shells that should not typically initiate outbound connections
        on a high-exposure server, correlating with T1059.001, T1071.001, and T1567.
      -->
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
        <Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">netsh.exe</Image>
      </NetworkConnect>

      <!--
        Include: Known Adversary Infrastructure (IoCs)
        Direct monitoring of the reported malicious IP addresses.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!--
        Include: Remote Access and Lateral Movement
        Monitoring RDP and WinRM ports.
        Correlates with T1021.001.
      -->
      <NetworkConnect onmatch="include">
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>
        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is any">5985;5986</DestinationPort>
      </NetworkConnect>

      <!--
        Exclude: Known Benign Noise based on Host State
        Reducing noise from installed software: OneDrive, Edge, and system updates.
      -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">OneDrive.exe</Image>
        <Image condition="image">msedge.exe</Image>
        <DestinationHostname condition="end with">.windowsupdate.microsoft.com</DestinationHostname>
        <DestinationHostname condition="end with">.update.microsoft.com</DestinationHostname>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 1 minutes and 2 seconds

=========== WITHOUT example (exec number 18) ===========
```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <!--
      Event ID 3: Network connection
      Focus: High-exposure server monitoring for CVE-2023-48788, C2, and Exfiltration.
    -->
    <RuleGroup name="networkconnect" groupCommit="false">
      <NetworkConnect onmatch="include">
        <!--
          T1071.001 / T1567 / T1041:
          Monitoring common LOLbins and scripting engines used for C2 and Exfiltration.
          These processes initiating network connections are highly suspicious on a server.
        -->
        <Image condition="contains any">powershell.exe;cmd.exe;rundll32.exe;certutil.exe;python.exe</Image>

        <!--
          T1572:
          Monitoring known tunneling and SSH tools for protocol encapsulation.
        -->
        <Image condition="contains any">plink.exe;ssh.exe;netsh.exe</Image>

        <!--
          T1021.001:
          Monitoring RDP traffic for remote access activity.
        -->
        <DestinationPort condition="is">3389</DestinationPort>
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          IoC Match:
          Directly monitoring for the reported malicious IP addresses.
        -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <NetworkConnect onmatch="include">
        <!--
          T1190 / CVE-2023-48788:
          Monitoring outbound connections from the web server process.
          In a high-exposure server, a web process (like w3wp.exe) initiating outbound
          connections often indicates a reverse shell or post-exploit payload delivery.
        -->
        <Image condition="image">w3wp.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 48 seconds
#### With : Valid / Without : **Invalid** (`<RuleGroup name="networkconnect" groupCommit="false">`)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 19

=========== WITH example (exec number 19) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!--
      The server has high network exposure and is susceptible to CVE-2023-48788 (SQLi -> RCE).
      Focus is on high-confidence indicators of C2, exfiltration, and post-exploit activity.
    -->
    <RuleGroup name="Security_Analysis_Network_Monitoring" groupRelation="or">

      <!-- 1. Monitoring for connections to known Malicious IOCs -->
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
      </NetworkConnect>

      <!-- 2. Living off the Land (LotL) processes initiating outbound connections -->
      <NetworkConnect onmatch="include">
        <Rule name="Suspicious_LotL_Outbound" groupRelation="or">
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
          <Image name="technique_id=T1071.001,technique_name=Web Protocols" condition="image">rundll32.exe</Image>
          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>
          <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- 3. Protocol Tunneling / Administrative Tool Abuse -->
      <NetworkConnect onmatch="include">
        <Rule name="Tunneling_Tools" groupRelation="or">
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
          <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- 4. Potential Post-Exploit Activity for CVE-2023-48788 -->
      <!-- Monitoring for common reverse shell ports to minimize noise compared to open port monitoring -->
      <NetworkConnect onmatch="include">
        <Rule name="Common_C2_Ports" groupRelation="and">
          <DestinationPort condition="is any">4444;31337;6667;5555</DestinationPort>
          <Image condition="is not">firefox.exe</Image> <!-- Exclude browser noise -->
          <Image condition="is not">msedge.exe</Image>
        </Rule>
      </NetworkConnect>

      <!-- 5. Exfiltration to Web Services (T1567) -->
      <!-- Correlating suspicious processes with common web-service destination patterns -->
      <NetworkConnect onmatch="include">
        <Rule name="Exfiltration_Web_Services" groupRelation="and">
          <Image condition="is any">powershell.exe;cmd.exe;rundll32.exe</Image>
          <DestinationHostname condition="contains any">dropbox.com;onedrive.live.com;google.drive</DestinationHostname>
        </Rule>
      </NetworkConnect>

    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 21 seconds
=========== WITHOUT example (exec number 19) ===========
```xml
<Sysmon schemaversion="4.85">
  <EventFiltering>
    <RuleGroup name="NetworkConnect" group_id="3">
      <!--
        T1071.001 / T1041 / T1567: Monitoring high-risk processes initiating outbound connections.
        Focuses on PowerShell, Cmd, and Python (installed on host) as these are primary vectors
        for C2, exfiltration, and arbitrary execution.
      -->
      <NetworkConnect onmatch="include">
        <Image contains any="powershell.exe;cmd.exe;python.exe;rundll32.exe" />
      </NetworkConnect>

      <!--
        T1572: Protocol Tunneling.
        Monitoring tools often used to encapsulate traffic (plink, ssh, netsh).
      -->
      <NetworkConnect onmatch="include">
        <Image contains any="plink.exe;ssh.exe;netsh.exe" />
      </NetworkConnect>

      <!--
        T1190: Exploit Public-Facing Application.
        Monitoring for post-exploitation egress. Specifically looking for the web server
        process or system services spawning network connections to external IPs.
      -->
      <NetworkConnect onmatch="include">
        <Image contains="w3wp.exe" />
      </NetworkConnect>

      <!--
        Direct IOC Matching: Monitoring for connections to the reported malicious IP addresses.
        This is the most high-fidelity signal for the current threat landscape.
      -->
      <NetworkConnect onmatch="include">
        <DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />
      </NetworkConnect>

      <!--
        Noise Reduction: Exclude common browser traffic to avoid flooding logs,
        unless the destination IP is part of the IOC list (which is handled by the 'include' above).
      -->
      <NetworkConnect onmatch="exclude">
        <Image contains any="firefox.exe;msedge.exe" />
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Time it took: 0 minutes and 13 seconds
#### With : Valid / Without : **Invalid** (`< ... group_id="3">` for example)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Execution number 20

=========== WITH example (exec number 20) ===========
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Threat_Detection_NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190: Monitoring for post-exploit callbacks from common web service processes (CVE-2023-48788) -->
        <Image name="technique_id=T1190,technique_name=Exploit Public-Facing Application" condition="image">w3wp.exe</Image>

        <!-- T1059.001 & T1071.001: PowerShell making external connections (C2/Exfiltration) -->
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">OpenConsole.exe</Image>
        <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">WindowsTerminal.exe</Image>

        <!-- T1572 & T1041: Tunneling and Exfiltration tools -->
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">plink.exe</Image>
        <Image name="technique_id=T1572,technique_name=Protocol Tunneling" condition="image">ssh.exe</Image>
        <Image name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" condition="image">rundll32.exe</Image>

        <!-- T1021.001: Monitoring RDP activity -->
        <DestinationPort name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" condition="is">3389</DestinationPort>

        <!-- Correlation with reported IoC IPs (Medium threat level) -->
        <Rule groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>

        <!-- T1567: Exfiltration via Web Services (Monitoring non-browser paths for cloud storage access) -->
        <!-- Using 'begin with' and 'contains' to identify suspicious paths from the host state -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="begin with">C:\Users\Public\</Image>
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="contains">\AppData\Local\Temp\</Image>
      </NetworkConnect>

      <!-- Noise Reduction: Excluding legitimate high-volume cloud synchronization observed in host installed programs -->
      <NetworkConnect onmatch="exclude">
        <Image condition="image">OneDrive.exe</Image>
        <Image condition="image">OneDriveStandaloneUpdater.exe</Image>
        <Image condition="end with">Dropbox.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 21 seconds
=========== WITHOUT example (exec number 20) ===========
```xml
<Sysmon schemaversion="4.8">
  <EventFiltering>
    <RuleGroup group="NetworkConnect">
      <!--
        T1190 & T1071.001: Monitoring critical service processes and shells for outbound connections.
        CVE-2023-48788 Target: Monitoring processes that could be exploited to spawn network activity.
        We specifically include powershell.exe and cmd.exe as they are present in the running processes list.
      -->
      <Rule>
        <NetworkConnect onmatch="include">
          <Image condition="contains any">powershell.exe;cmd.exe;rundll32.exe;certutil.exe;plink.exe;ssh.exe;netsh.exe</Image>
        </NetworkConnect>
      </Rule>

      <!--
        T1021.001: Remote Desktop Protocol Monitoring.
        Monitoring any process initiating or receiving connections on the RDP port.
      -->
      <Rule>
        <NetworkConnect onmatch="include">
          <DestinationPort condition="is">3389</DestinationPort>
        </NetworkConnect>
      </Rule>

      <!--
        IoC Integration: Monitoring all network activity associated with the reported malicious IP addresses.
        Matches both SourceIp and DestinationIp to catch C2 callbacks or inbound attacks.
      -->
      <Rule>
        <NetworkConnect onmatch="include">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </NetworkConnect>
      </Rule>

      <!--
        T1567 & T1041: Exfiltration Over Web Service / C2 Channel.
        Monitoring high-risk apps from the installed list (OneDrive, Office) and Python
        when they initiate network connections, as they are common vectors for exfiltration.
      -->
      <Rule>
        <NetworkConnect onmatch="include">
          <Image condition="contains any">OneDrive.exe;python.exe;ms-teams.exe</Image>
        </NetworkConnect>
      </Rule>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```



#### Time it took: 0 minutes and 13 seconds
#### With : Valid / Without : **Invalid** (`<RuleGroup group="NetworkConnect">`)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Results

| Execution # | With Valid? | Without Valid? | With time | Without time | 
|:-----------:|:-----------:|:--------------:|:---------:|:------------:|
| # 1 | Yes | No | 32 seconds | 58 seconds |
| # 2 | Yes | No | 78 seconds | 6 seconds |
| # 3 | Yes | No | 17 seconds | 8 seconds |
| # 4 | Yes | No | 33 seconds | 8 seconds |
| # 5 | Yes | No | 22 seconds | 12 seconds |
| # 6 | Yes | No | 19 seconds | 8 seconds |
| # 7 | Yes | No | 29 seconds | 29 seconds |
| # 8 | Yes | No | 30 seconds | 8 seconds |
| # 9 | Yes | No | 23 seconds | 11 seconds |
| # 10 | Yes | No | 18 seconds | 7 seconds |
| # 11 | Yes | No | 13 seconds | 14 seconds |
| # 12 | Yes | No | 15 seconds | 72 seconds |
| # 13 | Yes | No | 18 seconds | 14 seconds |
| # 14 | Yes | No | 17 seconds | 115 seconds |
| # 15 | Yes | No | 19 seconds | 27 seconds |
| # 16 | Yes | No | 14 seconds | 7 seconds |
| # 17 | Yes | No | 13 seconds | 37 seconds |
| # 18 | Yes | No | 62 seconds | 48 seconds |
| # 19 | Yes | No | 21 seconds | 13 seconds |
| # 20 | Yes | No | 21 seconds | 13 seconds |

| Method | How many Valid? | How many invalid? | Average execution time |
|:------:|:---------------:|:-----------------:|:----------------------:|
| With sysmon examples | 20 | 0 | 25.7  seconds | 
| Without sysmon examples | 0 | 20 | 25.75 seconds |

# Conclusions

The method I used in this test was copying the results on the sysmon config file path and running the command `.\Sysmon64.exe -c .\sysmon_config_file.xml `. This was eye-opening. I knew at least some of the times the sysmon configuration files with no examples were wrong, but I would never say wrong at all times. There are little details that make it invalid, but they are definitely there, some of them include:

- RuleGroup having invalid tags like `group` or `group_id`
- Using the condition incorrectly like `<DestinationIp is any="185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13" />`
- Not inserting the schemaversion correctly, like `<Sysmon xmlns="http://www.microsoft.com/sysmonv3">`

One main concern was also the time consumed that would be higher, but seems that the approach with no examples is very inconsistent when it comes to time, best case scenario being 6 seconds and worst 115 seconds.

So, from now on, **I think it is best to have the examples "always by our side"**. 