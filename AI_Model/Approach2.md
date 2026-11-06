# Approach 2 - Asking for a portion of the sysmon config file

Since approach 1 led to multiple attempt with no 100% success I thought that maybe asking for a portion of the file instead of the whole sysmon configuration file would be a better approach, since there is less information.

The prompt sent was:

```
    You are generating Sysmon XML and you are bulding a part of a sysmon configuration file that will be used to monitor an host vulnerable with epss 0.93 and is very valuable to the overall system.

    Valid example:
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains any">
            firefox.exe; 
            outlook.exe
        </CommandLine>
    </ProcessCreate>

    Rules:
    - ProcessCreate only uses XML tags from this list:
      [Image, FileVersion, Product, OriginalFileName, CommandLine, CurrentDirectory, TerminalSessionId, IntegrityLevel, Hashes, ParentImage, ParentCommandLine]

    - Only use condition="" with:
      ["is", "contains", "contains any"]

    - Never invent XML tags.
    - Never use placeholders.
    - Never explain.
    - Output ONLY valid XML (no formatting).

    Task:
    Create ONLY ProcessCreate rule for these attack patterns:
    - Domain Generation Algorithms - T1568.002
    - Match Legitimate Name or Location - T1036.005
    - Windows Service - T1543.003

    And catch the indicators of compromise:
    - c4edf28177e72d1bfc482cf4d05a156b (payload delivery attribute in MISP)
    - 124.222.137.114 (Network activity in MISP)
    - afaf29d9-d5b7-4dec-bfcd-ef18278ed307 (payload delivery in MISP)
    If you consider it to be worth and/or correct.

    You can also add more content if you think it needs due to its critical role in the system.
```

This prompt is meant to test:
+ Does the AI model can produce 100% valid sysmon config file portion?
+ Does it perform better than if it was a whole config file?
+ Does the AI model notice that the IP address is meant to not go in these set of rules?
+ Did the AI use all the IoCs correctly? 
+ Does the AI model try to use other common IoCs correctly in the portion of sysmon config file?
+ Did it do what was asked of him?
+ Was time taken acceptable? Better than the approach 1?
+ Did it respect the constraints given?

---------------------------------------------------------------------------------------------------------

# Qwen2.5:14b answer:

```xml
<ProcessCreate onmatch="include">
    <CommandLine condition="contains any">c4edf28177e72d1bfc482cf4d05a156b; 124.222.137.114</CommandLine>
    <Image condition="contains any">%windir%\system32\svchost.exe;%windir%\system32\services.exe</Image>
    <ParentImage condition="is">explorer.exe</ParentImage>
</ProcessCreate>
```

Time it took: 2 minutes and 19 seconds

### Conclusions

+ Yes, it is 100% valid, the structure is correct and it used the ';' as well
+ Slightly, compared to the first one this is 100% valid and it used more information given
+ It did not, but putting it into the CommandLine might be a smart move, although there are rules specialized for that
+ For some reason it ignored the afaf29d9-d5b7-4dec-bfcd-ef18278ed307 hash, and the other one was used in `CommandLine` instead of the `Hashes`. 
+ Yes, it added the `services.exe` and `explorer.exe` indicators 
+ Partially, it did only the portion asked of him but it did not consider one of the hash files
+ Yes, 2 minutes and 19 seconds is fast and faster than approach 1 (4min12sec less)
+ It used he placeholder "```xml"

---------------------------------------------------------------------------------------------------------

# Llama 3.1 answer:

```xml
<ProcessCreate onmatch="include">
  <CommandLine condition="contains any">
    winrm.exe
  </CommandLine>
</ProcessCreate>

<ProcessCreate onmatch="include">
  <Image condition="is">svchost.exe</Image>
  <Image condition="is">wininit.exe</Image>
  <Hashes condition="is">c4edf28177e72d1bfc482cf4d05a156b</Hashes>
</ProcessCreate>

<NetworkConnect onmatch="include">
  <IpCondition condition="is">124.222.137.114</IpCondition>
</NetworkConnect>

<DirectoryCreate onmatch="include">
  <Path condition="contains any">\Program Files\Microsoft\Windows Defender</Path>
  <Path condition="contains any">\Program Files\Microsoft\Windows Defender</Path>
</DirectoryCreate>
```
Time it took: 2 minutes and 37 seconds

+ The ProcessCreate is valid, the others are not.
+ Pretty much the same level of hallucination.
+ It did notice and tried to apply it in the correct rule, but it is not correctly structured
+ Not all of them, forgot the third hash value. It tried to put the Ip address on the correct ruleset at least.
+ Yes, besides the given IoCs it tried to filter other ones.
+ It did produce a portion of a sysmon config file, but it failed in structure and in following the rule that it was only meant to be ProcessCreate
+ Yes, 2 minutes and 37 seconds is fast, almost a minute faster than the other approach
+ It used he placeholder "```xml"

---------------------------------------------------------------------------------------------------------

# Gemma3 answer:

```xml
<ProcessCreate onmatch="include">
    <CommandLine condition="contains">c4edf28177e72d1bfc482cf4d05a156b</CommandLine>
    <CommandLine condition="contains">124.222.137.114</CommandLine>
    <CommandLine condition="contains">afaf29d9-d5b7-4dec-bfcd-ef18278ed307</CommandLine>
</ProcessCreate>
```
Time it took: 0 minutes and 37 seconds

+ Yes, it is valid, although not the best way to do it
+ Yes, it is 100% valid differing form before.
+ No, it added it to the CommandLine
+ It did usde them all, but not correctly 
+ No, it did not try to leave the "confort zone" and did a low effort solution, even when told the host of the system was in a critical risk state.
+ Yes, at least it didn't try to build new rules.
+ The fastest in approach 2. 6x faster than in approach 1
+ It used he placeholder "```xml"

---------------------------------------------------------------------------------------------------------

# Gemma4 answer:

```xml
<ProcessCreate onmatch="include">
    <!-- IOC Monitoring: Known Malicious Hashes -->
    <Hashes condition="is">
        c4edf28177e72d1bfc482cf4d05a156b
    </Hashes>

    <!-- DGA/Suspicious Script Execution (PowerShell abuse, encoded commands) -->
    <CommandLine condition="contains any">
        powershell.exe -e
        powershell.exe -encodedcommand
        invoke-expression
        cmd.exe /c net user
    </CommandLine>

    <!-- T1036.005 / Masquerading: Look for binaries or execution that suggests impersonation or suspicious file names -->
    <OriginalFileName condition="contains any">
        svchost.exe
        explorer.exe
        taskmgr.exe
    </OriginalFileName>

    <!-- Parent Process Monitoring: Common processes spawning unexpected shells or network tools -->
    <ParentImage condition="is">
        cmd.exe
    </ParentImage>

    <ParentCommandLine condition="contains any">
        schtasks.exe
        bitsadmin.exe
        curl.exe
        wget.exe
    </ParentCommandLine>

    <!-- T1543.003 / Service Abuse and IOC GUID Monitoring -->
    <CommandLine condition="contains any">
        sc.exe
        GUID_SERVICE_CHECK_1: afaf29d9-d5b7-4dec-bfcd-ef18278ed307
        124.222.137.114
    </CommandLine>

</ProcessCreate>
```
Time it took: 4 minutes and 10 seconds

+ It would've been 100% valid if, in the "any" conditions it added the ";".
+ Yes
+ Normally it is considered in the `NetworkConnect` event but adding the IP address in the CommandLine is not so bad 
+ Only the SHA256 one, the IMPHASH was added to the command line as a value of `GUID_SERVICE_CHECK_1` 
+ Yes, besides the IoCs given it used 13 other ones.
+ Yes, it created only a ProcessCreate rule as asked and used the IoCs
+ 4 minutes is a bit high compared to the other ones. It did better than the approach 1 (2 minutes less)
+ It used he placeholder "```xml"

---------------------------------------------------------------------------------------------------------

# Qwen3.6 answer:

*Literally no response*

Time it took: 17 minutes and 17 seconds

--- 

# Gemma3:27b-cloud

(This one is for comparison to approach 3)


Prompt sent:

```
    You are generating Sysmon XML and you are bulding a part of a sysmon configuration file that will be used to monitor an host vulnerable with epss 0.93 and is very valuable to the overall system.

    Valid example:
    <NetworkConnect onmatch="include">
        <DestinationPort>443</DestinationPort>
        <DestinationPort>80</DestinationPort>
        <Image condition="contains any">
            iexplore.exe;
            firefox.exe;
        </Image>
    </NetworkConnect>

    Which means "Log the events that have image iexplore.exe OR firefox.exe AND with 433 OR 80 port".

    Rules:
    - You can use these NetworkConnect XML tags from this list:
      [Image, Protocol, Initiated, SourceIp, SourceHostname, SourcePort, DestinationIp, DestinationHostname, DestinationPort]


    - Never invent XML tags.
    - Never use placeholders.
    - Never explain.
    - Output ONLY valid XML (no formatting).

    Task:
    Create ONLY ProcessCreate rule for these attack patterns:
    [{"value": "Exploit Public-Facing Application - T1190", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "PowerShell - T1059.001", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "Remote Desktop Protocol - T1021.001", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "Disable or Modify Tools - T1562.001", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "System Checks - T1497.001", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "Web Protocols - T1071.001", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "Protocol Tunneling - T1572", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "Exfiltration Over C2 Channel - T1041", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "Data Encrypted for Impact - T1486", "timestamp": 1772455068, "threat_level_id": 2}, {"value": "Exfiltration Over Web Service - T1567", "timestamp": 1772455068, "threat_level_id": 2}]

    And catch the indicators of compromise:
    [[{"type": "ip-src", "timestamp": 1772455068, "value": "185.216.70.170", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "77.90.38.170", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "154.216.19.224", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "154.216.17.157", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "176.65.141.201", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "176.65.141.232", "threat_level_id": 2}, {"type": "ip-src", "timestamp": 1772455068, "value": "206.123.145.13", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "sos.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "audiodg.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "audiofg.exe", "threat_level_id": 2}, {"type": "filename", "timestamp": 1772455068, "value": "KB332.ps1", "threat_level_id": 2}], 11]
    If you consider it to be worth and/or correct.

    You can also add more content if you think it needs due to its critical role in the system.
    Justify each choice using the xml comment syntax.
```

```xml
<NetworkConnect onmatch="include">
    <!-- Monitor PowerShell connections -->
    <Image condition="contains any">powershell.exe;powershell_ise.exe</Image>
    <DestinationPort>80</DestinationPort>
    <DestinationPort>443</DestinationPort>
    <DestinationPort>5985</DestinationPort> <!-- RDP default port -->
    <DestinationPort>5986</DestinationPort> <!-- RDP default port -->
</NetworkConnect>
<NetworkConnect onmatch="include">
    <!-- Monitor connections from known malicious IPs -->
    <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
    <DestinationPort>80</DestinationPort>
    <DestinationPort>443</DestinationPort>
</NetworkConnect>
<NetworkConnect onmatch="include">
    <!-- Monitor connections involving suspicious filenames -->
    <Image condition="contains any">sos.exe;audiodg.exe;audiofg.exe;KB332.ps1</Image>
    <DestinationPort>80</DestinationPort>
    <DestinationPort>443</DestinationPort>
</NetworkConnect>
<NetworkConnect onmatch="include">
    <!-- Monitor RDP connections -->
    <Image condition="contains any">mstsc.exe</Image>
    <DestinationPort>3389</DestinationPort>
</NetworkConnect>
<NetworkConnect onmatch="include">
    <!-- Monitor potential C2 communication over standard web ports -->
    <DestinationPort>80</DestinationPort>
    <DestinationPort>443</DestinationPort>
    <Protocol condition="is">tcp</Protocol>
</NetworkConnect>
<NetworkConnect onmatch="include">
    <!-- Monitor connections to uncommon ports often used for tunneling -->
    <DestinationPort condition="is">53</DestinationPort> <!-- DNS tunneling -->
    <DestinationPort condition="is">110</DestinationPort> <!-- POP3 -->
    <DestinationPort condition="is">143</DestinationPort> <!-- IMAP -->
</NetworkConnect>
```
Time it took: 0 minutes and 20 seconds
--- 

# Gemma4:31b-cloud

(This one is for comparison to approach 3)

```xml
<Sysmon>
    <NetworkConnect onmatch="include">
        <!-- T1190, T1071.001: Monitoring high-risk source IPs linked to exploitation and C2 -->
        <SourceIp>185.216.70.170</SourceIp>
        <SourceIp>77.90.38.170</SourceIp>
        <SourceIp>154.216.19.224</SourceIp>
        <SourceIp>154.216.17.157</SourceIp>
        <SourceIp>176.65.141.201</SourceIp>
        <SourceIp>176.65.141.232</SourceIp>
        <SourceIp>206.123.145.13</SourceIp>
        <!-- T1059.001, T1572, T1041: Monitoring suspicious processes and scripts initiating network connections -->
        <Image condition="contains any">
            sos.exe;
            audiodg.exe;
            audiofg.exe;
            powershell.exe;
        </Image>
        <!-- T1021.001: Remote Desktop Protocol -->
        <DestinationPort>3389</DestinationPort>
        <!-- T1071.001, T1567: Web protocols and Exfiltration over web services -->
        <DestinationPort>80</DestinationPort>
        <DestinationPort>443</DestinationPort>
        <DestinationPort>8080</DestinationPort>
    </NetworkConnect>
</Sysmon>
```
Time it took: 0 minutes and 3 seconds

--- 

# Comparison

| LLM | Valid sysmon? | Perform better than app1? | Notice IP address? | IoCs correctly used? | Creative? | It did what was asked of it? | Respect Constraints? | Time |
|:---:|:-------------:|:-------------------------:|:------------------:|:--------------------:|:---------:|:----------------------------:|:--------------------:|:----:|
| Qwen2.5:14b | ✅ | ✅ | ✅ | ➖ | ✅ | ➖ | ➖ | 2min 19s (faster) | 
| llama3.1:8b (latest) | ➖ | ❌ | ✅ | ➖ | ✅ | ❌ | ➖ | 2min 37s (faster) | 
| Gemma3:4b (latest) | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ➖ | 0min 37s (faster) | 
| Gemma4:e4b (latest) | ❌ | ✅ | ➖ | ➖ | ✅ | ➖ | ✅ | 4min 10s (faster) | 

❌ - No
✅ - Yes
➖ - Partially

---

# Conclusions

(+) Asking for a portion instead of the whole sysmon config file did improve structural validity results and the hallucination problems

(+) Less explanation than before since I tried it to be objective

(+) Better time results

(-) Eventhough hallucination was less, it still had some

(-) Seemed that the creativity to "think outside the box" was less present

# What to do now?

- May try new models
- Maybe try to make it step-by-step approach with chat history
- Will try to be more explicit on what to use
- Will try to make it so the attack patterns are considered as in the first approach 