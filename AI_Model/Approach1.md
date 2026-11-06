### This first approach is an accumulation of several attempts to make the AI give a sysmon config file that:
- Is valid
- It considers the attack patterns given and tries to monitor them
- It considers the installed programs on the host

```
    You are a Sysmon configuration expert.

    Task:
    Generate a minimal Sysmon configuration focused ONLY on detection of the following MITRE ATT&CK techniques:

    - T1106 (Native API)
    - T1648 (Serverless execution)
    - T1534 (Internal Spearphishing)

    Host context:
    
    These are the programs installed on the host: ['Docker Desktop', 'Git', 'Mozilla Firefox (x64 en-GB)', 'Mozilla Maintenance Service', 'Sublime Text', 'Windows Subsystem for Linux', 'Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211', 'Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211', 'Microsoft Teams Meeting Add-in for Microsoft Office']

    Please use this context as you see fit in the sysmon configuration file (if you think some of them are not worth to consider do not use them).


    Objective:
    Use this information to build a sysmon xml cofiguration file 

    Recall how sysmon config files work:
        This is the root: "<Sysmon schemaversion="4.91">"
        In the "EventFiltering" root we can exclude or include conditions like this: 
            <EventFiltering>
                <ProcessCreate onmatch="include">
                    <Image condition="contains">timeout.exe</Image>
                </ProcessCreate>
        If you leave it like:
            <FileCreateTime onmatch="exclude" />
        it excludes no conditions, meaning it will log everything.
        If if you leave it like:
            <FileCreateTime onmatch="include" />
        it includes no conditions, meaning it will log nothing.

        Besides ProcessCreate the available events are:
            NetworkConnect
            ProcessTerminate
            DriverLoad
            ImageLoad
            CreateRemoteThread
            RawAccessRead
            ProcessAccess
            FileCreate
            RegistryEvent
            FileCreateStreamHash
            PipeEvent
            WmiEvent
            DnsQuery
            FileDelete
            ClipboardChange
            ProcessTampering
            FileDeleteDetected
            FileBlockExecutable
            FileBlockShredding
            FileExecutableDetected


```

This prompt is meant to test:
+ Does the AI model produce a valid sysmon config file?
+ Does it use the installed programs in the sysmon config file?
+ Does it use different IoCs to try to catch the attack pattern behaviour?
+ Does it produce nonsense rules?
+ Does the AI model use irrelevant programs? ('Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211', 'Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211', 'Microsoft Teams Meeting Add-in for Microsoft Office')
+ Does the AI model respect the "minimal" part of the request?

---------------------------------------------------------------------------------------------------------

# Qwen2.5:14b answer:

To create a minimal Sysmon configuration focused on detecting the specified MITRE ATT&CK techniques (T1106 - Native API, T1648 - Serverless execution, and T1534 - Internal Spearphishing), we need to focus on events that provide visibility into these attack vectors. Here is a tailored XML configuration for Sysmon:

```xml
<Sysmon schemaversion="4.91">
    <EventFiltering>
        <!-- Native API (T1106) -->
        <ImageLoad onmatch="include">
            <Image condition="ends-with">ntdll.dll</Image>  <!-- Native APIs are often invoked through ntdll.dll calls -->
            <ServiceDll condition="ends-with">ntdll.dll</ServiceDll>
        </ImageLoad>

        <!-- Serverless execution (T1648) -->
        <!-- Since this technique typically involves cloud-based executions, we focus on network events related to AWS, Azure, and other serverless platforms. -->
        <NetworkConnect onmatch="include">
            <DestinationPort condition="contains">53</DestinationPort>  <!-- DNS queries for potential C2 communications -->
            <DestinationPort condition="contains">443</DestinationPort>
        </NetworkConnect>

        <!-- Internal Spearphishing (T1534) -->
        <!-- This involves tracking email and web browsing activity. We focus on network events for HTTP/HTTPS traffic. -->
        <NetworkConnect onmatch="include">
            <Image condition="contains">msmtp.exe</Image>  <!-- Example of an SMTP client, not typically installed but illustrates the idea -->
            <Image condition="contains">outlook.com</Image>
            <DestinationPort condition="contains">443</DestinationPort>
        </NetworkConnect>

        <RegistryEvent onmatch="include">
            <Channel condition="equal">Microsoft-Windows-Sysmon/Operational</Channel>
            <OpCode condition="equal">SetValue</OpCode>
            <Details condition="contains">HKCU\Software\Microsoft\Office</Details>  <!-- Example registry key for Office settings -->
        </RegistryEvent>

    </EventFiltering>
</Sysmon>
```

### Explanation:
1. **Native API (T1106)**: We monitor `ImageLoad` events specifically looking at calls to `ntdll.dll`, which is commonly used in native API calls.
2. **Serverless Execution (T1648)**: Network traffic analysis can help identify connections related to cloud-based services that might be involved in serverless execution. The configuration includes monitoring of DNS and HTTPS connections, which are common for C2 communications.
3. **Internal Spearphishing (T1534)**: Monitoring network connections to known email providers like outlook.com helps detect internal spearphishing attempts. Additionally, we can also monitor registry events that might correlate with changes in email client configurations or other software settings.

This configuration is minimalistic and focuses on the techniques specified without overcomplicating the monitoring scope. Adjustments may be necessary based on your specific environment's baseline behavior to avoid false positives.

Time it took: 6 minutes and 31 seconds

### Conclusions

+ No, the "ServiceDll", "Channel" and "OpCode" parameters of `ImageLoad` and `RegistryEvent` respectively are not valid. Additionally the "equal" conditions are invalid as well.
+ No, It does not use the installed programs showned to it
+ Yes, it did try to create sysmon rules that relates between its known data and the attack patterns. For example, the `ntdll.dll` was not specified in the prompt but it did add it because it knows is related to the Native API attack pattern
+ It made justified rules, but it were invalid.
+ No, it did not use irrelevant programs
+ Since it tried to be very specific, joining different conditions in the same event tag, I would say so, but it was just too little and it did not consider the files given

---------------------------------------------------------------------------------------------------------

# Llama3.1 answer:

Here is a minimal Sysmon configuration file focused on detecting the specified MITRE ATT&CK techniques:

```xml
<Sysmon schemaversion="4.91">
  <EventFiltering>
    <!-- Log process creation events to detect T1106 (Native API) -->
    <ProcessCreate onmatch="include" />

    <!-- Log process execution of suspicious scripts and binaries in WSL to detect T1648 (Serverless execution) -->
    <Process onmatch="include">
      <Image condition="contains">bash.exe</Image>
      <Image condition="contains">bash</Image>
      <Image condition="contains">sh.exe</Image>
      <Image condition="contains">wsl.exe</Image>
    </Process>

    <!-- Log process execution of internal spear phishing tools to detect T1534 (Internal Spearphishing) -->
    <Process onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <Image condition="contains">powershell</Image>
      <Image condition="endswith">.ps1</Image>
    </Process>

    <!-- Log image loading events to detect suspicious DLLs and binaries -->
    <ImageLoad onmatch="include" />
  </EventFiltering>

  <LogFormat>FullTee</LogFormat>
</Sysmon>
```

In this configuration, we focus on detecting the specified MITRE ATT&CK techniques by logging relevant process creation, execution, and image loading events. The `ProcessCreate` event is included to detect T1106 (Native API), while the `Process` event with specific conditions is used to detect T1648 (Serverless execution) in WSL and internal spear phishing tools. Additionally, the `ImageLoad` event is included to log suspicious DLLs and binaries.

Note that we do not include any specific filtering for the other programs installed on the host (e.g., Docker Desktop, Git, Mozilla Firefox), as they are unlikely to be involved in the targeted MITRE ATT&CK techniques.

Please note that this configuration may require tuning based on your environment's specifics.
Time it took: 3 minutes and 21 second

### Conclusions

+ No, it used LogFormat, which is not sysmon syntax as well as a `Process` event tag
+ Yes, it did considered the wsl.exe program and justified why it did not consider the other ones.
+ Yes, it uses various images of indicators of attack.
+ Yes, Imageload with onmatch include does not include all events as it may seem, it does the opposite. Additionally it meant to include all Process
+ No, it did not consider useless programs
+ No, the LLM tried to capture all of the `ImageLoad` and `ProcessCreate` logs, so I would say it did not care for the sheer amount of data it would produce. Maybe I should mention the problems with that next time

---------------------------------------------------------------------------------------------------------

# Gemma3 answer:

Okay, here's a minimal Sysmon configuration XML file designed to detect the specified MITRE ATT&CK techniques, considering the provided host context. I've focused on the most relevant events and kept the configuration as lean as possible.

```xml
<Sysmon schemaversion="4.91">
  <EventFiltering>
    <!-- Process Create - Detecting Native API Abuse (T1106) -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">timeout.exe</Image>
      <Image condition="contains">powershell.exe</Image>
      <CommandLine condition="contains">powershell</CommandLine>
      <CommandLine condition="contains">cmd.exe</CommandLine>
    </ProcessCreate>

    <!-- Serverless Execution (T1648) - Focused on PowerShell -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <CommandLine condition="contains">powershell</CommandLine>
    </ProcessCreate>

    <!-- Internal Spearphishing (T1534) -  Monitor for Suspicious PowerShell -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <CommandLine condition="contains">New-Object</CommandLine>
    </ProcessCreate>

    <!-- Network Connect - Monitoring outbound connections from potentially suspicious processes -->
    <NetworkConnect onmatch="include">
        <Direction>Outbound</Direction>
        <IPAddress condition="contains">microsoft.com</IPAddress>
        <Port condition="contains">80</Port>
    </NetworkConnect>

  </EventFiltering>

  <TargetHunt>
    <ProcessName condition="contains">Docker Desktop</ProcessName>
    <ProcessName condition="contains">Git</ProcessName>
    <ProcessName condition="contains">Mozilla Firefox</ProcessName>
    <ProcessName condition="contains">Mozilla Maintenance Service</ProcessName>
    <ProcessName condition="contains">Sublime Text</ProcessName>
    <ProcessName condition="contains">Windows Subsystem for Linux</ProcessName>
    <ProcessName condition="contains">Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211</ProcessName>
    <ProcessName condition="contains">Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211</ProcessName>
    <ProcessName condition="contains">Microsoft Teams Meeting Add-in for Microsoft Office</ProcessName>
  </TargetHunt>
</Sysmon>
```

**Explanation and Rationale:**

1.  **Schema Version:**  `schemaversion="4.91"` - Using the latest stable version.

2.  **EventFiltering:** This is where the magic happens, and it is tailored to the ATT&CK techniques.

    *   **`ProcessCreate` (T1106 - Native API):**
        *   `timeout.exe` is a common tool used for timing and can be abused for Native API calls.  I've added `powershell.exe` and `cmd.exe` because these are often used to launch and control malicious code.
        *   `CommandLine condition="contains">powershell</CommandLine>` and `CommandLine condition="contains">cmd.exe</CommandLine>` are added to monitor commands that could potentially use native APIs.

    *   **`ProcessCreate` (T1648 - Serverless Execution):** This is the most important event for detecting serverless execution.  I've focused on PowerShell, as it's the most common method for this technique.

    *   **`ProcessCreate` (T1534 - Internal Spearphishing):** I've added monitoring for PowerShell execution when it uses the `New-Object` cmdlet. This is frequently associated with phishing campaigns that deliver malicious payloads.

    *   **`NetworkConnect` (General Monitoring):** Added outbound connections to Microsoft domains and port 80 to increase visibility into potentially malicious network activity.

3.  **TargetHunt:** This section focuses on monitoring the specific processes installed on the host, increasing the chance of catching malicious activity associated with those programs.

**Important Considerations and Next Steps:**

*   **Testing:**  *Thoroughly test this configuration in a non-production environment* before deploying it to your production systems. You need to confirm that the events are logged as expected and that false positives are minimal.
*   **Alerting:**  Configure your SIEM or logging system to generate alerts based on these Sysmon events.  You'll likely need to tune the alerting thresholds to reduce false positives.
*   **Rule Refinement:** This is a *minimal* configuration.  As you gain experience with your environment and identify patterns, you should expand the rules to cover more scenarios.
*   **Regular Review:**  Sysmon configurations should be reviewed and updated regularly to keep pace with evolving threats.

This configuration provides a solid starting point for detecting the specified MITRE ATT&CK techniques.  Remember that security is an ongoing process, and continuous monitoring and adaptation are crucial.

Do you want me to:

*   Modify this configuration further (e.g., add more specific conditions)?
*   Explain a particular event type in more detail?
*   Generate a configuration tailored to a different set of ATT&CK techniques?
Time it took: 2 minutes and 52 seconds

### Conclusions

+ No, targethunt is not a sysmon event
+ Yes, it does, not very carefully though.
+ Yes, it tried to use information that represents attack patterns.
+ Yes, the targetunt event is not a sysmon event as it is does not make sense to include every installed program in there.
+ Yes, it tried to monitor the programs that realistically are not threats
+ No, the result shows that it tried to be specific and it mentions it, but at the same time it tried to log every installed program activity.

---------------------------------------------------------------------------------------------------------

# Gemma4 answer:

As a Sysmon configuration expert, my goal is to provide maximum detection coverage for the specified techniques while maintaining the absolute minimum necessary logging overhead.

Since T1106 (Native API) and T1648 (Serverless execution) often rely on scripting interpreters (like PowerShell or Python) or process injection, the `ProcessCreate` and `CreateRemoteThread` events are paramount. T1534 (Internal Spearphishing) requires monitoring network activity and the interaction with common communication tools (like browsers or Teams).

Below is the highly focused Sysmon XML configuration.

***

## Sysmon Configuration XML

```xml
<Sysmon schemaversion="4.91">
  <EventFiltering>
    <!-- ==================================================== -->
    <!-- 1. PROCESS CREATE (Core monitoring for all TTPs)   -->
    <!-- Needed for: T1106, T1648, T1534 -->
    <!-- We capture the full process metadata (Image, CmdLine, etc.) -->
    <!-- This is the primary event for observing execution context. -->
    <ProcessCreate onmatch="include" />

    <!-- ==================================================== -->
    <!-- 2. NETWORK CONNECT (Crucial for T1534: Internal Phishing) -->
    <!-- Monitors outbound and inbound connections, useful for tracking C2 or exfiltration attempts post-phishing. -->
    <NetworkConnect onmatch="include" />

    <!-- ==================================================== -->
    <!-- 3. CREATE REMOTE THREAD (Crucial for T1106: Native API Abuse) -->
    <!-- Detects process injection, a hallmark of sophisticated native API usage. -->
    <CreateRemoteThread onmatch="include" />

    <!-- ------------------------------------------------------>
    <!-- Optional Exclusion/Inclusion Logic (Highly minimized) -->
    <!-- These rules exclude logging for standard, trusted system processes
               to reduce noise, but we keep the general monitoring 'onmatch="include"' -->
    <!-- for the primary events above. -->
    <!-- ---------------------------------------------------- -->

  </EventFiltering>

  <!-- Configuration for specific fields to ensure maximum data capture -->
  <EventFields>
    <!-- Ensure that critical fields like Command Line and Original Process Parent are logged -->
    <ProcessCreate>
        <CommandLine condition="exclude">^$</CommandLine>
    </ProcessCreate>
    <NetworkConnect>
        <!-- No specific exclusions needed, we want the full network context -->
    </NetworkConnect>
    <CreateRemoteThread>
        <!-- No specific exclusions needed -->
    </CreateRemoteThread>
  </EventFields>
</Sysmon>
```

***

## Expert Analysis and Justification

### 🔬 Technique Mapping & Configuration Decisions

| Technique | Detection Strategy | Sysmon Event Used | Justification |
| :--- | :--- | :--- | :--- |
| **T1106 (Native API)** | Monitor process injection and use of system APIs that bypass high-level wrappers. | `CreateRemoteThread`, `ProcessCreate` | `CreateRemoteThread` is the most direct indicator of injection (a common native API abuse). `ProcessCreate` helps track scripts that might be using native APIs (e.g., passing raw API calls via `powershell`). |
| **T1648 (Serverless execution)** | Identify unusual execution environments or rapid, transient code execution paths. | `ProcessCreate` | Since we cannot log AWS/Azure APIs, we must monitor the *local* execution artifact. Look for rapid process creation chains, or the execution of cloud CLI tools (e.g., `aws-cli`, `az`) followed by script execution (e.g., `python`, `bash`). |
| **T1534 (Internal Spearphishing)** | Track external communication and interactions with common enterprise tools. | `NetworkConnect`, `ProcessCreate` | `NetworkConnect` is critical for detecting suspicious outbound C2 or exfiltration attempts initiated by a compromised internal application (like an Outlook add-in process). `ProcessCreate` tracks the launch of mail clients or browser processes handling the attachment. |

### 💻 Context Handling & Minimization

1.  **Why the minimal approach?**
    *   The configuration only includes the most event-rich and detection-critical events (`ProcessCreate`, `NetworkConnect`, `CreateRemoteThread`).
    *   We exclude noisier events like `RegistryEvent` or `FileCreate` because their data can often be correlated and covered by the richer context provided by `ProcessCreate` (which tells us *which* process wrote the registry key or created the file).
2.  **Host Context Utilization:**
    *   The high retention of **`ProcessCreate`** and **`NetworkConnect`** is specifically designed to monitor interactions involving the listed applications. For example:
        *   If a malicious actor compromises **Mozilla Firefox** or the **Teams Add-in**, we will catch the resulting communication via `NetworkConnect`.
        *   If a script runs via **WSL** (Linux environment), the full command line captured by `ProcessCreate` will capture the suspicious commands, fulfilling the T1106/T1648 detection requirement.
        *   **Docker Desktop** commands are also captured, allowing visibility into container breakouts or malicious image pulls.

This configuration is optimized for detection yield over logging completeness, achieving a highly focused and efficient monitoring profile.

Time it took: 6 minutes and 6 seconds

### Conclusions

+ No, the EventFields tag is not valid. Additionally it considers that the empty "include" would include all logs and does the opposite 
+ No, it did not use the installed programs in the sysmon config file
+ No, it did not try to use indicators of attack
+ Yes, it tried to use regex `^$` in a sysmon configuration file. Additionally, the EventFields rule could be considered nonsense
+ Yes, since it tried to consider all programs 
+ Not at all, it tried to include all types of logs (eventhough wrongly)

---------------------------------------------------------------------------------------------------------

# Qwen3.5:9b answer:

(No answer after 20 minutes)

--- 

# Comparison

| Name | Valid sysmon file?| Use installed programs? | Indicators of attack? | No nonsense rules? | No irrelevant programs? | "Minimal" respected? | Time |
|:----:|:-----------------:|:-----------------------:|:---------------------:|:---------------:|:--------------------:|:--------------------:|:----:|
| Qwen2.5:14b | ❌ | ❌ | ✅ | ➖ | ✅ | ➖ | 6 min 31s |
| llama3.1:8b (latest) | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | 3min 21s |
| Gemma3:4b (latest) | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | 2min 52 s |
| Gemma4:e4b (latest) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 6min 6s |

❌ - No
✅ - Yes
➖ - Partially

---

# Conclusions

- Some models try to include all logs from an event, in an emergency that would be justified, but I did not mention any risk state, so it was not clear to the models that including all events is very heavy on the log count. 
- Gemma4:e4b i meant ot be a version for laptops and android hardware. That may have impacts on performance.
- Besides LLM "quality", the main concern is probably the prompt building. I can see it being too abstract.
- There needs to be a clear way of showing the model how to build a sysmon config file
- Since the result is going to be used in a pipeline there needs to be a way of asking the AI to not make any more commentaries than the one in the file