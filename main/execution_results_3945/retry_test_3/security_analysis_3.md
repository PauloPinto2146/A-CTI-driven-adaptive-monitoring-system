[BEHAVIOR] Image: *\rundll32.exe, Protocol: *, Initiated: true, SourceIp: *, SourceHostname: *, SourcePort: *, DestinationIp: *, DestinationHostname: *, DestinationPort: *, DestinationPortName: * | Source: T1218.011  

[IOC] Image: *\wiseman.exe, Protocol: *, Initiated: true, SourceIp: *, SourceHostname: *, SourcePort: *, DestinationIp: *, DestinationHostname: *, DestinationPort: *, DestinationPortName: * | Source: IOC (sha256 = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205)  

[BEHAVIOR] Image: *, Protocol: UDP, Initiated: true, DestinationPort: 53, DestinationPortName: DNS, SourceIp: *, SourceHostname: *, SourcePort: * | Source: T1071.004  

**Explanation of omitted items**

- **wininet.dll (SHA256 = fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c)** – This is a library file, not an executable process. Sysmon Event ID 3 records network connections per **process**, so the DLL itself cannot be directly observed; therefore no recommendation can be derived from this IoC for this event type.  

- **T1021 (Remote Services)** – The ATT&CK description mentions logons via RDP, SSH, VNC, etc., but no specific ports, hostnames, or process names are provided in the context. Since Event ID 3 can only log concrete connection attributes, and none are supplied, we cannot formulate a precise, value‑based recommendation for this pattern.  

- **T1018 (Remote System Discovery)** – This technique involves enumerating hosts (e.g., using `net view`, `ping`). The activity is typically observed as command‑line execution, not as a distinct network connection pattern, and no explicit network indicators (IP/port) are given. Consequently, Event ID 3 does not yield a concrete observation that can be linked to this technique.  

- **T1102.001 (Dead‑Drop Resolver)** – The technique describes contacting “common web services” (e.g., pastebin.com, twitter.com) but no concrete domain or IP is provided. Without a specific network endpoint, we cannot craft a deterministic Event ID 3 filter; therefore this pattern is omitted.  

- **CVE‑2023‑27350** – The vulnerability enables authentication bypass on a PaperCut NG server and subsequent SYSTEM‑level code execution. No network‑level indicators (e.g., target IP, port, protocol) are described, so Event ID 3 cannot capture a distinct artifact of this CVE.  

Only the three recommendations above meet the requirement that they be observable through Sysmon Event ID 3 and are directly supported by the provided IoCs or ATT&CK behavior descriptions.