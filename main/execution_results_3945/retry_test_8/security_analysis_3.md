[BEHAVIOR] Image: *\rundll32.exe | Protocol: any | Initiated: true | SourceIp: * | DestinationIp: * | DestinationPort: * | Source: T1218.011 (Rundll32 abuse)  

[BEHAVIOR] Protocol: UDP | DestinationPort: 53 (DNS) | Initiated: true | Image: *\* (any non‑system process) | SourceIp: * | DestinationIp: * | Source: T1071.004 (DNS tunneling)  

[BEHAVIOR] DestinationPort: 3389 (RDP) | Initiated: true | Image: *\* (any process not mstsc.exe) | SourceIp: * | DestinationIp: * | Source: T1021 (Remote Services)  

[BEHAVIOR] DestinationPort: 22 (SSH) | Initiated: true | Image: *\* (any process not ssh.exe) | SourceIp: * | DestinationIp: * | Source: T1021 (Remote Services)  

[BEHAVIOR] DestinationPort: 445 (SMB) | Initiated: true | Image: *\* (any process) | SourceIp: * | DestinationIp: * | Source: T1018 (Remote System Discovery)  

[DERIVED] DestinationPort: 443 (HTTPS) | Initiated: true | Image: *\* (any atypical process) | SourceIp: * | DestinationIp: * | Source: T1102.001 (Dead‑Drop Resolver)  

[IOC] Image: *\wiseman.exe | Protocol: any | Initiated: * | SourceIp: * | DestinationIp: * | Source: IOC (wiseman.EXE)  

[IOC] Image: *\rundll32.exe | CommandLine: *wininet.dll* | Protocol: any | Initiated: true | SourceIp: * | DestinationIp: * | Source: IOC (wininet.dll)  

---

**Explanation of omitted items:**  

- The SHA‑256 hash values of the two samples are not usable for Event ID 3 because this Sysmon event records only network‑connection metadata (process image, IPs, ports, etc.) and does not contain file‑hash information.  

- No explicit IP addresses, hostnames, or domain names were provided in the threat data, so no [IOC] recommendations could be created for those fields.  

- CVE‑2023‑27350 describes a server‑side authentication bypass in PaperCut NG; the vulnerability does not specify particular client‑side network‑connection characteristics (e.g., destination IP, port, or protocol) that could be captured by Sysmon Event 3, therefore no recommendation directly tied to this CVE is included.