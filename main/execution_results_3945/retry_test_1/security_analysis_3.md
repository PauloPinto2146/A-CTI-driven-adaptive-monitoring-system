[IOC] Image = *\wiseman.EXE* (process hash ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205) | Source: sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  

[BEHAVIOR] Image = *\rundll32.exe* | Protocol = TCP/UDP | Initiated = true | any DestinationIp/DestinationPort (monitor atypical outbound connections from rundll32.exe) | Source: T1218.011  

[BEHAVIOR] Image ≠ (browser || system) | Protocol = UDP | DestinationPort = 53 | Initiated = true | any DestinationHostname (detect non‑browser processes making DNS queries) | Source: T1071.004  

[BEHAVIOR] Image = *\mstsc.exe* | Protocol = TCP | DestinationPort = 3389 | Initiated = true | any DestinationIp (monitor RDP client connections) | Source: T1021  

[BEHAVIOR] Image = *\ssh.exe* | Protocol = TCP | DestinationPort = 22 | Initiated = true | any DestinationIp (monitor SSH client connections) | Source: T1021  

[BEHAVIOR] Image = *\net.exe* | Protocol = TCP | DestinationPort = 445 | Initiated = true | any DestinationIp (monitor SMB connections launched by net.exe for remote‑system discovery) | Source: T1018  

[DERIVED] Image = any | Protocol = TCP/UDP | DestinationPort = any | Initiated = true | DestinationIp ∈ external IP ranges not normally contacted by the host (observe anomalous outbound traffic that may result from exploitation of CVE‑2023‑27350) | Source: CVE-2023-27350  

[DERIVED] Image = any | Protocol = TCP/UDP | DestinationPort = 80 | or 443 | Initiated = true | DestinationHostname ∈ {pastebin.com, twitter.com, github.com} (monitor access to common dead‑drop resolver web services) | Source: T1102.001  

**Omitted IoC:** *wininet.dll* – the file is a DLL, not an executable process; Sysmon Event ID 3 records network connections per process, so a DLL alone cannot be observed as the Image field.  

**All listed attack patterns are addressed**; none were omitted because each has a network‑connection‑relevant behavior that can be captured by Sysmon Event ID 3.