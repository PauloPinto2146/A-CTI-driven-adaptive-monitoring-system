[IOC] Image: *\wiseman.exe, Protocol: any, Initiated: true, SourceIp: any, DestinationIp: any, SourcePort: any, DestinationPort: any | Source: IOC (sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205)

[BEHAVIOR] Image: *\rundll32.exe, Protocol: any, Initiated: true, DestinationIp: external, DestinationPort: any | Source: T1218.011

[BEHAVIOR] Protocol: DNS, Initiated: true, Image: *\rundll32.exe, SourcePort: any, DestinationPort: 53 | Source: T1071.004

[BEHAVIOR] Protocol: DNS, Initiated: true, Image: *\powershell.exe, SourcePort: any, DestinationPort: 53 | Source: T1071.004

[BEHAVIOR] Protocol: DNS, Initiated: true, Image: *\python.exe, SourcePort: any, DestinationPort: 53 | Source: T1071.004

[DERIVED] DestinationPort: 3389, Protocol: TCP, Initiated: true, Image: any | Source: T1021

[DERIVED] DestinationPort: 22, Protocol: TCP, Initiated: true, Image: any | Source: T1021

[DERIVED] DestinationPort: 5900, Protocol: TCP, Initiated: true, Image: any | Source: T1021

[DERIVED] DestinationPort: 445, Protocol: TCP, Initiated: true, Image: *\net.exe | Source: T1018

[DERIVED] DestinationPort: 445, Protocol: TCP, Initiated: true, Image: *\cmd.exe | Source: T1018

[DERIVED] DestinationPort: 445, Protocol: TCP, Initiated: true, Image: *\powershell.exe | Source: T1018

[DERIVED] DestinationPort: 80, Protocol: TCP, Initiated: true, Image: *\rundll32.exe | Source: T1102.001

[DERIVED] DestinationPort: 443, Protocol: TCP, Initiated: true, Image: *\rundll32.exe | Source: T1102.001

--- Explanations for omitted items ---

* wininet.dll – This indicator is a DLL file hash. Sysmon Event ID 3 logs network connections and associates them with the originating **process image**, not with loaded DLL modules. Because the DLL name/hash does not appear as an Image field, it cannot be directly observed through this event type.

* CVE‑2023‑27350 – The vulnerability description notes remote code execution on the host but does not specify any particular network‑connection characteristics (e.g., IPs, ports, protocols). Without concrete network artefacts, there is no observable element that can be captured by Event ID 3.