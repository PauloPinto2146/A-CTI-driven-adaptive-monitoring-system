[IOC] Image = wiseman.exe AND Hashes = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IOC sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  

[BEHAVIOR] Image = rundll32.exe AND CommandLine contains ".dll" OR ".cpl" OR "javascript:" OR "mshtml" | Source: T1218.011  

[BEHAVIOR] Image = sc.exe OR powershell.exe AND CommandLine contains "create" "service" | Source: T1543.003  

[BEHAVIOR] Image = whoami.exe OR query.exe OR net.exe AND CommandLine contains "user" | Source: T1033  

[BEHAVIOR] Image = systeminfo.exe OR hostname.exe OR ver.exe | Source: T1082  

[BEHAVIOR] Image = certutil.exe AND CommandLine contains "-decode" OR "-decodehex" OR "-split" | Source: T1140  

[BEHAVIOR] Image = certutil.exe OR powershell.exe AND CommandLine contains "-EncodedCommand" OR base64‑encoded payload | Source: T1027  

[BEHAVIOR] Image = reg.exe AND CommandLine contains "query" | Source: T1012  

[BEHAVIOR] Image = runas.exe | Source: T1134  

[BEHAVIOR] Image = ipconfig.exe OR ifconfig.exe OR netsh.exe OR route.exe OR arp.exe OR nbtscan.exe | Source: T1016  

[BEHAVIOR] Image = mstsc.exe OR ssh.exe OR psexec.exe | Source: T1021  

[BEHAVIOR] Image filename differs from PE OriginalFileName metadata (e.g., Image = *\example.exe* but OriginalFileName ≠ *example.exe*) | Source: T1036  

[DERIVED] IntegrityLevel = System AND Image NOT IN {svchost.exe, services.exe, lsass.exe, winlogon.exe, csrss.exe} | Source: CVE-2023-27350  

---  

**Omitted Indicators / Attack Patterns and Rationale**  
- **wininet.dll (IOC)** – This is a DLL, not an executable. Sysmon Event ID 1 records process creation only, so DLL loading cannot be observed directly.  
- **T1112 – Modify Registry** – Registry write activity is captured by Sysmon Event ID 12 (RegistryEvent), not by Event ID 1. Therefore it cannot be monitored with process‑creation events.  
- **T1547.001 – Registry Run Keys / Startup Folder** – Persistence via registry run keys involves registry writes, which are outside the scope of process‑creation logging (Event ID 1).  

No other provided indicators or techniques lack a viable observation point within Sysmon process‑creation events.