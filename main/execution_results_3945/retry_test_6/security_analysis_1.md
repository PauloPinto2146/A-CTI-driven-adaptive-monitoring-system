[IOC] Image = *\wiseman.exe; Hashes.SHA256 = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IOC wiseman.EXE  
[IOC] Image = *\rundll32.exe; CommandLine = *wininet.dll* | Source: IOC wininet.dll  
[BEHAVIOR] Image = *\whoami.exe | Source: T1033 (System Owner/User Discovery)  
[BEHAVIOR] Image = *\query.exe; CommandLine = *user* | Source: T1033 (System Owner/User Discovery)  
[BEHAVIOR] Image = *\net.exe; CommandLine = *user* | Source: T1033 (System Owner/User Discovery)  
[BEHAVIOR] Image = *\rundll32.exe; CommandLine = *\*.dll* | Source: T1218.011 (Rundll32 Abuse)  
[BEHAVIOR] Image = *\rundll32.exe; CommandLine = *\*.cpl* | Source: T1218.011 (Rundll32 Abuse)  
[BEHAVIOR] Image = *\rundll32.exe; CommandLine = *javascript:* | Source: T1218.011 (Rundll32 Abuse)  
[BEHAVIOR] Image = *\sc.exe; CommandLine = *create* | Source: T1543.003 (Windows Service Creation)  
[BEHAVIOR] Image = *\sc.exe; CommandLine = *config* | Source: T1543.003 (Windows Service Creation)  
[BEHAVIOR] Image = *\systeminfo.exe | Source: T1082 (System Information Discovery)  
[BEHAVIOR] Image = *\certutil.exe; CommandLine = *-decode* | Source: T1140 (Deobfuscate/Decode Files)  
[BEHAVIOR] Image = *\certutil.exe; CommandLine = *-decodehex* | Source: T1140 (Deobfuscate/Decode Files)  
[BEHAVIOR] Image = *\powershell.exe; CommandLine = *-EncodedCommand* | Source: T1027 (Obfuscated Files or Information)  
[BEHAVIOR] Image = *\copy.exe; CommandLine = */b* | Source: T1140 (Deobfuscate/Decode Files)  
[BEHAVIOR] Image = *\ipconfig.exe | Source: T1016 (System Network Configuration Discovery)  
[BEHAVIOR] Image = *\ifconfig | Source: T1016 (System Network Configuration Discovery)  
[BEHAVIOR] Image = *\route.exe | Source: T1016 (System Network Configuration Discovery)  
[BEHAVIOR] Image = *\netsh.exe | Source: T1016 (System Network Configuration Discovery)  
[BEHAVIOR] Image = *\arp.exe | Source: T1016 (System Network Configuration Discovery)  
[BEHAVIOR] Image = *\nbtstat.exe | Source: T1016 (System Network Configuration Discovery)  
[BEHAVIOR] Image = *\net.exe; CommandLine = *view* | Source: T1018 (Remote System Discovery)  
[BEHAVIOR] Image = *\ping.exe | Source: T1018 (Remote System Discovery)  
[BEHAVIOR] Image = *\tracert.exe | Source: T1018 (Remote System Discovery)  
[BEHAVIOR] Image = *\nslookup.exe | Source: T1018 (Remote System Discovery)  
[BEHAVIOR] Image = *\mstsc.exe | Source: T1021 (Remote Services)  
[BEHAVIOR] Image = *\ssh.exe | Source: T1021 (Remote Services)  
[BEHAVIOR] Image = *\vncviewer.exe | Source: T1021 (Remote Services)  
[BEHAVIOR] Image = *\runas.exe | Source: T1134 (Access Token Manipulation)  
[DERIVED] Image = *\*; OriginalFileName != *\* | Source: T1036 (Masquerading)  
[DERIVED] Image = *\Startup\* | Source: T1547.001 (Registry Run Keys / Startup Folder)  

---  
**Omitted attack patterns and rationale**

- **T1112 (Modify Registry)** – This technique involves registry writes, which are not captured by Sysmon Event ID 1 (process creation).  
- **T1012 (Query Registry)** – Likewise, registry queries do not generate a process‑creation event with sufficient detail for detection.  
- **T1027 (Obfuscated Files or Information)** – While generic obfuscation can involve many utilities, the specific observable actions (e.g., use of compression tools) were not explicitly mentioned in the provided threat data; the relevant observable behaviors (certutil, PowerShell, copy) are already covered under other techniques.  

**Omitted IoCs**

All provided IoCs (hashes and filenames for *wiseman.EXE* and *wininet.dll*) have been incorporated in the recommendations above; none are omitted.