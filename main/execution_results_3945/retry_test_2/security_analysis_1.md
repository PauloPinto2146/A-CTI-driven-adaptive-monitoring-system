[IOC] Image: wiseman.EXE; Hashes: ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IOC sha256  

[IOC] Image: wininet.dll; Hashes: fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | Source: IOC sha256  

[BEHAVIOR] Image: whoami.exe; CommandLine: * | Source: T1033  

[BEHAVIOR] Image: query.exe; CommandLine: * | Source: T1033  

[BEHAVIOR] Image: net.exe; CommandLine: *user* | Source: T1033  

[BEHAVIOR] Image: rundll32.exe; CommandLine: *\.dll* | Source: T1218.011  

[BEHAVIOR] Image: rundll32.exe; CommandLine: *\.cpl* | Source: T1218.011  

[BEHAVIOR] Image: rundll32.exe; CommandLine: *javascript:* | Source: T1218.011  

[BEHAVIOR] Image: sc.exe; CommandLine: *create* | Source: T1543.003  

[BEHAVIOR] Image: sc.exe; CommandLine: *config* | Source: T1543.003  

[BEHAVIOR] Image: systeminfo.exe; CommandLine: * | Source: T1082  

[BEHAVIOR] Image: wmic.exe; CommandLine: *os get* | Source: T1082  

[BEHAVIOR] Image: certutil.exe; CommandLine: *-decode* | Source: T1140  

[BEHAVIOR] Image: powershell.exe; CommandLine: *-EncodedCommand* | Source: T1140  

[BEHAVIOR] Image: copy.exe; CommandLine: */b* | Source: T1140  

[BEHAVIOR] Image: reg.exe; CommandLine: *add*HKLM\Software\Microsoft\Windows\CurrentVersion\Run* | Source: T1547.001  

[BEHAVIOR] Image: reg.exe; CommandLine: *query* | Source: T1012  

[BEHAVIOR] Image: ipconfig.exe; CommandLine: * | Source: T1016  

[BEHAVIOR] Image: netsh.exe; CommandLine: * | Source: T1016  

[BEHAVIOR] Image: route.exe; CommandLine: * | Source: T1016  

[BEHAVIOR] Image: mstsc.exe; CommandLine: * | Source: T1021  

[BEHAVIOR] Image: ssh.exe; CommandLine: * | Source: T1021  

[BEHAVIOR] Image: psexec.exe; CommandLine: * | Source: T1021  

[BEHAVIOR] Image: runas.exe; CommandLine: * | Source: T1134  

[BEHAVIOR] Image: ping.exe; CommandLine: * | Source: T1018  

[BEHAVIOR] Image: net.exe; CommandLine: *view* | Source: T1018  

[BEHAVIOR] Image: tracert.exe; CommandLine: * | Source: T1018  

[DERIVED] ParentImage: *PaperCut*; Image: cmd.exe; CommandLine: * | Source: CVE-2023-27350  

---  

**Omitted Attack Patterns Explanation**  
No attack pattern from the supplied list was omitted because each one maps to at least one observable process‑creation artifact (e.g., a specific utility, command‑line flag, or parent‑child relationship) that Sysmon Event ID 1 can record. All recommendations therefore remain traceable to the provided context.