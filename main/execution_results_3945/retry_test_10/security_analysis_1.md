[IOC] Image = *\wiseman.exe* | Hashes = SHA256: ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IoC (wiseman.EXE sha256)  
[BEHAVIOR] Image = *\rundll32.exe* | CommandLine contains “.dll” OR “.cpl” OR “javascript:” | Source: T1218.011  
[BEHAVIOR] Image = *\sc.exe* | CommandLine matches “create *” OR “config *” | Source: T1543.003  
[BEHAVIOR] Image = *\powershell.exe* | CommandLine contains “-EncodedCommand” OR “-enc” | Source: T1140  
[BEHAVIOR] Image = *\certutil.exe* | CommandLine contains “-decode” OR “-decodebase64” | Source: T1140  
[BEHAVIOR] Image = *\reg.exe* | CommandLine contains “add” AND CommandLine matches “HKLM\\.*\\Run” | Source: T1112  
[BEHAVIOR] Image = *\whoami.exe* | CommandLine = “whoami” | Source: T1033  
[BEHAVIOR] Image = *\query.exe* | CommandLine contains “user” | Source: T1033  
[BEHAVIOR] Image = *\net.exe* | CommandLine contains “user” | Source: T1033  
[BEHAVIOR] Image = *\systeminfo.exe* | CommandLine = “systeminfo” | Source: T1082  
[BEHAVIOR] Image = *\ipconfig.exe* | CommandLine = “ipconfig /all” | Source: T1016  
[BEHAVIOR] Image = *\netsh.exe* | CommandLine contains “interface ip show” | Source: T1016  
[BEHAVIOR] Image = *\route.exe* | CommandLine contains “print” | Source: T1016  
[BEHAVIOR] Image = *\ping.exe* | CommandLine contains an IPv4 address | Source: T1018  
[BEHAVIOR] Image = *\net.exe* | CommandLine = “net view” | Source: T1018  
[BEHAVIOR] Image = *\runas.exe* | CommandLine contains “/user:” | Source: T1134  
[BEHAVIOR] Image = *\mstsc.exe* | CommandLine contains “/v:” | Source: T1021  
[BEHAVIOR] Image = *\psexec.exe* | CommandLine contains “\\” | Source: T1021  
[DERIVED] Image = *\*.* | OriginalFileName field does NOT match the file name (potential masquerading) | Source: T1036  
[DERIVED] ParentImage = *\explorer.exe* | Child Image = *\rundll32.exe* | CommandLine contains “.dll” | Source: T1218.011  

**Omitted items and rationale**

- **IoC wininet.dll (SHA256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c)** – a DLL is not directly observable by Sysmon Event ID 1, which records process creation, not module load. Monitoring would require a different event (e.g., Event ID 7) and therefore is excluded.  

- **CVE‑2023‑27350 (PaperCut NG authentication bypass)** – the vulnerability is exploited via network‑level request handling, not by creating a new process. Sysmon Event ID 1 cannot capture the remote‑code‑execution vector itself, so no relevant process‑creation rule can be derived.  

- **T1027 – Obfuscated Files or Information** – detection of file‑level obfuscation (creation of .zip, .7z, high‑entropy files) relies on file‑creation events (Event ID 11) rather than process creation, so it is not included here.  

- **T1547.001 – Registry Run Keys / Startup Folder** – this technique modifies registry keys; Sysmon Event ID 1 only logs the process that *writes* the keys (e.g., reg.exe). While generic reg.exe monitoring is covered under T1112, specific Run‑Key writes cannot be uniquely identified without registry‑change events, so no dedicated recommendation is added.  

- **T1027 (Obfuscated Files) – additional payload decoding via custom scripts** – similar to above, requires monitoring of file‑creation or scripting activity beyond what is captured in a process‑creation event.  

All other attack patterns listed have known command‑line utilities that generate observable process‑creation events, and those behaviors are reflected in the recommendations above.