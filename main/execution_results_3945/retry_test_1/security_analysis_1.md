[IOC] Hashes: ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: SHA256‑wiseman.EXE  
[IOC] Hashes: fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | Source: SHA256‑wininet.dll  

[BEHAVIOR] Image: whoami.exe | CommandLine: “whoami” | IntegrityLevel: any | Source: T1033  
[BEHAVIOR] Image: query.exe | CommandLine contains “user” | IntegrityLevel: any | Source: T1033  
[BEHAVIOR] Image: qprocess.exe | CommandLine contains “query user” | IntegrityLevel: any | Source: T1033  

[BEHAVIOR] Image: rundll32.exe | CommandLine contains “wininet.dll” | IntegrityLevel: any | Source: T1218.011  
[BEHAVIOR] Image: rundll32.exe | CommandLine contains “.cpl” | IntegrityLevel: any | Source: T1218.011  

[BEHAVIOR] Image: sc.exe | CommandLine contains “create” | IntegrityLevel: high | Source: T1543.003  
[BEHAVIOR] Image: powershell.exe | CommandLine contains “-EncodedCommand” | IntegrityLevel: any | Source: T1027  

[BEHAVIOR] Image: certutil.exe | CommandLine contains “-decode” or “-decodehex” | IntegrityLevel: any | Source: T1140  
[BEHAVIOR] Image: copy.exe | CommandLine matches “/b *” | IntegrityLevel: any | Source: T1140  

[BEHAVIOR] Image: systeminfo.exe | CommandLine: none or “/?” | IntegrityLevel: any | Source: T1082  
[BEHAVIOR] Image: wmic.exe | CommandLine contains “computersystem get *” | IntegrityLevel: any | Source: T1082  

[BEHAVIOR] Image: ipconfig.exe | CommandLine: none or “/all” | IntegrityLevel: any | Source: T1016  
[BEHAVIOR] Image: netsh.exe | CommandLine contains “interface ip show config” | IntegrityLevel: any | Source: T1016  
[BEHAVIOR] Image: route.exe | CommandLine contains “print” | IntegrityLevel: any | Source: T1016  

[BEHAVIOR] Image: reg.exe | CommandLine contains “query” | IntegrityLevel: any | Source: T1012  

[BEHAVIOR] Image: runas.exe | CommandLine contains “/user:” | IntegrityLevel: any | Source: T1134  

[BEHAVIOR] Image: mstsc.exe | CommandLine contains “/v:” | IntegrityLevel: any | Source: T1021  
[BEHAVIOR] Image: ssh.exe | CommandLine contains “-l” | IntegrityLevel: any | Source: T1021  

[BEHAVIOR] Image: ping.exe | CommandLine contains a target IP address | IntegrityLevel: any | Source: T1018  
[BEHAVIOR] Image: net.exe | CommandLine contains “view” | IntegrityLevel: any | Source: T1018  

[DERIVED] ParentImage: any process | Child Image: any newly created process with a hash not in the corporate baseline (high entropy) | Source: CVE‑2023‑27350 (detect unexpected system‑level binaries potentially dropped by the exploit)  