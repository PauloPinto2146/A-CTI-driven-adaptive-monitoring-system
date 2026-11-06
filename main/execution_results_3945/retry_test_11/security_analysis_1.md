[IOC] Process creation where Image = “wiseman.exe” and Hashes (SHA256) = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IoC sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  

[BEHAVIOR] Process creation of “whoami.exe” (or “whoami” command) | Source: T1033  

[BEHAVIOR] Process creation of “query.exe” or “net.exe” with arguments indicating user enumeration (e.g., “query user”, “net user”) | Source: T1033  

[BEHAVIOR] Process creation of “rundll32.exe” with command‑line containing “.dll”, “.cpl”, “javascript:”, “mshtml” or an ordinal (e.g., “#1”) | Source: T1218.011  

[BEHAVIOR] Process creation of “sc.exe” with arguments “create”, “config”, or “sdset” indicating service creation/modification | Source: T1543.003  

[BEHAVIOR] Process creation of “systeminfo.exe” (or “systemsetup” on macOS) for system information discovery | Source: T1082  

[BEHAVIOR] Process creation of “certutil.exe” with arguments for decoding/encoding (e.g., “-decode”, “-decodehex”) | Source: T1140  

[BEHAVIOR] Process creation of “powershell.exe” with flags such as “-EncodedCommand”, “-e”, or usage of “Invoke‑Expression” for deobfuscation/decoding | Source: T1140  

[DERIVED] Process creation where Image filename does not match the PE OriginalFileName metadata (indicating possible masquerading) | Source: T1036  

[BEHAVIOR] Process creation of remote‑service client binaries such as “mstsc.exe” (RDP), “ssh.exe”, or “vncviewer.exe” | Source: T1021  

[BEHAVIOR] Process creation of “reg.exe” with sub‑command “add” or “delete” indicating registry modification (persistence, privilege escalation) | Source: T1112  

[BEHAVIOR] Process creation of “reg.exe” with sub‑command “query” or “query” via PowerShell for registry reads (environment discovery) | Source: T1012  

[BEHAVIOR] Process creation of “runas.exe” (or PowerShell commands invoking “Start‑Process” with “-Credential”) for token manipulation | Source: T1134  

[BEHAVIOR] Process creation of network‑configuration tools such as “ipconfig.exe”, “netsh.exe”, “route.exe”, “nbtstat.exe”, “ifconfig”, “arp.exe” for system network configuration discovery | Source: T1016  

[BEHAVIOR] Process creation of remote‑system discovery utilities such as “ping.exe”, “tracert.exe”, “net.exe view”, “net view”, “nslookup.exe” in rapid succession | Source: T1018