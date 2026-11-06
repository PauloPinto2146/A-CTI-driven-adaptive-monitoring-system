[IOC] Process creation where Hashes (SHA256) = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (wiseman.EXE) | Source: IOC sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  
[IOC] Process creation where Image = wininet.dll or CommandLine contains “wininet.dll” and Hashes (SHA256) = fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | Source: IOC sha256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c  

[BEHAVIOR] Process creation where Image = whoami.exe or CommandLine contains “whoami” | Source: T1033 (System Owner/User Discovery)  
[BEHAVIOR] Process creation where Image = query.exe or CommandLine contains “query user” | Source: T1033 (System Owner/User Discovery)  
[BEHAVIOR] Process creation where Image = net.exe and CommandLine matches “user *” | Source: T1033 (System Owner/User Discovery)  

[BEHAVIOR] Process creation where Image = rundll32.exe and CommandLine matches “*.dll*” or CommandLine contains “.cpl” or CommandLine contains “javascript:” or CommandLine contains “mshtml” | Source: T1218.011 (Rundll32 Abuse)  

[BEHAVIOR] Process creation where Image = sc.exe and CommandLine contains “create” or CommandLine contains “config” | Source: T1543.003 (Windows Service)  
[BEHAVIOR] Process creation where Image = powershell.exe and CommandLine contains “New-Service” or CommandLine contains “Set-Service” | Source: T1543.003 (Windows Service)  

[BEHAVIOR] Process creation where Image = systeminfo.exe or CommandLine contains “systeminfo” | Source: T1082 (System Information Discovery)  

[BEHAVIOR] Process creation where Image = certutil.exe and CommandLine contains “-decode” or CommandLine contains “-decodehex” | Source: T1140 (Deobfuscate/Decode Files or Information)  
[BEHAVIOR] Process creation where Image = powershell.exe and CommandLine contains “-EncodedCommand” | Source: T1140 (Deobfuscate/Decode Files or Information)  
[BEHAVIOR] Process creation where Image = copy.exe and CommandLine matches “/b *” | Source: T1140 (Deobfuscate/Decode Files or Information)  

[DERIVED] Process creation where OriginalFileName field does not match the filename component of Image (indicates possible masquerading) | Source: T1036 (Masquerading)  

[BEHAVIOR] Process creation where Image = mstsc.exe or Image = rdpclip.exe or Image = ssh.exe or Image = psexec.exe | Source: T1021 (Remote Services)  

[BEHAVIOR] Process creation where Image = reg.exe and CommandLine contains “add” or CommandLine contains “delete” or CommandLine contains “save” | Source: T1112 (Modify Registry)  

[BEHAVIOR] Process creation where Image = ipconfig.exe or Image = netsh.exe or Image = route.exe or Image = arp.exe | Source: T1016 (System Network Configuration Discovery)  

[BEHAVIOR] Process creation where Image = reg.exe and CommandLine contains “HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run” or CommandLine contains “HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run” | Source: T1547.001 (Registry Run Keys / Startup Folder)  

[DERIVED] Process creation where Image = 7z.exe or Image = winrar.exe or Image = compact.exe and CommandLine creates/compresses archive files (e.g., “*.zip”, “*.7z”) | Source: T1027 (Obfuscated Files or Information)  

[BEHAVIOR] Process creation where Image = runas.exe or CommandLine contains “runas /user:” | Source: T1134 (Access Token Manipulation)  

[BEHAVIOR] Process creation where Image = ping.exe or Image = tracert.exe or Image = net.exe and CommandLine contains “view” or CommandLine contains IP addresses | Source: T1018 (Remote System Discovery)  