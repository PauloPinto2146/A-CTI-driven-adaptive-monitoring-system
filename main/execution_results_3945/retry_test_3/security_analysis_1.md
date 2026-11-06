[IOC] Image equals "wiseman.EXE" AND Hashes.sha256 equals "ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205" | Source: IOC sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  
[IOC] Image equals "wininet.dll" AND Hashes.sha256 equals "fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c" | Source: IOC sha256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c  
[BEHAVIOR] Image equals "whoami.exe" OR CommandLine contains "whoami" | Source: T1033  
[BEHAVIOR] Image equals "query.exe" OR CommandLine contains "query user" OR CommandLine contains "net user" | Source: T1033  
[BEHAVIOR] Image equals "rundll32.exe" AND CommandLine matches regex ".*\.(dll|cpl|js|javascript:).*" | Source: T1218.011  
[BEHAVIOR] ParentImage equals "rundll32.exe" AND Image ends with ".exe" | Source: T1218.011  
[BEHAVIOR] Image equals "sc.exe" AND CommandLine contains "create" OR CommandLine contains "config" | Source: T1543.003  
[BEHAVIOR] Image equals "systeminfo.exe" OR CommandLine contains "systeminfo" | Source: T1082  
[BEHAVIOR] Image equals "hostname.exe" OR CommandLine contains "hostname" | Source: T1082  
[BEHAVIOR] Image equals "certutil.exe" AND CommandLine contains "-decode" | Source: T1140  
[BEHAVIOR] Image equals "powershell.exe" AND CommandLine contains "-EncodedCommand" | Source: T1140  
[BEHAVIOR] Image equals "copy.exe" AND CommandLine matches regex "copy\s+/b\s+.*" | Source: T1140  
[BEHAVIOR] Image equals "reg.exe" AND CommandLine contains "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | Source: T1547.001  
[BEHAVIOR] Image equals "reg.exe" AND CommandLine contains "HKLM\\System\\CurrentControlSet\\Services" | Source: T1543.003  
[BEHAVIOR] Image equals "reg.exe" AND CommandLine contains "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies" | Source: T1112  
[BEHAVIOR] Image equals "ipconfig.exe" OR Image equals "ifconfig.exe" OR Image equals "netsh.exe" OR Image equals "route.exe" | Source: T1016  
[BEHAVIOR] Image equals "arp.exe" | Source: T1016  
[BEHAVIOR] Image equals "runas.exe" | Source: T1134  
[BEHAVIOR] Image equals "psexec.exe" AND CommandLine contains "-s" | Source: T1134  
[BEHAVIOR] Image equals "mstsc.exe" OR Image equals "ssh.exe" OR Image equals "rdpclip.exe" | Source: T1021  
[BEHAVIOR] Image equals "net.exe" AND CommandLine contains "view" | Source: T1018  
[BEHAVIOR] Image equals "ping.exe" OR Image equals "tracert.exe" OR Image equals "nbtstat.exe" | Source: T1018  
[DERIVED] IntegrityLevel equals "System" for newly created processes where ParentImage is not a known service, scheduled task, or installer | Source: CVE-2023-27350  
[DERIVED] OriginalFileName from PE metadata does NOT match Image filename (mismatch) | Source: T1036