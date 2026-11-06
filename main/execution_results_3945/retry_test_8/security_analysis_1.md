[IOC] Image == *\wiseman.exe* AND Hashes.sha256 == ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  
[IOC] Image == *\wininet.dll* | Source: filename wininet.dll  

[BEHAVIOR] Image == *\whoami.exe* OR CommandLine CONTAINS "whoami" OR CommandLine CONTAINS "query user" OR CommandLine CONTAINS "net user" | Source: T1033 System Owner/User Discovery  

[BEHAVIOR] Image == *\rundll32.exe* AND CommandLine MATCHES_REGEX ".*\.(dll|cpl|sct|hta|js).*|.*javascript:.*|.*mshtml,RunHTMLApplication.*" | Source: T1218.011 Rundll32 Abuse  

[BEHAVIOR] Image == *\sc.exe* AND CommandLine CONTAINS "create" AND CommandLine MATCHES_REGEX ".*(svhostx|winhelp|[^\\]+)$" | Source: T1543.003 Windows Service Creation/Modification  

[BEHAVIOR] Image == *\systeminfo.exe* OR CommandLine CONTAINS "systeminfo" OR CommandLine CONTAINS "systemsetup" | Source: T1082 System Information Discovery  

[BEHAVIOR] Image == *\certutil.exe* AND CommandLine CONTAINS "-decode" | Source: T1140 Deobfuscate/Decode Files or Information  

[BEHAVIOR] Image == *\powershell.exe* AND CommandLine CONTAINS "-EncodedCommand" | Source: T1027 Obfuscated Files or Information  

[BEHAVIOR] Image == *\reg.exe* AND CommandLine CONTAINS "query" | Source: T1012 Query Registry  

[BEHAVIOR] Image == *\runas.exe* OR CommandLine CONTAINS "runas" | Source: T1134 Access Token Manipulation  

[BEHAVIOR] Image == *\net.exe* AND CommandLine CONTAINS "view" | Source: T1018 Remote System Discovery  

[BEHAVIOR] Image == *\ping.exe* OR Image == *\tracert.exe* | Source: T1018 Remote System Discovery  

[BEHAVIOR] Image == *\ipconfig.exe* OR Image == *\ifconfig.exe* OR Image == *\route.exe* OR Image == *\arp.exe* | Source: T1016 System Network Configuration Discovery  

[BEHAVIOR] Image == *\runas.exe* OR Image == *\psexec.exe* OR Image == *\mstsc.exe* | Source: T1021 Remote Services  

[BEHAVIOR] Image == *\explorer.exe* AND CommandLine MATCHES_REGEX ".*(OriginalFilename|CompanyName)\\s*!=\\s*ImageName.*" | Source: T1036 Masquerading  

[DERIVED] ParentImage == *\setupcompleted.exe* AND CommandLine CONTAINS "--run-as-system" | Source: CVE-2023-27350 PaperCut NG authentication bypass (service execution in SYSTEM context)  