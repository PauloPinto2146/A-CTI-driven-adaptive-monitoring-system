[IOC] Image=wiseman.EXE, Hashes=SHA256:ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IOC sha256 ebba8f...

[BEHAVIOR] Image=whoami.exe | Source: T1033

[BEHAVIOR] Image=query.exe, CommandLine=*user* | Source: T1033

[BEHAVIOR] Image=net.exe, CommandLine=*user* | Source: T1033

[BEHAVIOR] Image=rundll32.exe, CommandLine=*.dll* | Source: T1218.011

[BEHAVIOR] Image=rundll32.exe, CommandLine=*.cpl* | Source: T1218.011

[BEHAVIOR] Image=rundll32.exe, CommandLine=*javascript:* | Source: T1218.011

[BEHAVIOR] Image=sc.exe, CommandLine=*create* | Source: T1543.003

[BEHAVIOR] Image=systeminfo.exe | Source: T1082

[BEHAVIOR] Image=certutil.exe, CommandLine=* -decode* | Source: T1140

[BEHAVIOR] Image=copy.exe, CommandLine=* /b* | Source: T1140

[BEHAVIOR] Image=powershell.exe, CommandLine=* -EncodedCommand* | Source: T1140

[BEHAVIOR] OriginalFileName mismatch (process where OriginalFileName ≠ Image filename) | Source: T1036

[BEHAVIOR] Image=mstsc.exe | Source: T1021

[BEHAVIOR] Image=ssh.exe | Source: T1021

[BEHAVIOR] Image=reg.exe, CommandLine=*add* | Source: T1112

[BEHAVIOR] Image=reg.exe, CommandLine=*delete* | Source: T1112

[BEHAVIOR] Image=reg.exe, CommandLine=*query* | Source: T1012

[BEHAVIOR] Image=ipconfig.exe | Source: T1016

[BEHAVIOR] Image=netsh.exe | Source: T1016

[BEHAVIOR] Image=route.exe | Source: T1016

[BEHAVIOR] Image=runas.exe | Source: T1134

[BEHAVIOR] Image=net.exe, CommandLine=*view* | Source: T1018

[BEHAVIOR] Image=ping.exe | Source: T1018

[BEHAVIOR] Image=tracert.exe | Source: T1018

--- Omitted Indicators Explanation ---
The IOC for **wininet.dll** was not included because Sysmon EventID 1 records only process creation; a DLL file on its own does not constitute a process launch and therefore cannot be directly observed via this event type.

The vulnerability **CVE‑2023‑27350** lacked specific executable names, command‑line arguments, or other concrete artifacts tied to the exploitation flow. Without such details, no deterministic process‑creation rule can be derived, so it was omitted from the recommendations.