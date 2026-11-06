[IOC] Image matches any of the provided malicious filenames **or** Hashes SHA256 match any of the listed hashes (e.g., 6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141, acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4, …) | Source: IoCs (sha256 / filename list)

[BEHAVIOR] Image = “lsass.exe” OR Image in {“procdump.exe”, “mimikatz.exe”, “dumppriv.exe”} AND CommandLine contains “lsass” (credential‑dumping activity) | Source: T1003

[BEHAVIOR] Image = “sc.exe” OR Image = “net.exe” OR Image = “powershell.exe” AND CommandLine contains any of {“stop”, “disable”, “delete”, “change”, “config”} AND ServiceName matches critical services (e.g., MSExchangeIS, SQLSERVERAGENT) | Source: T1489

[BEHAVIOR] Image = “psexec.exe” OR Image = “wmic.exe” AND CommandLine includes an admin‑share path (e.g., “\\\\*\\ADMIN$”, “C$”, “\\\\host\\C$”) indicating SMB/Windows Admin Share lateral movement | Source: T1021.002

[BEHAVIOR] Image = “reg.exe” OR Image = “powershell.exe” AND CommandLine references high‑value registry locations such as “HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run”, “HKLM\\System\\CurrentControlSet\\Services”, or “HKCU\\…\\Run” (registry‑modification behavior) | Source: T1112

[BEHAVIOR] Image = “wscript.exe” OR Image = “cscript.exe” OR Image = “mshta.exe” OR Image = “powershell.exe” AND CommandLine contains script‑execution flags (e.g., “/e:vbscript”, “/EncodedCommand”, “/c”, “/b”) indicative of malicious payload execution from phishing attachments | Source: T1566

[BEHAVIOR] ParentImage = “w3wp.exe” AND Image in {“cmd.exe”, “powershell.exe”, “msbuild.exe”, “cscript.exe”} (web‑server process spawning a shell/LOLbin after a crafted request) | Source: T1190

[BEHAVIOR] Image = “mstsc.exe” OR Image = “rdpclip.exe” OR Image = “svchost.exe” AND CommandLine shows remote‑desktop connection parameters (e.g., “/v:”, “/admin”) (RDP login activity) | Source: T1021.001

[BEHAVIOR] Image = “sc.exe” OR Image = “net.exe” OR Image = “psexec.exe” AND CommandLine contains “create” or “config” for a service whose binary is not in a known‑good ServiceBinaryAllowlist (temporary service execution) | Source: T1569.002

[BEHAVIOR] Image in {“vssadmin.exe”, “wbadmin.exe”, “diskshadow.exe”, “bcdedit.exe”, “REAgentC.exe”, “wmic.exe”} AND CommandLine contains destructive flags (e.g., “delete shadows”, “/delete”, “/all”, “bootstatuspolicy ignoreallfailures”, “recoveryenabled no”) (inhibit‑system‑recovery behavior) | Source: T1490

[BEHAVIOR] Image in {“upx.exe”, “mpress.exe”} AND CommandLine includes packing/unpacking switches (software‑packing activity) | Source: T1027.002

[DERIVED] Image = “w3wp.exe” (or other public‑facing service) AND within 15 minutes a child process (e.g., “cmd.exe”, “powershell.exe”, “msbuild.exe”) spawns and initiates an outbound network connection (exploit‑public‑facing‑application chain) | Source: T1190

[DERIVED] Process creation of any executable residing in a user‑writable or temporary directory (e.g., %TEMP%, %APPDATA%) when the parent is a remote‑support tool or unknown binary (indicative of exploitation of CVE‑2024‑57727 or CVE‑2023‑48788) | Source: CVE‑2024‑57727 / CVE‑2023‑48788