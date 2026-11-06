[IOC] Hashes = 6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141, acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4, 31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502, 1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449, 1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11, 24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7, 589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880, 5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241, 60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6, 6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f, 765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a, 7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245, 8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4, 90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c, 97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2, bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc, d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570, d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb, dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da, ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22, f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347, ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b | Source: IoC (file hashes)

[BEHAVIOR] Image ends with "sc.exe" and CommandLine contains "stop" or "config" | Source: T1489 (Service Stop)

[BEHAVIOR] Image = "w3wp.exe" spawning child process Image = "cmd.exe" or "powershell.exe" | Source: T1190 (Exploit Public-Facing Application)

[BEHAVIOR] Image = "mstsc.exe" (Remote Desktop client) execution | Source: T1021.001 (Remote Desktop Protocol)

[BEHAVIOR] Image = "net.exe" with CommandLine matching "use", "view", or "share" for network enumeration | Source: T1018 (Remote System Discovery)

[BEHAVIOR] Image = "ping.exe" or "tracert.exe" executed in rapid succession (≤30 s) | Source: T1018 (Remote System Discovery)

[BEHAVIOR] Image = "vssadmin.exe" and CommandLine contains "delete shadows" or "/all" | Source: T1490 (Inhibit System Recovery)

[BEHAVIOR] Image = "wbadmin.exe" and CommandLine contains "delete catalog" | Source: T1490 (Inhibit System Recovery)

[BEHAVIOR] Image = "bcdedit.exe" and CommandLine contains "bootstatuspolicy" or "recoveryenabled no" | Source: T1490 (Inhibit System Recovery)

[BEHAVIOR] Image = "powershell.exe" with CommandLine containing encoded/obfuscated scripts (e.g., "-enc", "-e") | Source: T1027.002 (Software Packing)

[BEHAVIOR] Image = "cmd.exe" with CommandLine launching executable from %TEMP% or user‑writable path (e.g., "C:\\Windows\\Temp\\*.exe") | Source: T1027.002 (Software Packing)

[BEHAVIOR] Image = "psexec.exe" creating a temporary service (detected via ParentImage = "services.exe") | Source: T1569.002 (Service Execution)

[BEHAVIOR] Image = "reg.exe" with CommandLine modifying HKLM\Software\Microsoft\Windows\CurrentVersion\Run or similar persistence keys | Source: T1112 (Modify Registry)

[BEHAVIOR] Image = "cmd.exe" or "powershell.exe" with CommandLine containing "net user" or "net localgroup" to add privileged accounts | Source: T1078 (Valid Accounts)

[BEHAVIOR] Image = "vssadmin.exe", "wbadmin.exe", "diskshadow.exe", or "bcdedit.exe" executed by a non‑system parent (e.g., user‑initiated PowerShell) | Source: T1490 (Inhibit System Recovery)

--- OMITTED ITEMS AND REASONS ---

Omitted ATT&CK technique T1190 (Exploit Public-Facing Application) – only the post‑exploit process creation (w3wp.exe → shell) is observable via Sysmon; the initial malicious request and HTTP error signals are not captured by Event ID 1, so a dedicated recommendation would be incomplete.

Omitted ATT&CK technique T1219 (Remote Access Tools) – no specific remote‑access tool names, hashes, or command‑line patterns are provided in the intelligence, therefore Event 1 cannot be targeted without introducing inferred values, which would violate the “DERIVED only when not explicit” rule.

Omitted ATT&CK technique T1021.002 (SMB/Windows Admin Shares) – lateral movement via admin shares is manifested by remote file copy and service creation (Event 10/12); Sysmon process‑creation events do not expose the SMB share usage itself, so no reliable Event 1 rule can be defined.

Omitted ATT&CK technique T1566 (Phishing) – the technique operates at the email/URL level; there is no process‑creation artifact directly tied to the phishing activity in the supplied data.

Omitted ATT&CK technique T1078 (Valid Accounts) – while account abuse is a core behavior, the intelligence does not list concrete processes or command‑lines that uniquely indicate valid‑account misuse; generic logon activity is outside Event 1 scope.

Omitted ATT&CK technique T1486 (Data Encrypted for Impact) – ransomware encryption is reflected by massive file‑write activity (Event 11) and shadow‑copy deletion, not by a distinct process‑creation signature in the provided context.

Omitted ATT&CK technique T1112 (Modify Registry) – only registry‑modifying commands are mentioned; Sysmon Event 1 can see the reg.exe process, but no specific registry keys or values are enumerated beyond generic persistence keys, making a precise rule ambiguous without introducing derived values.

Omitted ATT&CK technique T1027.002 (Software Packing) – the only observable behavior is the execution of unpacking stagers (e.g., PowerShell with encoded payloads). While a generic rule is listed, a more precise detection (specific packer names) is not possible from the supplied IoCs.

Omitted CVE‑2023‑3519, CVE‑2023‑48788, CVE‑2024‑57727, CVE‑2025‑5777 – none of the vulnerabilities describe a distinct executable or command line that would be emitted as a process‑creation event; they are network‑oriented (remote code execution, SQL injection, path traversal, memory over‑read). Consequently, Event 1 cannot directly observe them.