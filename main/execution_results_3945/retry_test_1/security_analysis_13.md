[BEHAVIOR] EventType: SetValue, Image: C:\Windows\System32\sc.exe, TargetObject: HKLM\System\CurrentControlSet\Services\*\Start, Details: Service start type (DWORD) created or changed (e.g., 0=Boot, 2=Automatic, 3=Manual, 4=Disabled) | Source: T1543.003  

[BEHAVIOR] EventType: SetValue, Image: C:\Windows\System32\services.exe, TargetObject: HKLM\System\CurrentControlSet\Services\*\Start, Details: Service start type (DWORD) altered during service installation or modification | Source: T1543.003  

[BEHAVIOR] EventType: SetValue, Image: C:\Windows\System32\powershell.exe, TargetObject: HKLM\System\CurrentControlSet\Services\*\Start, Details: Service start type (DWORD) set via PowerShell cmdlets (e.g., New-Service, Set-Service) | Source: T1543.003  

[BEHAVIOR] EventType: SetValue, Image: C:\Windows\System32\reg.exe, TargetObject: HKLM\System\CurrentControlSet\Services\*\Start, Details: Direct registry write changing service start type (DWORD) | Source: T1543.003  

**Why other indicators were not included**

- **IOC – “wiseman.EXE” and “wininet.dll”** – Sysmon Event ID 13 only records *registry value writes*. The provided filenames are executable or DLL objects; there is no explicit statement that these binaries write DWORD/QWORD values to the registry. Without a concrete registry key or value tied to those files, they cannot be observed with this event type, so they are omitted.

- **T1056.001 (Keylogging)** – The technique mentions “registry modifications” as part of a keylogger’s installation, but no specific DWORD/QWORD registry values or keys are enumerated in the context. Since Event 13 does not capture string‑type Run‑key writes (the usual persistence mechanism for keyloggers), there is no concrete registry modification to monitor here.

- **T1082 (System Information Discovery)** – This technique involves *reading* system information, not writing registry values. Event 13 captures only writes, so it cannot be used to detect this behavior.

- **T1112 (Modify Registry)** – The description covers a broad range of registry edits, many of which are string‑type (e.g., Run keys, SafeDllSearchMode). The only DWORD/QWORD modifications explicitly linked to a concrete technique in the provided context are the service *Start* values under HKLM\System\CurrentControlSet\Services, already addressed under T1543.003. Other possible DWORD edits (e.g., “EnableLUA”, “SafeDllSearchMode”) are not mentioned in the supplied intelligence, so they would be DERIVED and therefore excluded per the requirement to avoid unverifiable concrete values.

- **T1547.001 (Registry Run Keys / Startup Folder)** – Persistence via Run keys primarily uses string values (paths to executables). Since Event 13 does not record string‑type value writes, there is no applicable registry modification to monitor.

- **T1012 (Query Registry)** – This technique is about *reading* registry data, not writing, and thus falls outside the scope of Event 13.

- **CVE‑2023‑27350** – The vulnerability description details authentication bypass and arbitrary code execution in the context of SYSTEM, but it does **not** specify any particular registry value (DWORD/QWORD) that is written as part of the exploit. Without such a concrete registry write, Event 13 cannot be used to directly detect exploitation of this CVE.