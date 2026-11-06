[IOC] SetValue where Image ends with “wiseman.exe” | Source: IOC filename wiseman.EXE  
[IOC] SetValue where Image ends with “wininet.dll” | Source: IOC filename wininet.dll  
[BEHAVIOR] SetValue where TargetObject matches “HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*” (or any value under the Run/RunOnce keys) | Source: T1547.001  
[BEHAVIOR] SetValue where TargetObject matches “HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*” (or any value under the user‑specific Run/RunOnce keys) | Source: T1547.001  
[BEHAVIOR] SetValue where TargetObject matches “HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*” | Source: T1547.001  
[BEHAVIOR] SetValue where TargetObject matches “HKLM\System\CurrentControlSet\Services\*\ImagePath” (service executable path) | Source: T1543.003  
[BEHAVIOR] SetValue where TargetObject matches “HKLM\System\CurrentControlSet\Services\*\Type” (service type) | Source: T1543.003  
[BEHAVIOR] SetValue where TargetObject matches “HKLM\System\CurrentControlSet\Services\*\Start” (service startup type) | Source: T1543.003  
[BEHAVIOR] SetValue where TargetObject matches “HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute” (non‑default boot commands) | Source: T1547.001  
[BEHAVIOR] SetValue where TargetObject matches any of the following persistence‑related keys: “HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce”, “HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce”, “HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices”, “HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices”, “HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce”, “HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce” | Source: T1112  
[BEHAVIOR] SetValue where TargetObject matches “HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*” (policy‑run keys) | Source: T1112  
[DERIVED] SetValue where TargetObject matches “HKLM\System\CurrentControlSet\Services\*\ImagePath” and Details end with “.sys” (installation of a driver that could be used for low‑level keylogging) | Source: T1056.001  

**Why certain items were not included**

- **T1082 (System Information Discovery)** – This technique involves querying system information; it does not create or modify registry values, so EventID 13 cannot capture it.  
- **T1012 (Query Registry)** – The technique is limited to reading registry data. EventID 13 records only value **writes**, therefore it is not applicable.  
- **T1056.001 (Keylogging)** – The ATT&CK description mentions hooking APIs, raw keystroke buffers, driver use, etc., but does not specify any particular registry keys that are modified for keylogging. Only a derived recommendation (monitoring .sys driver registration) could be inferred, which is labeled [DERIVED].  
- **CVE‑2023‑27350** – The vulnerability description references an unauthenticated code‑execution path via the `SetupCompleted` class and does not identify any registry keys or values that are written as part of the exploit. Consequently, no direct EventID 13 monitoring can be tied to this CVE.