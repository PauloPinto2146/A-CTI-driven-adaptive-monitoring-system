[IOC] EventType=SetValue, Image=*\\wiseman.exe, TargetObject=*, Details=* | Source: IOC filename wiseman.EXE  
[BEHAVIOR] EventType=SetValue, Image=*\\sc.exe, TargetObject=HKLM\System\CurrentControlSet\Services\*, Details=* | Source: T1543.003  
[BEHAVIOR] EventType=SetValue, Image=*\\powershell.exe, TargetObject=HKLM\System\CurrentControlSet\Services\*, Details=* | Source: T1543.003  
[BEHAVIOR] EventType=SetValue, Image=*\\sc.exe, TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run*, Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue, Image=*\\powershell.exe, TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run*, Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue, Image=*\\svchost.exe, TargetObject=*, Details=* | Source: T1056.001  

**Omitted items and rationale**

- **wininet.dll** – This IOC is a DLL, not an executable process. Sysmon EventID 13 records the *process* (Image) that writes a registry value; there is no direct way to associate a DLL file name with a SetValue event, so it cannot be reliably monitored via this event type.

- **T1082 (System Information Discovery)** – The technique involves gathering OS and hardware details through commands or APIs. It does not entail writing registry values, therefore EventID 13 cannot capture relevant activity for this technique.

- **T1012 (Query Registry)** – This technique is limited to reading registry data. EventID 13 only logs modifications (writes) to the registry, not read operations, so no monitoring recommendation can be derived from it.

- **CVE‑2023‑27350** – The vulnerability description details authentication bypass and arbitrary code execution but does not specify any registry‑value modifications as part of the exploit. Without explicit registry writes, EventID 13 cannot be used to detect exploitation of this CVE.