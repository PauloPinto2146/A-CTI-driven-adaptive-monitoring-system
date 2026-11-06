[IOC] EventType:SetValue Image:wiseman.EXE TargetObject:* Details:* | Source: IOC:wiseman.EXE  
[IOC] EventType:SetValue Image:wininet.dll TargetObject:* Details:* | Source: IOC:wininet.dll  
[BEHAVIOR] EventType:SetValue Image:* TargetObject:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\*\ImagePath Details:* | Source: T1543.003  
[BEHAVIOR] EventType:SetValue Image:* TargetObject:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\*\Type Details:* | Source: T1543.003  
[BEHAVIOR] EventType:SetValue Image:* TargetObject:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run* Details:* | Source: T1547.001  
[BEHAVIOR] EventType:SetValue Image:* TargetObject:HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run* Details:* | Source: T1547.001  
[BEHAVIOR] EventType:SetValue Image:* TargetObject:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run Details:* | Source: T1112  
[BEHAVIOR] EventType:SetValue Image:* TargetObject:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\BootExecute Details:* | Source: T1112  

**Omitted attack patterns and why they were not included**

- **T1082 (System Information Discovery)** – This technique is focused on reading system information; it does not involve writing registry values, so it cannot be observed with Sysmon Event ID 13 (SetValue).  
- **T1012 (Query Registry)** – Similarly, this technique involves reading registry data, not modifying it, and therefore is outside the scope of Event ID 13.  
- **T1056.001 (Keylogging)** – The primary behavior described for keylogging is API hooking and direct keystroke capture. While a keylogger may later use persistence mechanisms (covered under T1547.001), the technique itself does not explicitly mandate registry value writes of DWORD/QWORD type, so no dedicated SetValue monitoring rule was added beyond the generic persistence keys already covered.  

No other indicators of compromise or vulnerability‑specific registry paths were provided, so no additional recommendations could be justified.