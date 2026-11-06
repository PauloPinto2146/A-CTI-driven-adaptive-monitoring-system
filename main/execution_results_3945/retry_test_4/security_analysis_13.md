[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*; Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*; Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\*; Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\*\Depend; Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*; Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\System\CurrentControlSet\Services\*\ImagePath; Details=* | Source: T1543.003  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\System\CurrentControlSet\Services\*\Start; Details=* | Source: T1543.003  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\System\CurrentControlSet\Services\*\Type; Details=* | Source: T1543.003  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute; Details=* | Source: T1547.001  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit; Details=* | Source: T1112  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell; Details=* | Source: T1112  
[BEHAVIOR] EventType=SetValue; Image=*; TargetObject=HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode; Details=* | Source: T1112  

[IOC] EventType=SetValue; Image=*wiseman.EXE*; TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*; Details=* | Source: filename wiseman.EXE  
[IOC] EventType=SetValue; Image=*wininet.dll*; TargetObject=HKLM\System\CurrentControlSet\Services\*; Details=* | Source: filename wininet.dll  

**Omissions explained**

- **T1056.001 (Keylogging)** – The described techniques focus on API hooking, driver installation, or hardware‑buffer reads. No specific registry values are mentioned that could be captured by Sysmon EventID 13, so no SetValue monitoring is required.  
- **T1082 (System Information Discovery)** – This technique involves querying system information, not writing registry values; therefore it cannot be observed with EventID 13.  
- **T1012 (Query Registry)** – As a read‑only operation, it does not generate SetValue events, so it is excluded.  
- **CVE‑2023‑27350** – The vulnerability description details an authentication bypass and arbitrary code execution via the SetupCompleted class, but it does not specify any registry modifications. Consequently, no SetValue rule can be derived from it.  