[IOC] Monitor SetValue events where Image ends with “wiseman.EXE” (any registry value written by this process) | Source: IOC filename wiseman.EXE  
[IOC] Monitor SetValue events where Image ends with “wininet.dll” (any registry value written by this process) | Source: IOC filename wininet.dll  
[BEHAVIOR] Monitor SetValue events targeting known Run/RunOnce keys (e.g., HKLM\Software\Microsoft\Windows\CurrentVersion\Run, HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, HKCU\Software\Microsoft\Windows\CurrentVersion\Run*, HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce) | Source: T1547.001  
[BEHAVIOR] Monitor SetValue events under the service configuration hive “HKLM\System\CurrentControlSet\Services\*” (e.g., ImagePath, Description, Start) | Source: T1543.003  
[BEHAVIOR] Monitor SetValue events modifying critical auto‑run/privilege‑escalation keys such as HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit, HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute | Source: T1112  
[DERIVED] Monitor SetValue events under “HKLM\System\CurrentControlSet\Services\*” that occur after exploitation of CVE‑2023‑27350, as attackers may install a malicious service for persistence or privilege escalation | Source: CVE-2023-27350  

**Why certain items were omitted**  
- **T1056.001 (Keylogging)**: This technique focuses on capturing keystrokes and does not involve writing registry values, so it cannot be observed with Sysmon EventID 13.  
- **T1082 (System Information Discovery)**: This technique gathers system details via read‑only queries; no registry modifications are performed, thus it is not visible to SetValue events.  
- **T1012 (Query Registry)**: Similar to T1082, this technique entails reading registry data, not modifying it, and therefore cannot be captured by EventID 13.  

All recommendations are limited to registry value modifications that Sysmon can record and are directly tied to the provided threat intelligence.