[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*\Start, Details: DWORD value change indicating service start‑type modification (e.g., automatic, manual, disabled) | Source: T1543.003  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*\Type, Details: DWORD value change that defines the service type (e.g., own process, share process) | Source: T1543.003  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*\ErrorControl, Details: DWORD value change controlling error handling for the service | Source: T1543.003  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*, Details: DWORD (or QWORD) value creation/modification in a Run key indicating atypical persistence registration | Source: T1547.001  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*, Details: DWORD (or QWORD) value creation/modification in a user‑specific Run key indicating persistence registration | Source: T1547.001  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*, Details: DWORD (or QWORD) value change under policy‑run keys used for forced execution at logon | Source: T1547.001  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode, Details: DWORD value toggle that disables SafeDllSearchMode, a known defense‑evasion setting | Source: T1112  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA, Details: DWORD value change that enables/disables UAC, often abused for privilege escalation | Source: T1112  

[BEHAVIOR] EventType: SetValue, Image: * (any process), TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute, Details: Modification of the multi‑string value (recorded as a DWORD/QWORD change when applicable) that can inject malicious commands to run at boot | Source: T1547.001  

---

**Why certain items were not included**

- **wiseman.EXE** and **wininet.dll** – These are file names (IOCs). EventID 13 records registry *value* modifications; it does not capture execution of a specific binary or loading of a DLL, therefore there is no concrete registry value tied to these filenames in the supplied intelligence that could be observed with this event type. Consequently no [IOC] recommendation was made.

- **T1056.001 (Keylogging)** – The described techniques focus on hooking APIs, installing drivers, or reading hardware buffers. The ATT&CK analytics for this technique (AN0243) emphasize monitoring API calls and driver modifications, not registry value writes. No registry‑specific persistence or configuration modifications were explicitly linked to keylogging in the provided context, so it cannot be reliably observed via SetValue events.

- **T1082 (System Information Discovery)** – This technique primarily involves reading system information (e.g., via `systeminfo`, `systemsetup`, or API calls). The associated analytic (AN1452) looks for process execution followed by read‑only access to OS configuration APIs or registry reads. Since EventID 13 only logs *writes*, there is no relevant observable activity for this technique.

- **T1012 (Query Registry)** – By definition, this technique concerns reading registry data, not modifying it. The detection analytic (AN0589) targets registry read access, which is not captured by EventID 13. Hence no recommendation was generated.

- **CVE‑2023‑27350 (PaperCut NG auth bypass)** – The vulnerability description details an authentication bypass and arbitrary code execution but does **not** specify any registry modifications as part of the exploit. Without a documented registry write (e.g., creating a service or persistence key), the event type cannot be leveraged to detect this CVE, so no recommendation is provided.