[BEHAVIOR] Monitor any process that opens **C:\Windows\System32\lsass.exe** with **GrantedAccess** containing `PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION|PROCESS_DUP_HANDLE`; ensure the **CallTrace** shows a call such as `advapi32.dll!OpenProcess` or `ntdll.dll!NtOpenProcess` → Source: T1134  

[BEHAVIOR] Monitor processes that open **C:\Windows\System32\winlogon.exe** *or* **C:\Windows\System32\osk.exe** with **GrantedAccess** including `PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_CREATE_THREAD`; the **CallTrace** should contain `user32.dll!SetWindowsHookEx` or similar hooking APIs → Source: T1056.001  

[IOC] Monitor when the executable **wiseman.EXE** (SourceImage) opens any target process with **GrantedAccess** set to a high‑privilege mask (e.g., `PROCESS_ALL_ACCESS`); capture the **CallTrace** for the OpenProcess call → Source: wiseman.EXE  

*Omitted indicators:*  
- **wininet.dll** is a DLL module, not a process; Sysmon EventID 10 records only process‑to‑process accesses, so it cannot be observed with this event.  
- **T1140 (Deobfuscate/Decode Files or Information)** describes file‑or‑command‑based decoding activity, which does not involve opening one process from another, and therefore cannot be captured by EventID 10.