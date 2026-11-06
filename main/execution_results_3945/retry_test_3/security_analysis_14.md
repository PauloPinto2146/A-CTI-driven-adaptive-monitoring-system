[BEHAVIOR] EventType: RenameKey; Image: any executable; TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*; NewName: * | Source: T1547.001 – Registry Run Keys / Startup Folder  

[BEHAVIOR] EventType: RenameKey; Image: any executable; TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*; NewName: * | Source: T1547.001 – Registry Run Keys / Startup Folder  

[BEHAVIOR] EventType: RenameKey; Image: any executable; TargetObject: HKLM\System\CurrentControlSet\Services\*; NewName: * | Source: T1112 – Modify Registry  

[BEHAVIOR] EventType: RenameKey; Image: any executable; TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute; NewName: * | Source: T1112 – Modify Registry  

**Explanation of omitted items**

- **wiseman.EXE** and **wininet.dll** – These IoCs are file names. Sysmon Event ID 14 only records registry‑key/value rename operations; it does not capture file creation, loading, or execution. Therefore there is no direct observable element for these filenames in a RenameKey event, so they are excluded.

- **T1056.001 (Keylogging)** – This technique concerns interception of keystrokes and does not involve registry renames. No rename‑related activity is described, so it is not applicable to Event 14.

- **T1543.003 (Windows Service)** – While services are often created or modified via the registry, the technique description focuses on service creation, binary path changes, and driver loading. It does not mention renaming service‑related registry keys, so no specific rename monitoring can be derived.

- **T1082 (System Information Discovery)** – This technique is about querying system information (e.g., via `systeminfo`). It does not include registry key renaming, so it is not relevant to Event 14.

- **T1012 (Query Registry)** – This technique involves reading registry values, not renaming them. Consequently, it provides no basis for a RenameKey monitoring rule.