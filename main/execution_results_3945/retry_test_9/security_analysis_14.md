[BEHAVIOR] Monitor RenameKey events where TargetObject matches **HKLM\System\CurrentControlSet\Services\*** (service registry keys) and NewName is any | Source: T1543.003  
[BEHAVIOR] Monitor RenameKey events where TargetObject matches **HKLM\Software\Microsoft\Windows\CurrentVersion\Run*** or **HKCU\Software\Microsoft\Windows\CurrentVersion\Run*** (Run/RunOnce keys) and NewName is any | Source: T1547.001  
[BEHAVIOR] Monitor RenameKey events where TargetObject matches **HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute** and NewName is any | Source: T1547.001  
[DERIVED] Monitor RenameKey events where NewName contains a leading null character or other anomalous Unicode characters (e.g., “\0” prefix) that can be used to hide keys | Source: T1112  

**Explanation of omitted items**

- **T1056.001 (Keylogging)** – EventID 14 records registry rename operations; keylogging is achieved via API hooks, driver code, or raw buffer reads, none of which involve renaming registry keys or values.  
- **T1082 (System Information Discovery)** – System discovery is performed through command execution or API queries, not through renaming registry objects, so it cannot be captured by this event type.  
- **T1012 (Query Registry)** – Querying the registry reads data; it does not modify key names, thus no RenameKey events are generated.  
- **IOC filenames “wiseman.EXE” and “wininet.dll”** – These values appear as *data* within registry values (e.g., the path to an executable) rather than as the *name* of a registry key. EventID 14 only logs the new *key* name, not the value contents, so these IoCs cannot be observed here.  
- **CVE‑2023‑27350** – The vulnerability description concerns authentication bypass and arbitrary code execution via a class in PaperCut NG; it does not mention any specific registry key rename activity, so no relevant RenameKey monitoring can be derived.