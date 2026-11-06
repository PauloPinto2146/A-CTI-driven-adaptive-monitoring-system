[BEHAVIOR] EventType: CreateKey; Image: *; TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey; Image: *; TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey; Image: *; TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey; Image: *; TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey; Image: *; TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey; Image: *; TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\* | Source: T1219  

**Explanation of omitted IoCs and attack pattern references**  
The provided list of malicious filenames (e.g., h3odp7l2u.exe, inc.exe) are concrete IOCs, but the Sysmon EventID 12 only records registry key create/delete actions. No specific registry keys, values, or paths associated with those files are mentioned in the threat intelligence, so there is nothing concrete to monitor at the registry‑key level for those IoCs. Consequently, they are omitted from the recommendations because EventID 12 cannot directly capture “process‑creates‑registry‑key” events tied to a particular filename without a known target registry location.  

The attack pattern T1219 is represented in the recommendations through the behavior of remote‑access tools establishing persistence via service or autorun registry keys, which is the only aspect of T1219 observable via registry modifications. No additional T1219‑specific details (e.g., exact keys used by a particular RAT) were provided, so the guidance focuses on the generic persistence locations commonly abused by remote access tools.