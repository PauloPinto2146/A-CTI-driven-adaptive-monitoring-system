[IOC] SourceImage=*\\wiseman.EXE, TargetImage=*, GrantedAccess=*, CallTrace=* | Source: IoC – filename wiseman.EXE  

[DERIVED] SourceImage=*, TargetImage=*\\lsass.exe, GrantedAccess=0x0010|0x0400|0x001F0FFF (PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, PROCESS_ALL_ACCESS), CallTrace=* | Source: ATT&CK T1134 (Access Token Manipulation – token‑stealing often requires opening LSASS to duplicate its token)  

[DERIVED] SourceImage=*, TargetImage=*\\winlogon.exe, GrantedAccess=0x0010|0x0400 (PROCESS_VM_READ, PROCESS_QUERY_INFORMATION), CallTrace=* | Source: ATT&CK T1056.001 (Keylogging – credential‑capture tools frequently open winlogon.exe to hook or read its memory)  


**Omitted indicators / patterns**

- **wininet.dll** – Sysmon Event ID 10 logs process‑to‑process access events; it does not record module‑load or DLL‑import activity, so a DLL filename cannot be directly observed with this event type.  

- **Attack pattern T1056.001 (Keylogging)** – The primary techniques for keylogging involve API hooking, driver or registry modifications, not the act of opening another process. Consequently, there are no specific source/target process pairs mandated by the ATT&CK description that can be captured by Event ID 10.  

- **Attack pattern T1140 (Deobfuscate/Decode Files)** – This technique concerns the use of utilities such as certutil, powershell, or copy to decode payloads, which generates command‑line activity rather than process‑access events. Hence it cannot be reliably monitored with Event ID 10.  



NO RECOMMENDATIONS for any other IoC or ATT&CK technique, because they cannot be observed through Sysmon Event ID 10.