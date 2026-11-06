[IOC] SourceImage=wiseman.EXE, TargetImage=*, GrantedAccess includes PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, CallTrace=* | Source: filename wiseman.EXE  
[BEHAVIOR] SourceImage=*, TargetImage=lsass.exe, GrantedAccess includes PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION, CallTrace=* | Source: T1134  
[BEHAVIOR] SourceImage=*, TargetImage=winlogon.exe, GrantedAccess includes PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, CallTrace=* | Source: T1056.001  

**Omitted indicators / patterns**  
- **wininet.dll**: This IOC is a DLL, not an executable process. Sysmon Event ID 10 records only process‑to‑process access events, so a DLL name cannot be directly monitored with this event type.  
- **T1140 (Deobfuscate/Decode Files or Information)**: The technique involves file or data decoding and does not entail opening one process from another, which is the activity captured by Event ID 10. Therefore it is not relevant for this monitoring scope.