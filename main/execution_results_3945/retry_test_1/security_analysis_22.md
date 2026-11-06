[IOC] Image == *\wiseman.EXE* | Source: IOC filename wiseman.EXE  
[BEHAVIOR] Image == *\rundll32.exe* | Source: T1218.011 (Rundll32 abuse)  
[BEHAVIOR] Image == *\powershell.exe* | Source: T1071.004 (DNS tunneling)  
[BEHAVIOR] Image == *\python.exe* | Source: T1071.004 (DNS tunneling)  
[BEHAVIOR] Image == *\net.exe* OR Image == *\ping.exe* OR Image == *\tracert.exe* | Source: T1018 (Remote System Discovery)  
[DERIVED] QueryName length > 50 characters (indicative of encoded payloads) | Source: T1071.004 (DNS tunneling – high‑entropy subdomains)  

**Why other items were omitted**

- **wininet.dll** – The DLL is not a process; Event ID 22 records only the process image that issued the DNS query, not the DLLs it loads. Therefore it cannot be directly observed via this event type.  
- **T1021 (Remote Services)** – This technique involves establishing remote sessions (RDP, SSH, etc.) and does not inherently generate DNS queries captured by Event 22, so it is not applicable for monitoring with this event.  
- **T1102.001 (Dead Drop Resolver)** – The dead‑drop resolver pattern uses HTTP/HTTPS to retrieve content from web services, not DNS queries, and thus cannot be detected with Sysmon DNS query events.  