[IOC] DNS queries where Image = wiseman.exe | Source: filename ‘wiseman.EXE’  
[BEHAVIOR] DNS queries where Image = rundll32.exe (Rundll32 abuse) | Source: T1218.011  
[BEHAVIOR] DNS queries initiated by non‑browser, non‑system processes (e.g., powershell.exe, python.exe, rundll32.exe) | Source: T1071.004  
[BEHAVIOR] DNS queries with QueryName length > 50 characters (possible base64/encoded payload) | Source: T1071.004  
[BEHAVIOR] DNS query rate > N queries per 30 seconds per Image (high‑frequency tunneling) | Source: T1071.004  
[BEHAVIOR] DNS queries with non‑zero QueryStatus (failed or error responses) from suspicious processes (e.g., rundll32.exe, wiseman.exe) | Source: T1071.004  

**Explanation of omitted items**  
- *wininet.dll*: The IoC is a DLL name; Sysmon Event ID 22 records only the querying process image, not the DLLs it has loaded, so this indicator cannot be directly observed via this event.  
- *T1021 (Remote Services)* and *T1018 (Remote System Discovery)*: Their descriptions focus on lateral movement and host enumeration using protocols such as RDP, WMI, Ping, etc. While these activities may cause DNS lookups, the ATT&CK narratives do not explicitly tie them to malicious DNS query characteristics, and no specific DNS‑related behaviors are provided to monitor with Event ID 22.  
- *T1102.001 (Dead Drop Resolver)*: This technique involves retrieving data from legitimate Web services and does not prescribe DNS usage; therefore there is no concrete DNS‑query behavior to capture with Event ID 22.  
- Any other concrete indicators (e.g., hash values, IP addresses, domains) were not supplied in the threat data, so no additional IOC‑based recommendations could be generated.