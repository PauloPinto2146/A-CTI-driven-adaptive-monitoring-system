[IOC] Image = *\wiseman.EXE | Source: filename wiseman.EXE  
[BEHAVIOR] Image = *\rundll32.exe | Source: T1218.011  
[BEHAVIOR] QueryName length ≥ 30 characters (indicative of encoded payload) | Source: T1071.004  
[BEHAVIOR] QueryName domain = pastebin.com or twitter.com (dead‑drop resolver) | Source: T1102.001  

**Why other items were not included**

- **wininet.dll** – The Sysmon 22 event records the Image (path of the process) that performed the DNS query, not the DLLs it has loaded. Since the DLL name cannot be captured directly, it cannot be monitored with this event type.  

- **T1021 (Remote Services)** – The technique describes using legitimate remote‑service protocols (RDP, SSH, etc.). No specific DNS‑related behavior (e.g., unique query patterns or domains) is described in the provided context, so there is nothing to correlate with Event 22.  

- **T1018 (Remote System Discovery)** – Typical discovery commands (net view, ping, tracert) do not generate DNS queries captured by Event 22, and the ATT&CK description does not tie discovery to DNS activity. Hence no viable recommendation can be derived for this event.  

- **Additional IOC “wininet.dll”** – As explained above, DLL usage is not observable in the DNS query event, so it was omitted.  

All remaining recommendations are directly observable via the fields available in Sysmon Event 22 and are justified by the supplied ATT&CK techniques or IoCs.