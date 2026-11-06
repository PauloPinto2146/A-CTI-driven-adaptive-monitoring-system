[IOC] Image = *wiseman.EXE* performing DNS queries | Source: IOC filename wiseman.EXE  
[BEHAVIOR] Image = *rundll32.exe* performing DNS queries (potential Rundll32 abuse) | Source: T1218.011  
[BEHAVIOR] Image = *powershell.exe* or *python.exe* performing DNS queries (potential DNS tunneling) | Source: T1071.004  
[BEHAVIOR] Image = *net.exe* or *ping.exe* performing DNS queries (possible remote system discovery) | Source: T1018  
[BEHAVIOR] QueryName having an unusually long sub‑domain (indicative of encoded payloads) | Source: T1071.004  

**Why some items were not included**

- **wininet.dll** – Sysmon Event ID 22 only records the executable image that initiates the DNS request. It does not capture DLL load information, so a DNS query cannot be directly linked to the presence of *wininet.dll*; therefore no recommendation can be made for this IoC using this event type.  

- **CVE‑2023‑27350** – The vulnerability involves unauthenticated remote code execution in PaperCut NG via improper access control. It does not involve DNS resolution as part of the exploit, and Event ID 22 cannot surface authentication‑bypass activity. Consequently, no DNS‑specific monitoring requirement can be derived from this CVE.  

- **T1021 (Remote Services)** – While remote service usage may generate DNS lookups for host name resolution, the ATT&CK description does not specify DNS‑based behavior, and no concrete DNS‑related indicators are provided. Thus, no focused recommendation for Event ID 22 can be justified.  

- **T1102.001 (Dead Drop Resolver)** – This technique uses web services (HTTP/HTTPS) to retrieve C2 information and does not mandate DNS queries, so Event ID 22 does not capture relevant activity for this pattern.  

If none of the above applied, the output would be “NO RECOMMENDATIONS”.