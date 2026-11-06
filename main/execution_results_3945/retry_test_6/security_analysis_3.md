[IOC] Image=*\\wiseman.exe* | Source: IOC (sha256=ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205)  
[IOC] Image=*\\wininet.dll* | Source: IOC (sha256=fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c)  
[BEHAVIOR] Image=*\\rundll32.exe* | Source: T1218.011 (Rundll32 abuse)  
[BEHAVIOR] DestinationPort=53 Protocol=UDP Initiated=True | Source: T1071.004 (DNS tunneling)  
[BEHAVIOR] DestinationPort=3389 Protocol=TCP Initiated=True | Source: T1021 (Remote Services – RDP)  
[BEHAVIOR] DestinationPort=22 Protocol=TCP Initiated=True | Source: T1021 (Remote Services – SSH)  
[BEHAVIOR] DestinationPort=5900 Protocol=TCP Initiated=True | Source: T1021 (Remote Services – VNC)  
[BEHAVIOR] Image=*\\net.exe* | Source: T1018 (Remote System Discovery)  
[BEHAVIOR] Image=*\\ping.exe* | Source: T1018 (Remote System Discovery)  
[BEHAVIOR] Image=*\\tracert.exe* | Source: T1018 (Remote System Discovery)  

**Omitted attack pattern**

[T1102.001] was not included because the provided threat intelligence does not contain any concrete indicators (e.g., specific web service domains, URLs, or IP addresses) associated with a dead‑drop resolver. Without explicit IoCs, Sysmon Event ID 3 cannot be tuned to a meaningful, evidence‑based filter for this technique.