[IOC] Image = *wiseman.exe* | Source: sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  
[BEHAVIOR] Image = *rundll32.exe* | Source: T1218.011  
[BEHAVIOR] Protocol = UDP AND DestinationPort = 53 | Source: T1071.004  
[BEHAVIOR] DestinationPort = 3389 | Source: T1021  
[BEHAVIOR] DestinationPort = 22 | Source: T1021  
[BEHAVIOR] Image = net.exe AND DestinationPort = 445 | Source: T1018  

**Omitted indicators / attack patterns and rationale**  
- **wininet.dll (SHA256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c)** – Sysmon Event ID 3 records the *process image* that initiates a network connection; a DLL such as *wininet.dll* would appear as a loaded module, not as the image field, so it cannot be directly observed via this event type.  
- **T1102.001 (Dead Drop Resolver)** – The threat description does not provide concrete domains, IP addresses, or ports associated with the dead‑drop service. Without explicit indicators, a Sysmon network‑connection rule would require guessing values, which falls outside the “observable through this event type” constraint. Hence no recommendation is made for this technique.