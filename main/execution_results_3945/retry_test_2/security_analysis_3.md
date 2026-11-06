[IOC] Image=wiseman.exe | Source: IOC sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  

[BEHAVIOR] Image=rundll32.exe | Source: ATT&CK T1218.011  

[BEHAVIOR] DestinationPort=53 Protocol=UDP Initiated=true Image in {powershell.exe, rundll32.exe, python.exe} | Source: ATT&CK T1071.004  

[BEHAVIOR] DestinationPort=3389 Protocol=TCP Initiated=true | Source: ATT&CK T1021  

[BEHAVIOR] DestinationPort=22 Protocol=TCP Initiated=true | Source: ATT&CK T1021  

[BEHAVIOR] DestinationPort=5900 Protocol=TCP Initiated=true | Source: ATT&CK T1021  

[BEHAVIOR] DestinationPort=445 Protocol=TCP Initiated=true Image in {net.exe, ping.exe, tracert.exe} | Source: ATT&CK T1018  

---

**Explanation of omitted items**

- **wininet.dll (SHA‑256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c)** – Sysmon Event ID 3 records network connections *by process*, not by loaded DLLs. Because a DLL does not appear as the “Image” field, there is no direct observable element for this IOC in this event type.

- **T1102.001 (Dead Drop Resolver)** – The ATT&CK description requires monitoring of HTTP(S) requests to known dead‑drop domains. No specific domains, IPs, or URLs are provided in the supplied intelligence, so no concrete observable can be defined for Event ID 3.

- **CVE‑2023‑27350** – The vulnerability description does not disclose the network service (port, protocol, or host) used by an attacker to exploit PaperCut NG. Without those concrete values, a meaningful Event ID 3 rule cannot be derived while satisfying the “no introduction of values not in context” rule.  

- **Other attack patterns (T1218.011, T1071.004, T1021, T1018)** – Where behavior could be expressed via observable fields (e.g., specific processes or destination ports), recommendations have been included above. Any aspects of those techniques that require monitoring of process arguments, file loads, registry changes, or DNS query content cannot be captured by Event ID 3 and therefore are omitted.