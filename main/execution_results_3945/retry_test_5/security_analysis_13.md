[BEHAVIOR] Monitor SetValue events where **Image** is a service‑management utility (e.g., `sc.exe`, `powershell.exe`, `cmd.exe`) that writes a **DWORD “Start”** value under the key **`HKLM\System\CurrentControlSet\Services\<service name>\Start`** – this indicates creation or modification of a Windows service. | Source: T1543.003  

[BEHAVIOR] Monitor SetValue events where **Image** is a service‑management utility (e.g., `sc.exe`, `powershell.exe`, `cmd.exe`) that writes a **DWORD “Type”** value under the key **`HKLM\System\CurrentControlSet\Services\<service name>\Type`** – modification of service type is a hallmark of malicious service or driver installation. | Source: T1543.003  

[BEHAVIOR] Monitor SetValue events where **Image** is any process (including `reg.exe`, PowerShell, or WMI) that writes a **DWORD “SafeDllSearchMode”** (or disables it) under **`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\SafeDllSearchMode`** – disabling SafeDllSearchMode is a known registry‑based defense‑evasion technique. | Source: T1112  

[BEHAVIOR] Monitor SetValue events where **Image** is a process that writes a **DWORD “Notify”** value under **`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Notify`** (or similar “Notify” keys used for persistence) – such modifications are explicitly mentioned in the T1112 analytic for suspicious persistence‑related registry changes. | Source: T1112  

---

**Why the following were not included**

- **IoC filenames “wiseman.EXE” and “wininet.dll”** – Event ID 13 records *registry value writes* (DWORD/QWORD). Neither filename is tied to a specific DWORD/QWORD registry value in the provided intelligence, and the typical persistence mechanism that references these files (`ImagePath` values) uses REG_SZ strings, which Event 13 does not capture. Therefore they cannot be observed with this event type.

- **T1056.001 (Keylogging)** – The description notes “Registry modifications” for keylogging but does not name any concrete DWORD/QWORD values or keys that are altered. Without a specific registry location, a meaningful SetValue‑focused rule cannot be derived.

- **T1082 (System Information Discovery)** – This technique involves *reading* system information, not modifying registry values. Event 13 only logs writes, so it cannot detect this behavior.

- **T1012 (Query Registry)** – By definition this technique is about *reading* the registry. No write activity is described, so Event 13 is not applicable.

- **T1547.001 (Registry Run Keys / Startup Folder)** – Persistence via Run keys mainly writes **REG_SZ** string values (paths to executables). Since Event 13 captures only DWORD/QWORD writes, those Run‑key modifications are outside its observable scope.

- **Any other registry keys referenced only as strings or as part of read‑only discovery** – They are excluded because Event 13 cannot record them.