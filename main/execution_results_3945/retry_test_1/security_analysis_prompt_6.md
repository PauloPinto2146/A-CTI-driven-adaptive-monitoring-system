
.Context:
	Attack pattern context: ['\n    The attack pattern T1543.003-Windows Service is described as:\n    "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.(Citation: TechNet Services) Windows service configuration information, including the file path to the service\'s executable or recovery programs/commands, is stored in the Windows Registry.\n\nAdversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API. \n\nAdversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: `.sys`) to disk, the payload can be loaded and registered via [Native API](https://attack.mitre.org/techniques/T1106) functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values (i.e. [Modify Registry](https://attack.mitre.org/techniques/T1112)), or by using command-line utilities such as `PnPUtil.exe`.(Citation: Symantec W.32 Stuxnet Dossier)(Citation: Crowdstrike DriveSlayer February 2022)(Citation: Unit42 AcidBox June 2020) Adversaries may leverage these drivers as [Rootkit](https://attack.mitre.org/techniques/T1014)s to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020)\n\nServices may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1569/002).\n\nTo make detection analysis more challenging, malicious services may also incorporate [Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004) (ex: using a service and/or payload name related to a legitimate OS or benign software component). Adversaries may also create ‘hidden’ services (i.e., [Hide Artifacts](https://attack.mitre.org/techniques/T1564)), for example by using the `sc sdset` command to set service permissions via the Service Descriptor Definition Language (SDDL). This may hide a Windows service from the view of standard service enumeration methods such as `Get-Service`, `sc query`, and `services.exe`.(Citation: SANS 1)(Citation: SANS 2)"\n            \n\n            The attack pattern T1543.003 is detected using DET0552 (Detection of Windows Service Creation or Modification) which has the following Windows analytics associated:\n     - AN1527 descibed as: "Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\\System\\CurrentControlSet\\Services`, and service execution under SYSTEM with unsigned or anomalous binary paths. Detects privilege escalation via driver installation or `CreateServiceW` usage. Correlates parent-child lineage, startup behavior, and rare service names." with mutable elements:\n         . ServiceNamePattern: Regex for suspicious or uncommon service names (e.g., `svhostx`, `winhelp`, etc.)\n         . ImagePathFilter: Flag services whose image path resides in uncommon directories (e.g., `C:\\Users\\`, `C:\\Temp\\`)\n         . DriverExtensionList: Watch for `.sys` files loaded by `sc`, Registry, or `ZwLoadDriver` APIs\n         . StartupTypeChangeWindow: Temporal window to correlate Registry `Start` key changes with service creation\n         . UnsignedBinaryAlert: Raise alerts for unsigned binaries registered as services\n']
	Vulnerability context: Known vulnerabilities:

- CVE-2023-27350: This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, HIGH on integrity, HIGH on availability



.Task:
	Produce a Sysmon monitoring requirements analysis specifically for
	EventID 6: The driver loaded events provides information about a driver being loaded on the system. The configured hashes are provided as well as signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading.



.Reported threat data:
	- Attack patterns: ['T1543.003']
	- Indicators of compromise: [{'sha256': 'ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205', 'filename': 'wiseman.EXE'}, {'sha256': 'fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c', 'filename': 'wininet.dll'}]
	- Vulnerabilities: ['CVE-2023-27350']

.Requirements:
	1. Only recommend activity that this event type can record
	2. Avoid monitoring recommendations unrelated to the reported threat
	3. Include all information necessary to observe the reported activity, and nothing else
	4. Do not generate Sysmon configuration XML
	5. The output will be consumed by another LLM that generates the configuration, so be objective

.For each monitoring recommendation, identify its source using exactly one of these labels:

	[IOC]
	Use when the recommendation directly monitors a concrete value explicitly present in the provided threat intelligence, such as a filename, hash, IP address, domain, port, or registry value.
	Only use the exact values provided in the context.

	[BEHAVIOR]
	Use when the recommendation monitors behavior explicitly described by the provided ATT&CK or vulnerability context.
	Do not introduce concrete values that are not present in the provided context.

	[DERIVED]
	Use only when the recommendation is a reasonable monitoring consequence of the provided context but is not explicitly stated by an IoC, ATT&CK analytic, or vulnerability description.
	Do not introduce concrete values for DERIVED recommendations.

Each recommendation must be expressible with these fields:
	ImageLoaded: File path of the driver loaded
Hashes: Hashes captured by Sysmon driver
Signed: Is the driver loaded signed
Signature: Signer name of the driver
SignatureStatus: Status of the signature
Every recommendation must be traceable to the provided context.
If a recommendation cannot be justified by the provided context, do not include it.

.Output format (plain text):
	One recommendation per line:
	[LABEL] <what to observe> | Source: <ATT&CK ID, CVE, or IoC key>
	If nothing in the context can be observed through this event type,
	output exactly: NO RECOMMENDATIONS

When omitting any indicator of compromise in [{'sha256': 'ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205', 'filename': 'wiseman.EXE'}, {'sha256': 'fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c', 'filename': 'wininet.dll'}] and any attack pattern in ['T1543.003'], explain why it was not considered in the security analysis.
	
