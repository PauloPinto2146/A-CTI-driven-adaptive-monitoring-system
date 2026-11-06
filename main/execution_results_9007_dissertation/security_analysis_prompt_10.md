
.Context:
	Attack pattern context: ['\n    The attack pattern T1003-OS Credential Dumping is described as:\n    "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.\n\nSeveral of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.\n"\n            \n\n            The attack pattern T1003 is detected using DET0234 (Credential Dumping via Sensitive Memory and Registry Access Correlation) which has the following Windows analytics associated:\n     - AN0648 descibed as: "Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction." with mutable elements:\n         . AccessMask: Set to detect full access rights (0x1F0FFF) or modify based on tool behavior.\n         . TimeWindow: Define how soon access to LSASS is followed by suspicious file or registry activity.\n         . ParentProcessFilter: Allowlist known security tools or system processes accessing LSASS.\n', '\n    The attack pattern T1027.002-Software Packing is described as:\n    "Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. Virtual machine software protection translates an executable\'s original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018) \n\nUtilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.(Citation: Awesome Executable Packing)  "\n            \n\n            The attack pattern T1027.002 is detected using DET0023 (Obfuscated Binary Unpacking Detection via Behavioral Patterns) which has the following Windows analytics associated:\n     - AN0066 descibed as: "Detection of unpacking behavior through abnormal memory allocation, followed by executable code injection and execution from non-image sections." with mutable elements:\n         . ParentProcessName: To scope detections to suspicious parent-child process relationships typical of loaders or droppers.\n         . AllocationSizeThreshold: To tune for unusually large virtual memory allocations that might indicate unpacked payloads.\n']
	Vulnerability context: Known vulnerabilities:

- CVE-2023-3519: Unauthenticated remote code execution
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, HIGH on integrity, HIGH on availability

- CVE-2023-48788: A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiClientEMS version 7.2.0 through 7.2.2, FortiClientEMS 7.0.1 through 7.0.10 allows attacker to execute unauthorized code or commands via specially crafted packets.
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, HIGH on integrity, HIGH on availability

- CVE-2024-57727: SimpleHelp remote support software v5.5.7 and before is vulnerable to multiple path traversal vulnerabilities that enable unauthenticated remote attackers to download arbitrary files from the SimpleHelp host via crafted HTTP requests. These files include server configuration files containing various secrets and hashed user passwords.
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, NONE on integrity, NONE on availability

- CVE-2025-5777: Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, NONE on integrity, NONE on availability



.Task:
	Produce a Sysmon monitoring requirements analysis specifically for
	EventID 10: The process accessed event reports when a process opens another process, an operation that’s often followed by information queries or reading and writing the address space of the target process. This enables detection of hacking tools that read the memory contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash attacks. Enabling it can generate significant amounts of logging if there are diagnostic utilities active that repeatedly open processes to query their state, so it generally should only be done so with filters that remove expected accesses.



.Reported threat data:
	- Attack patterns: ['T1003', 'T1027.002']
	- Indicators of compromise: [{'filename': 'x86_64-unknown-linux-esxi.elf'}, {'filename': 'h3odp7l2u.exe'}, {'filename': 'hi9lezv.exe'}, {'filename': '072wiof7.exe'}, {'filename': 'k0d649u.exe'}, {'filename': '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat'}, {'filename': '2qfguc.exe'}, {'filename': '7hhel.exe'}, {'filename': '3ctjhm3.exe'}, {'filename': '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat'}, {'filename': 'bjiw49.exe'}, {'filename': '7l73h.exe'}, {'filename': '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat'}, {'filename': '0m6m882x2.exe'}, {'filename': 'inc.exe'}, {'filename': '61pd6n3t.exe'}, {'filename': 'mk1yd.exe'}, {'filename': 'a3mnw9.exe'}, {'filename': 'win.bin'}, {'filename': 'vw06lg0y.exe'}, {'filename': 'qgp2s6z.exe'}, {'filename': 'tt24n8xsl.exe'}]
	- Vulnerabilities: ['CVE-2023-3519', 'CVE-2023-48788', 'CVE-2024-57727', 'CVE-2025-5777']

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
	SourceImage: File path of the source process that created a thread in another process
TargetImage: File path of the executable of the target process
GrantedAccess: The access flags (bitmask) associated with the process rights requested for the target process
CallTrace: Stack trace of where open process is called. Included is the DLL and the relative virtual address of the functions in the call stack right before the open process call
Every recommendation must be traceable to the provided context.
If a recommendation cannot be justified by the provided context, do not include it.

.Output format (plain text):
	One recommendation per line:
	[LABEL] <what to observe> | Source: <ATT&CK ID, CVE, or IoC key>
	If nothing in the context can be observed through this event type,
	output exactly: NO RECOMMENDATIONS
	
