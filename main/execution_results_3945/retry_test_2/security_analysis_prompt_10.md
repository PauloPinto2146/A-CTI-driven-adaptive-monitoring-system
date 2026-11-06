
.Context:
	Attack pattern context: ['\n    The attack pattern T1056.001-Keylogging is described as:\n    "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured. In order to increase the likelihood of capturing credentials quickly, an adversary may also perform actions such as clearing browser cookies to force users to reauthenticate to systems.(Citation: Talos Kimsuky Nov 2021)\n\nKeylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:\n\n* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.\n* Reading raw keystroke data from the hardware buffer.\n* Windows Registry modifications.\n* Custom drivers.\n* [Modify System Image](https://attack.mitre.org/techniques/T1601) may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks) "\n            \n\n            The attack pattern T1056.001 is detected using DET0089 (Behavioral Detection of Keylogging Activity Across Platforms) which has the following Windows analytics associated:\n     - AN0243 descibed as: "Monitors suspicious usage of Windows API calls like SetWindowsHookEx, GetKeyState, or polling functions within non-UI service processes, combined with Registry or driver modifications." with mutable elements:\n         . TargetImage: Scope to sensitive GUI/session processes like winlogon.exe or osk.exe\n         . AccessMask: Can be tuned to 0x1fffff for full-access injection detection\n         . TimeWindow: Tunable for sustained polling or multiple registry edits in short succession\n', '\n    The attack pattern T1140-Deobfuscate/Decode Files or Information is described as:\n    "Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.\n\nOne such example is the use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file.(Citation: Malwarebytes Targeted Attack against Saudi Arabia) Another example is using the Windows <code>copy /b</code> or <code>type</code> command to reassemble binary fragments into a malicious payload.(Citation: Carbon Black Obfuscation Sept 2016)(Citation: Sentinel One Tainted Love 2023)\n\nSometimes a user\'s action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary.(Citation: Volexity PowerDuke November 2016)"\n            \n\n            The attack pattern T1140 is detected using DET0275 (Detect Adversary Deobfuscation or Decoding of Files and Payloads) which has the following Windows analytics associated:\n     - AN0767 descibed as: "An adversary leverages built-in tools such as certutil.exe, powershell.exe, or copy.exe to decode, reassemble, or extract hidden malicious content from obfuscated containers or encoded formats. The decoding utility often spawns shortly after file staging or download and may be chained with script interpreters or further payload execution." with mutable elements:\n         . ToolName: May vary across environments (e.g., certutil, powershell, copy, expand, 7zip)\n         . FileExtensionFilter: Targets may use .txt, .cer, .enc, .b64, .zip, etc. to disguise payloads\n         . CommandLineRegex: Command syntax varies between base64 decoding, copy /b, and expand switches\n         . TimeWindow: Deobfuscation typically follows staging/download within a short timeframe\n', '\n    The attack pattern T1134-Access Token Manipulation is described as:\n    "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.\n\nAn adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001)) or used to spawn a new process (i.e. [Create Process with Token](https://attack.mitre.org/techniques/T1134/002)). An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)\n\nAny standard user can use the <code>runas</code> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens."\n            \n\n            The attack pattern T1134 is detected using DET0283 (Behavior-chain detection for T1134 Access Token Manipulation on Windows) which has the following Windows analytics associated:\n     - AN0786 descibed as: "Detection of suspicious token manipulation chains: use of token-related APIs (e.g., LogonUser, DuplicateTokenEx) or commands (runas) → spawning of a new process under a different security context (e.g., SYSTEM) → mismatched parent-child process lineage or anomalies in Event Tracing for Windows (ETW) token/PPID data → abnormal lateral or privilege escalation activity." with mutable elements:\n         . TimeWindow: Correlation time between suspicious API usage, runas, and process creation (e.g., 5–10m).\n         . AllowedServiceAccounts: Whitelist of service accounts permitted to spawn SYSTEM-level processes.\n         . KnownAdminTools: Legitimate administrative utilities that trigger token changes.\n         . ParentProcessAnomalyThreshold: Deviation threshold for PPID mismatches detected via ETW.\n']
	Vulnerability context: Known vulnerabilities:

- CVE-2023-27350: This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, HIGH on integrity, HIGH on availability



.Task:
	Produce a Sysmon monitoring requirements analysis specifically for
	EventID 10: The process accessed event reports when a process opens another process, an operation that’s often followed by information queries or reading and writing the address space of the target process. This enables detection of hacking tools that read the memory contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash attacks. Enabling it can generate significant amounts of logging if there are diagnostic utilities active that repeatedly open processes to query their state, so it generally should only be done so with filters that remove expected accesses.



.Reported threat data:
	- Attack patterns: ['T1056.001', 'T1140', 'T1134']
	- Indicators of compromise: [{'filename': 'wiseman.EXE'}, {'filename': 'wininet.dll'}]
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

When omitting any indicator of compromise in [{'filename': 'wiseman.EXE'}, {'filename': 'wininet.dll'}] and any attack pattern in ['T1056.001', 'T1140', 'T1134'], explain why it was not considered in the security analysis.
	
