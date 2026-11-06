
.Context:
	Attack pattern context: ['\n    The attack pattern T1070.004-File Deletion is described as:\n    "Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary\'s footprint.\n\nThere are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well.(Citation: Microsoft SDelete July 2016) Examples of built-in [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) functions include <code>del</code> on Windows, <code>rm</code> or <code>unlink</code> on Linux and macOS, and `rm` on ESXi."\n            \n\n            The attack pattern T1070.004 is detected using DET0140 (Behavioral Detection of Malicious File Deletion) which has the following Windows analytics associated:\n     - AN0392 descibed as: "Detects adversary behavior deleting artifacts (e.g., dropped payloads, evidence files) using native or external utilities (e.g., del, erase, SDelete). Detects deletion events correlated with unusual process lineage or timing post-execution." with mutable elements:\n         . TimeWindow: Defines correlation window after suspicious binary execution or login session.\n         . FilePathPattern: Focuses on deletion of temp files, malware staging dirs, or known indicators.\n         . UserContext: Privilege level or impersonated user deleting sensitive files.\n']
	Vulnerability context: Known vulnerabilities:

- CVE-2023-27350: This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, HIGH on integrity, HIGH on availability



.Task:
	Produce a Sysmon monitoring requirements analysis specifically for
	EventID 23: A file was deleted. Additionally to logging the event, the deleted file is also saved in the ArchiveDirectory (which is C:\Sysmon by default). Under normal operating conditions this directory might grow to an unreasonable size - see event ID 26: FileDeleteDetected for similar behavior but without saving the deleted files.



.Reported threat data:
	- Attack patterns: ['T1070.004']
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
	Image: File path of the process that deleted the file
TargetFilename: The path of the deleted file
Hashes: The hashes of the file, types set in the config. This also determines the stored filename
IsExecutable: Boolean statement whether the file is a PE file
Archived: Boolean statement whether the file was stored in the configured archive folder
Every recommendation must be traceable to the provided context.
If a recommendation cannot be justified by the provided context, do not include it.

.Output format (plain text):
	One recommendation per line:
	[LABEL] <what to observe> | Source: <ATT&CK ID, CVE, or IoC key>
	If nothing in the context can be observed through this event type,
	output exactly: NO RECOMMENDATIONS

When omitting any indicator of compromise in [{'sha256': 'ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205', 'filename': 'wiseman.EXE'}, {'sha256': 'fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c', 'filename': 'wininet.dll'}] and any attack pattern in ['T1070.004'], explain why it was not considered in the security analysis.
	
