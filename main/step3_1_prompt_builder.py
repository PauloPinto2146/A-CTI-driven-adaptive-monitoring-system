import json
import os
import sys

from dotenv import load_dotenv
from pathlib import Path
from utils import get_sysmon_event_name


# utils

def format_dict(d):
	return "\n".join(f"{k}: {v}" for k, v in d.items())

def format_examples(examples):
	return "\n\n".join(f"<example>\n{e}\n</example>" for e in examples)

# ======================================================
# ============= Sysmon context extraction ============== 
# ======================================================


SYSMON_CONTEXT_DIR = Path("sysmon_context")

def load_examples(directory, prefix):
    # Files are like: include(...).xml / exclude(...).xml
    return [
        p.read_text(encoding="utf-8").strip()
        for p in sorted(directory.glob(f"{prefix}*.xml"))
    ]

def get_sysmon_event_context(sysmon_event_id):
    with open(SYSMON_CONTEXT_DIR / "sysmon_context.json", encoding="utf-8") as f:
        whole_context = json.load(f)
    event_context = whole_context.get(str(sysmon_event_id), {})
    description = event_context.get("sysmon_event_description", "")
    tags = event_context.get("sysmon_tags", {})
    conditions = whole_context.get("Conditions", {})
    event_dir = SYSMON_CONTEXT_DIR / str(sysmon_event_id)
    include_examples = load_examples(event_dir, "include")

    exclude_examples = load_examples(event_dir, "exclude")
    return description, tags, conditions, include_examples, exclude_examples

# ======================================================
# ============== PROMPT BUILDING FOR LLM =============== 
# ======================================================

# ---------- First prompt building ----------

def llm_context_security_analysis(context_dict, sysmon_event_id, misp_event_id):
	description, tags, _, _, _ = get_sysmon_event_context(sysmon_event_id)
	sysmon_event = get_sysmon_event_name(sysmon_event_id)

	security_analysis_instruction = f"""
.Task:
	Produce a Sysmon monitoring requirements analysis specifically for
	EventID {sysmon_event_id}: {description}\n\n

.Reported threat data:
	- Attack patterns: {context_dict.get("attack_pattern_names")}
	- Indicators of compromise: {context_dict.get("ioc_array")}
	{f"- Vulnerabilities: {context_dict.get('cves')}" if context_dict.get("cves") else ""}

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
	{format_dict(tags)}
Every recommendation must be traceable to the provided context.
If a recommendation cannot be justified by the provided context, do not include it.

.Output format (plain text):
	One recommendation per line:
	[LABEL] <what to observe> | Source: <ATT&CK ID, CVE, or IoC key>
	If nothing in the context can be observed through this event type,
	output exactly: NO RECOMMENDATIONS

When omitting any indicator of compromise in {context_dict.get("ioc_array")} and any attack pattern in {context_dict.get("attack_pattern_names")}, explain why it was not considered in the security analysis.
	"""

	attack_pattern_context = context_dict.get("attack_pattern_context")
	ioc_dict = context_dict.get("ioc_dict")
	vul_context = context_dict.get("vul_context")

	attack_pattern_context_string = ""
	for a in attack_pattern_context:
		attack_pattern_context_string += f"{a}\n" 

	first_prompt =  f"""
.Context:
	Attack pattern context: {attack_pattern_context}
	{f"Vulnerability context: {vul_context}" if vul_context else ""}

{security_analysis_instruction}
"""
	
	with open(f"execution_results_{misp_event_id}/security_analysis_prompt_{sysmon_event_id}.md", "w") as f:
		f.write(first_prompt)
	return first_prompt	


# ---------- Second prompt building ----------

def build_second_prompt(ap_names, iocs, sysmon_event_id, misp_event_id):
	description, tags, conditions, include_examples, exclude_examples = get_sysmon_event_context(sysmon_event_id)
	sysmon_event_name = get_sysmon_event_name(sysmon_event_id)

	second_prompt = f"""
.Context:
	EventID {sysmon_event_id}: {description}

	These are the applicable tags that you can use:
	{format_dict(tags)}

	ONLY use these conditions:
	{format_dict(conditions)}
	Do NOT use any other variation like "end with any" or "image any". That will result in an invalid output.

.Examples
	Examples of rules that exclude benign noise:
	{format_examples(exclude_examples)}

	Examples of rules that include suspicious activity:
	{format_examples(include_examples)}

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon {sysmon_event_name} snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the \"Image\" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: {ap_names}
	- Remember to consider the reported indicators of compromise: {iocs}
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	"""
	with open(f"execution_results_{misp_event_id}/generation_prompt_{sysmon_event_id}.md", "w") as f:
		f.write(second_prompt)
	return second_prompt	


# ---------- Retry prompt building ----------

def build_retry_prompt(sysmon_snippet, sysmon_event_id):
	description, tags, conditions, include_examples, exclude_examples = get_sysmon_event_context(sysmon_event_id)

	sysmon_event_name = get_sysmon_event_name(sysmon_event_id)

	retry_prompt = f"""
.The following Sysmon configuration was REJECTED by Sysmon:
{sysmon_snippet}


.Recall the valid Sysmon tags:
	{format_dict(tags)}

.Recall the valid Sysmon conditions:
	{format_dict(conditions)}
	Do NOT use any other variation like "end with any" or "image any". That will result in an invalid output.

.Examples
	Examples of rules that exclude benign noise:
	{format_examples(exclude_examples)}

	Examples of rules that include suspicious activity:
	{format_examples(include_examples)}

.Task:
	Fix the configuration so that Sysmon accepts it.


.Rules:
	- Keep the structure exactly as in the examples: a <RuleGroup name="" groupRelation="or"> containing the event element (e.g. <ProcessCreate onmatch="include">) and then the rules
	- Preserve every rule and every IOC value. Do not delete, add or merge rules
	- If a condition is invalid, replace it with the closest valid one that keeps the same meaning
	- Only use the valid tags and conditions mentioned earlier
	- Escape special characters in values (&amp; &lt; &gt;)
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

Output ONLY the corrected XML. No markdown fences, no explanations.
"""

	
	return retry_prompt	