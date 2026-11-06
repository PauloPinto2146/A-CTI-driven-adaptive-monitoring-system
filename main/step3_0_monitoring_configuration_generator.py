import ollama
import numpy as np
import json
import os
import sys

from dotenv import load_dotenv
from ollama import chat
from ollama import Client

from utils import (
    list_installed_programs,
    list_services,
    list_running_processes,
    get_ips_information,
)

from step3_1_prompt_builder import (
    llm_context_security_analysis,
    build_second_prompt,
    build_retry_prompt
)

from step3_2_syntax_verifier import (
	verify
)

# ============================================================================================================================================

def get_ioc_values(ioc_array):
	iocs_values = []
	for ioc_set in ioc_array:
		for ioc_key, ioc_value in ioc_set.items():
			iocs_values.append(ioc_value)
	return iocs_values

# ============================================================================================================================================

def get_security_analysis(model, context_dict, sysmon_event_id, misp_event_id):
	load_dotenv()
	first_prompt = llm_context_security_analysis(context_dict, sysmon_event_id, misp_event_id)

	# Connects to local Ollama (no need for API Key)
	host = os.getenv("OLLAMA_HOST") #, "http://localhost:11434")
	api_key = os.getenv("OLLAMA_API_KEY")

	headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
	client = Client(host=host, headers=headers)

	try:
		messages = [{'role': 'user', 'content': first_prompt}]
		response = client.chat(model=model, messages=messages)

		security_analysis = response['message']['content']
		with open(f"execution_results_{misp_event_id}/security_analysis_{sysmon_event_id}.md", "w") as f:
			f.write(security_analysis)

	except Exception as e:
		print(f"Error while trying to call model '{model}' in first prompt: {e}")
		return

	return messages, security_analysis, client

# ============================================================================================================================================

def get_sysmon_config(model, client, messages, security_analysis, ap_names, iocs, sysmon_event_id, misp_event_id):
	# SECOND PROMPT
	second_prompt = build_second_prompt(ap_names, iocs, sysmon_event_id, misp_event_id)
	messages2 = messages + [{'role':'assistant', 'content': security_analysis}, {'role':'user','content': second_prompt}]

	try:
		response2 = client.chat(model, messages=messages2)
		sysmon_snippet = response2['message']['content'].replace("```xml","").replace("```","")

		with open(f"execution_results_{misp_event_id}/sysmon_snippet_{sysmon_event_id}.md", "w") as f:
			f.write(sysmon_snippet)

	except Exception as e:
		print(f"Error while trying to call model '{model}' in second prompt: {e}")
		return
	return messages2, sysmon_snippet, client			
	
# =================================================================================================================================================================================================================================

def retry_invalid_config(model, sysmon_snippet, sysmon_event_id, misp_event_id):

	load_dotenv()

	# Connects to local Ollama (no need for API Key)
	host = os.getenv("OLLAMA_HOST") #, "http://localhost:11434")
	api_key = os.getenv("OLLAMA_API_KEY")

	headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
	client = Client(host=host, headers=headers)

	retry_prompt = build_retry_prompt(sysmon_snippet, sysmon_event_id)

	try:
		messages = [{'role': 'user', 'content': retry_prompt}]
		response = client.chat(model, messages=messages)
		sysmon_retry_res = response['message']['content']

		with open(f"execution_results_{misp_event_id}/retry_prompt_{sysmon_event_id}.md", "w") as f:
			f.write(retry_prompt)
	except Exception as e:
		print(f"Error while trying to call model '{model}' in second prompt: {e}")
		return
	return sysmon_retry_res		

# =================================================================================================================================================================================================================================

def llm_call(context_dict, sysmon_event_id, misp_event_id):

	model = "gpt-oss:120b-cloud"

	print("Building security analysis...")
	messages, security_analysis, client = get_security_analysis(model, context_dict, sysmon_event_id, misp_event_id)
	print("Building sysmon config...")
	messages2, sysmon_res, client = get_sysmon_config(model, client, messages, security_analysis, context_dict.get("attack_pattern_names"), get_ioc_values(context_dict.get("ioc_array")), sysmon_event_id, misp_event_id)

	return security_analysis, sysmon_res

# =================================================================================================================================================================================================================================

def llm_call_retry(sysmon_snippet, sysmon_event_id, misp_event_id):

	model = "gpt-oss:120b-cloud"

	print(f"Asking LLM to retry invalid sysmon snippet id {sysmon_event_id} ...")
	return retry_invalid_config(model, sysmon_snippet, sysmon_event_id, misp_event_id)

# =================================================================================================================================================================================================================================

def produce_sysmon_snippets(context_dict, misp_event_id):
	sysmon_snippets = []

	context_dict_except_hash_algorithms = dict(list(context_dict.items())[:-1])

	i = 0
	sysmon_snippets_file = f"execution_results_{misp_event_id}/sysmon_snippets_{misp_event_id}.json"

	if not os.path.exists(sysmon_snippets_file):
		for sysmon_event_id, context_value in context_dict_except_hash_algorithms.items():
			
			# Events 4 and 16 are not filterable in the sysmon configuration file (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
			if int(sysmon_event_id) != 4 and int(sysmon_event_id) != 16:
				i += 1
				print(f"Calling the LLM for sysmon event ID {sysmon_event_id} ({i}/{len(context_dict)})")
				security_analysis, sysmon_snippet = llm_call(context_value, sysmon_event_id, misp_event_id)
				
				# Check validity and retry if needed:
				fail_count = 0
				check_flag = False
				retried = False
				while fail_count < 5 and not check_flag:
					valid_bool = verify(sysmon_snippet, sysmon_event_id)
					if not valid_bool:
						fail_count += 1
						with open(f"execution_results_{misp_event_id}/failed_attempt{fail_count}_{misp_event_id}_sysmonID{sysmon_event_id}.xml", "w") as f:
							f.write(sysmon_snippet)
						sysmon_snippet = llm_call_retry(sysmon_snippet, sysmon_event_id, misp_event_id)
						retried = True
					else:
						check_flag = True
						if retried:
							with open(f"execution_results_{misp_event_id}/successful_retry_sysmonID{sysmon_event_id}.xml", "w") as f:
								f.write(sysmon_snippet)
						sysmon_snippets.append({
								sysmon_event_id : {
									"security_analysis": security_analysis,
									"sysmon_snippet": sysmon_snippet
								}
							}
						)
			else:
				i += 1
				print(f"Skipping sysmon ID {sysmon_event_id} since it is not filterable in the configuration file ({i}/{len(context_dict)})")
		with open(sysmon_snippets_file, "w") as f:
			json.dump(sysmon_snippets, f, indent = 4)
	else:
		with open(sysmon_snippets_file, "r") as f: 
			sysmon_snippets = json.load(f)
	return sysmon_snippets

# =================================================================================================================================================================================================================================
