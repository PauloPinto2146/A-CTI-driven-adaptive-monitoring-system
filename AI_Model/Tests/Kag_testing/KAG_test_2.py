import ollama
import numpy as np
import json
import os
import sys

from ollama import chat
from ollama import Client
from AI_utils import list_network_exposure, listRegistryNetwork, print_time_it_took, mark_time

from context_creator import create_attack_pattern_context, get_attack_patterns_from_MISP_event, create_network_ioc_context, create_vulnerability_context

def get_attack_pattern_context_analysis(misp_event_id, model = "gemma4:31b-cloud"):
	
	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)


	context_array = []
	print("Producing context...")
	context_array = create_attack_pattern_context(attack_patterns_from_event)

	print(f"	Building query...")
	query = f"""
Tell for this attack patterns: {attack_pattern_names_from_event}
Which information would you consider for the NetworkConnect portion of a sysmon configuration file?
	"""

	# -----------------------------
	# BUILD CONTEXT
	# -----------------------------

	print(f"	Building context...")
	context = "\n".join(context_array)

	# -----------------------------
	# FINAL PROMPT
	# -----------------------------

	prompt = f"""
Use the following context:
{context}

Question:
{query}
	"""

	messages = [{'role': 'user','content': prompt}]

	init_time = mark_time()
	print("=== Prompt sent ===")
	print(prompt)
	try:

		client = Client(
			host="https://ollama.com",
			headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
		)
		response = client.chat(model, messages=messages)
		print("\n=== AI RESPONSE ===")
		print(response['message']['content'])
		ai_response = response['message']['content']
	except Exception as e:
		print(f"Error while trying to call model '{model}': {e}")
		return

	final_time = mark_time()

	print_time_it_took(init_time, final_time)

#====================================================================================

def get_complete_context_analysis(misp_event_id, model = "gemma4:31b-cloud"):

	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	vul_context, cves = create_vulnerability_context(misp_event_id)

	context_array = []
	print("Producing context...")
	context_array.extend(create_attack_pattern_context(attack_patterns_from_event))
	context_array.append(ioc_context)
	context_array.append(vul_context)

	print(f"	Building query...")
	query = f"""
Tell for this attack patterns: {attack_pattern_names_from_event}
For these indicators of compromise: {ioc_dict}
And these vulnerabilities: {cves}
Which information would you consider for the NetworkConnect portion of a sysmon configuration file?
	"""

	# -----------------------------
	# BUILD CONTEXT
	# -----------------------------

	print(f"	Building context...")
	context = "\n".join(context_array)

	# -----------------------------
	# FINAL PROMPT
	# -----------------------------

	prompt = f"""
Use the following context:
{context}

Question:
{query}
	"""

	messages = [{'role': 'user','content': prompt}]

	init_time = mark_time()
	print("=== Prompt sent ===")
	print(prompt)
	try:

		client = Client(
			host="https://ollama.com",
			headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
		)
		response = client.chat(model, messages=messages)
		print("\n=== AI RESPONSE ===")
		print(response['message']['content'])
		ai_response = response['message']['content']
	except Exception as e:
		print(f"Error while trying to call model '{model}': {e}")
		return

	final_time = mark_time()

	print_time_it_took(init_time, final_time)

#====================================================================================

def context_build(misp_event_id = "7227"):

	print("Producing context...")

	print(f"	Getting attack pattern context...")
	ap_init_time = mark_time()
	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	print(attack_patterns_from_event)
	ap_final_time = mark_time()
	
	print(f"	Getting ioc context...")
	ioc_init_time = mark_time()
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	ioc_init_time = mark_time()
	
	print(f"	Getting vulnerability context...")
	vul_init_time = mark_time()
	vul_context, cves = create_vulnerability_context(misp_event_id)
	vul_final_time = mark_time()

	context_array = []
	
	print(f"	Appending attack pattern context...")
	context_array.append(create_attack_pattern_context(attack_patterns_from_event))
	print(f"	Appending ioc context...")
	context_array.append(ioc_context)
	print(f"	Appending vulnerability context...")
	context_array.append(vul_context)

	for c in context_array:
		print(c)

#====================================================================================

if __name__ == "__main__":

	if sys.argv[1] == "context":
		context_build()
	else:
		init_time = mark_time()
		print("==============================")
		print("Producing results with attack pattern context only...")
		print("==============================")
		get_attack_pattern_context_analysis("7227")
		final_time = mark_time()
		print("KAG TIME:")
		print_time_it_took(init_time, final_time)

		init_time = mark_time()
		print("==============================")
		print("Producing results with attack pattern context + IoC + vulnerabilities...")
		print("==============================")
		get_complete_context_analysis("7227")
		final_time = mark_time()
		print("ÑO KAG TIME:")
		print_time_it_took(init_time, final_time)
