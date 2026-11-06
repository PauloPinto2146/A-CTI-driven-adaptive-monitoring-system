import ollama
import numpy as np
import json
import os
import sys

from ollama import chat
from ollama import Client
from AI_utils import list_network_exposure, listRegistryNetwork, print_time_it_took, mark_time

from context_creator import create_attack_pattern_context, get_attack_patterns_from_MISP_event, create_network_ioc_context, create_vulnerability_context

def get_attack_pattern_analysis_KAG(misp_event_id, model = "gemma4:31b-cloud", embedding_model = "nomic-embed-text", print_context = False):
	
	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	vul_context, cves = create_vulnerability_context(misp_event_id)

	context_array = []
	print("Producing context...")
	for ap in attack_patterns_from_event:
		context_array.append(create_attack_pattern_context(ap))
	context_array.append(ioc_context)
	context_array.append(vul_context)

	embedded_context = []
	print(f"	Embedding context...")
	for c in context_array:
		response = ollama.embeddings(
					model=embedding_model,
					prompt=c
				)

		embedded_context.append({
				"text": c,
				"embedding": np.array(response["embedding"])
			})

	print(f"	Building query...")
	query = f"""
Tell for this attack patterns: {attack_pattern_names_from_event}
For these indicators of compromise: {ioc_dict}
And these vulnerabilities: {cves}
Which information would you consider for the NetworkConnect portion of a sysmon configuration file?
	"""

	print(f"	Embedding query...")
	query_response = ollama.embeddings(
	    model=embedding_model,
	    prompt=query
	)

	query_embedding = np.array(query_response["embedding"])

	# -----------------------------
	# BUILD CONTEXT
	# -----------------------------

	print(f"	Building context...")
	context = "\n\n".join(context_array)

	if print_context:
		print("=== All context ===")
		for ed in embedded_context:
			print(ed.get("text"))

		print("=== RETRIEVED CONTEXT ===")
		print(context + "\n\n")

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

def get_attack_pattern_analysis(misp_event_id, model = "gemma4:31b-cloud"):

	_, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	vul_context, cves = create_vulnerability_context(misp_event_id)

	query = f"""
Tell for this attack patterns: {attack_pattern_names_from_event}
Knowing these are associated with a vulnerability that has 0.988 epss value, which information would you consider for the NetworkConnect portio of a sysmon configuration file?
	"""

	messages = [{'role': 'user','content': query}]

	init_time = mark_time()
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

if __name__ == "__main__":

	misp_event_id = "7227"

	init_time = mark_time()
	print("==============================")
	print("Producing results with KAG...")
	print("==============================")
	get_attack_pattern_analysis_KAG(misp_event_id)
	final_time = mark_time()
	print("KAG TIME:")
	print_time_it_took(init_time, final_time)

	init_time = mark_time()
	print("==============================")
	print("Producing results without KAG...")
	print("==============================")
	get_attack_pattern_analysis(misp_event_id)
	final_time = mark_time()
	print("ÑO KAG TIME:")
	print_time_it_took(init_time, final_time)
