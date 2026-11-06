import ollama
import numpy as np
import json
import os
import sys

from ollama import chat
from ollama import Client
from AI_utils import list_network_exposure, listRegistryNetwork, print_time_it_took, mark_time

from context_creator import create_attack_pattern_context, get_attack_patterns_from_MISP_event, create_network_ioc_context, create_vulnerability_context

def kag_test3_aux(misp_event_id, model, test_type, context_array, attack_pattern_names_from_event, ioc_dict, cves):
	with open("KAG_TEST_3_THREATMODEL.json") as f:
		threat_model_test_data = json.load(f)

	test_data = threat_model_test_data.get(test_type)

	for x in test_data:

		print(f"	Building query...")

		data_to_consider = f"""
For these attack patterns: {attack_pattern_names_from_event}
For these indicators of compromise: {ioc_dict}
And these vulnerabilities: {cves}\n
"""
		instruction = f"""
Create a contexted security analysis that details what information to monitor with sysmon, sepcifically for the NetworkConnect snippet.
Do NOT introduce anything that does not have to do with monitoring that could be noise, since your result will be used by another LLM.
Consider that the host being monitored is a {x.get("Asset_Type")}, it has a {x.get("Impact")} impact if it was to be attacked and has {x.get("Network_Exposure")} network exposure.
		"""

		print("Instruction 1 given: \n", instruction)

		query = data_to_consider + instruction
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
		try:

			client = Client(
				host="https://ollama.com",
				headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
			)
			response = client.chat(model, messages=messages)
			print(f"\n#{x.get("Impact")} Impact")
			print(response['message']['content'])
			ai_response = response['message']['content']
			final_time = mark_time()
			print_time_it_took(init_time, final_time)

			instruction2 = f"""
	Instruction:
	Based on the security analysis previously done before, provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements. 
	Use the xml comment syntax to explain your choices.
	"""

			print("Instruction 2 given: \n", instruction2)

			messages.extend([{'role':'assistant', 'content': ai_response}, {'role':'user','content': instruction2}])	 

			try:
				init_time = mark_time()
				print("Initiating second prompt")
				response2 = client.chat(model, messages=messages)
				print(response2['message']['content'])
				ai_response2 = response['message']['content']
				final_time = mark_time()
				print_time_it_took(init_time, final_time)
			except Exception as e:
				print(f"Error while trying to call model '{model}': {e}")
				return
		except Exception as e:
			print(f"Error while trying to call model '{model}': {e}")
			return

def kag_test3(misp_event_id, model = "gemma4:31b-cloud"):

	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	vul_context, cves = create_vulnerability_context(misp_event_id)

	context_array = []
	print("Producing context...")
	context_array.extend(create_attack_pattern_context(attack_patterns_from_event))
	context_array.append(ioc_context)
	context_array.append(vul_context)

	kag_test3_aux(misp_event_id, model, "Network_Exposure_test", context_array, attack_pattern_names_from_event, ioc_dict, cves)
	kag_test3_aux(misp_event_id, model, "Impact_test", context_array, attack_pattern_names_from_event, ioc_dict, cves)


#====================================================================================

if __name__ == "__main__":
	misp_event_id = "7227"
	kag_test3(misp_event_id)