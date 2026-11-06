import ollama
import numpy as np
import json
import os
import sys

from ollama import chat
from ollama import Client
from AI_utils import list_network_exposure, listRegistryNetwork, print_time_it_took, mark_time, list_installed_programs, list_services, list_running_processes, list_network_exposure

from context_creator import create_attack_pattern_context, get_attack_patterns_from_MISP_event, create_network_ioc_context, create_vulnerability_context


"""
This test will try to inject the host's current state to see what the AI can do with it in two different scenarios:
- On the first prompt
- On the second prompt

Hopefully it will consider only certain services
"""

def kag_test4_aux(misp_event_id, model, context_array, attack_pattern_names_from_event, ioc_dict, cves, host_dict):

	print( "===================================================================")
	print(f"	Building query...")

	data_to_consider = f"""
Consider:
These attack patterns: {attack_pattern_names_from_event}
These indicators of compromise: {ioc_dict}
These vulnerabilities: {cves}
"""

	host_state = f"""
The host's: 
	installed programs: {host_dict.get("programs")}
	services: {host_dict.get("services")}
	running processes: {host_dict.get("running_processes")}
	ports: {host_dict.get("ports")}\n
"""
	instruction = f"""
Create a contexted security analysis that details what information to monitor with sysmon, sepcifically for the NetworkConnect snippet.
Do NOT introduce anything that does not have to do with monitoring that could be noise, since your result will be used by another LLM.
Consider that the host being monitored is a server with HIGH network exposure.
	"""

	print("Instruction 1 given: \n", data_to_consider + instruction)

	query1 = data_to_consider + host_state + instruction
	context = "\n".join(context_array)

	# -----------------------------
	# FINAL PROMPT
	# -----------------------------

	prompt1 = f"""
Use the following context:
{context}

Question:
{query1}
	"""

	query2 = data_to_consider + instruction
	prompt2 = f"""
Use the following context:
{context}

Question:
{query2}
	"""


	sysmon_context = f"""
EventID 3 Network connection
	Image: File path of the process that made the network connection
	Protocol: Protocol being used for the network connection
	Initiated: Indicates whether the process initiated the TCP connection
	SourceIsIpv6: Is the source IP an Ipv6 address
	SourceIp: Source IP address that made the network connection
	SourceHostname: DNS name of the host that made the network connection
	SourcePort: Source port number
	SourcePortName: Name of the source port being used
	DestinationIsIpv6: Is the destination IP an Ipv6 address
	DestinationIp: IP address destination
	DestinationHostname: DNS name of the host that is contacted
	DestinationPort: Destination port number
	DestinationPortName: Name of the destination port
"""

	# ======== host state first ======== 
	messages1 = [{'role': 'user','content': prompt1}]
	try:
		init_time = mark_time()
		client = Client(
			host="https://ollama.com",
			headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
		)
		response = client.chat(model, messages=messages1)
		print(response['message']['content'])
		ai_response = response['message']['content']
		final_time = mark_time()
		print_time_it_took(init_time, final_time)

		instruction2 = f"""
Use the following context:
{sysmon_context}

Instruction:
Based on the security analysis previously done before, provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements (You can use the parameters Imge, Protocol, Initiated, SourceIp, SourceHostname, SourcePort, DesinationIp, DestinationHostname, DestinationPort).  
Use the xml comment syntax to explain your choices.
"""

		print("Instruction 2 given: \n", instruction2)

		messages1.extend([{'role':'assistant', 'content': ai_response}, {'role':'user','content': instruction2}])	 

		try:
			init_time = mark_time()
			response2 = client.chat(model, messages=messages1)
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

	# ======== host state second ======== 
	messages2 = [{'role': 'user','content': prompt2}]
	try:
		init_time = mark_time()
		client = Client(
			host="https://ollama.com",
			headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
		)
		response = client.chat(model, messages=messages2)
		print(response['message']['content'])
		ai_response = response['message']['content']
		final_time = mark_time()
		print_time_it_took(init_time, final_time)

		instruction2 = f"""
Use the following context:
{sysmon_context}

Instruction:
Based on the security analysis previously done before and
{host_state}

Provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements (You can use the parameters Imge, Protocol, Initiated, SourceIp, SourceHostname, SourcePort, DesinationIp, DestinationHostname, DestinationPort). 
Use the xml comment syntax to explain your choices.
"""

		print("Instruction 2 given: \n", instruction2)

		messages2.extend([{'role':'assistant', 'content': ai_response}, {'role':'user','content': instruction2}])	 

		try:
			init_time = mark_time()
			response2 = client.chat(model, messages=messages2)
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

def kag_test4(misp_event_id, model = "gemma4:31b-cloud"):

	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	vul_context, cves = create_vulnerability_context(misp_event_id)

	context_array = []
	print("Producing context...")
	context_array.extend(create_attack_pattern_context(attack_patterns_from_event))
	context_array.append(ioc_context)
	context_array.append(vul_context)

	host_dict = {
		"programs": list_installed_programs(),
		"services": list_services(),
		"running_processes": list_running_processes(),
		"ports": list_network_exposure()
	}

	kag_test4_aux(misp_event_id, model, context_array, attack_pattern_names_from_event, ioc_dict, cves, host_dict)


#====================================================================================

if __name__ == "__main__":
	misp_event_id = "7227"
	kag_test4(misp_event_id)