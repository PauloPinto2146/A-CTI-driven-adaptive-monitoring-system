import ollama
import numpy as np
import json
import os
import sys

from ollama import chat
from ollama import Client
from AI_utils import list_network_exposure, listRegistryNetwork, print_time_it_took, mark_time, list_installed_programs, list_services, list_running_processes, list_network_exposure, get_network_connect_examples, get_ips_information
from context_creator import create_attack_pattern_context, get_attack_patterns_from_MISP_event, create_network_ioc_context, create_vulnerability_context


"""
This test will try to inject the ip address context.
I noticed that, most of the times, the AI won't try to monitor IP adresses and ports itself.
So I will try to give it some IP address context (via ip-api.com) and see what results come up
"""

def ai_chat_aux(prompt, model, instruction, client):


	try:
		messages = [{'role': 'user','content': prompt}]
		
		init_time = mark_time()
		response = client.chat(model, messages=messages)
		final_time = mark_time()

		print(response['message']['content'])
		security_analysis = response['message']['content']
		print_time_it_took(init_time, final_time)

		messages2 = ([{'role':'assistant', 'content': security_analysis}, {'role':'user','content': instruction}])	 

		try:
			init_time = mark_time()
			response2 = client.chat(model, messages=messages2)
			final_time = mark_time()

			print(response2['message']['content'])
			sysmon_res = response['message']['content']
			
			print_time_it_took(init_time, final_time)
		except Exception as e:
			print(f"Error while trying to call model '{model}': {e}")
			return
	except Exception as e:
		print(f"Error while trying to call model '{model}': {e}")
		return

	return security_analysis, sysmon_res

def kag_test4_aux(misp_event_id, model, context_dict, attack_pattern_names_from_event, ioc_dict, cves, host_dict, sysmon_context):

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

	query = data_to_consider + instruction
	
	attack_pattern_context = context_dict.get("attack_pattern_context")
	ioc_context = context_dict.get("ioc_context")
	vul_context = context_dict.get("vul_context")
	ports = list_network_exposure()
	ip_context = context_dict.get("ip_context")

	# -----------------------------
	# FINAL PROMPT
	# -----------------------------

	prompt1 = f"""
Context:
Attack pattern context: {attack_pattern_context}
IoCs context: {ioc_context}
Vulnerability context: {vul_context}
Ip addresses and port context: {ip_context}

Question:
{query}
	"""

	prompt2 = f"""
Context:
Attack pattern context: {attack_pattern_context}
IoCs context: {ioc_context}
Vulnerability context: {vul_context}

Question:
{query}
	"""

	instruction = f"""
Context:
{sysmon_context}

Learn from these examples of portions of NetworkConnect:
{get_network_connect_examples()}

Instruction:
Based on the security analysis previously done before and the host state:
{host_state}

Provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements. 
Try to avoid isolate rules that can produce a lot of noise, like isolating port 8080 in an open include box.
Follow the example format and populate the name attribute of the tags with the corresponding technique_id and technique_name whenever applicable.
Use the xml comment syntax to explain your choices. And at the end of the XML file, still with the comment syntax, explain why you did not monitor some of the things it was given to you.
"""

	client = Client(
			host="https://ollama.com",
			headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
		)


	print("Ip context: ", ip_context)
	print("=========== With IP context ===========")
	ip_context_sec_analysis, ip_context_sysmon = ai_chat_aux(prompt1, model, instruction, client)
	print("=========== NO IP context ===========")
	no_ip_context_sec_analysis, no_ip_context_sysmon = ai_chat_aux(prompt2, model, instruction, client)
	
	

def kag_test4(misp_event_id, model = "gemma4:31b-cloud"):

	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	vul_context, cves = create_vulnerability_context(misp_event_id)

	context_dict = {}
	print("Producing context...")
	context_dict["attack_pattern_context"] = create_attack_pattern_context(attack_patterns_from_event)
	context_dict["ioc_context"] = ioc_context
	context_dict["vul_context"] = vul_context
	ports = list_network_exposure()
	context_dict["ip_context"] = get_ips_information(ports)


	host_dict = {
		"programs": list_installed_programs(),
		"services": list_services(),
		"running_processes": list_running_processes(),
		"ports": ports
	}

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

Condition 	Description
is 	Default, values are equals
is any 	The field is one of the ; delimited values
is not 	Values are different
contains 	The field contains this value
contains any 	The field contains any of the ; delimited values
contains all 	The field contains all of the ; delimited values
excludes 	The field does not contain this value
excludes any 	The field does not contain one or more of the ; delimited values
excludes all 	The field does not contain any of the ; delimited values
begin with 	The field begins with this value
end with 	The field ends with this value
not begin with 	The field does not begin with this value
not end with 	The field does not end with this value
less than 	Lexicographical comparison is less than zero
more than 	Lexicographical comparison is more than zero
image 	Match an image path (full path or only image name). For example: lsass.exe will match c:\\windows\\system32\\lsass.exe
"""

	kag_test4_aux(misp_event_id, model, context_dict, attack_pattern_names_from_event, ioc_dict, cves, host_dict, sysmon_context)


#====================================================================================

if __name__ == "__main__":
	misp_event_id = "7227"
	kag_test4(misp_event_id)