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
Two different implementations:
	1. The "normal" version already in play 
	2. A version where I only give the host's state affter the produced sysmon snippet
This test will try to introduce the host's indicators, since most of the time it does not consider the host state at all
"""

def kag_test9_aux(misp_event_id, model, context_dict, network_attack_patterns_names, ioc_dict, cves, host_dict):

	print( "===================================================================")
	print(f"Building query...")
	print( "===================================================================")

	data_to_consider = f"""
Consider:
These attack patterns: {network_attack_patterns_names}
These indicators of compromise: {ioc_dict}
These vulnerabilities: {cves}
"""

	security_analysis_instruction = f"""
Create a contexted security analysis that details what information to monitor with sysmon, sepcifically for the NetworkConnect snippet.
Do NOT introduce anything that does not have to do with monitoring that could be noise, since your result will be used by another LLM.
Consider that the host being monitored is a server with HIGH network exposure.
Use plain text.
	"""

	query = data_to_consider + security_analysis_instruction
	
	attack_pattern_context = context_dict.get("attack_pattern_context")
	ioc_context = context_dict.get("ioc_context")
	vul_context = context_dict.get("vul_context")
	ports = list_network_exposure()
	ip_context = context_dict.get("ip_context")

	first_prompt = f"""
Context:
Attack pattern context: {attack_pattern_context}
IoCs context: {ioc_context}
Vulnerability context: {vul_context}
Ip addresses and port context: {ip_context}

Question:
{query}
	"""

	client = Client(
			host="https://ollama.com",
			headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
		)

	try:
		messages = [{'role': 'user','content': first_prompt}]
		
		init_time = mark_time()
		response = client.chat(model, messages=messages)
		final_time = mark_time()

		security_analysis = response['message']['content']
		print("=========== Test case NORMAL ===========")
		print(security_analysis)
		print_time_it_took(init_time, final_time)

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

		networkConnect_examples = get_network_connect_examples()

		host_state = f"""
	installed programs: {host_dict.get("programs")}
	services: {host_dict.get("services")}
	running processes: {host_dict.get("running_processes")}
	ports: {host_dict.get("ports")}\n
"""

		sysmon_instruction_normal = f"""
Context:
{sysmon_context}

Use these examples of NetworkConnect for your final result:
{networkConnect_examples}

Instruction:
Based on the security analysis previously done before and the host state:
{host_state}

Provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements. 
Try to avoid isolate rules that can produce a lot of noise, like isolating port 8080 in an open include box.
Follow the example format and populate the name attribute of the tags with the corresponding technique_id and technique_name whenever applicable.
Use the xml comment syntax to refer the attack pattern or vulnerability being dealt with. And at the end of the XML file, still with the comment syntax, explain the what you used and not used from the security analysis.
Do NOT implement monitoring rules outside of the reported attack patterns: {network_attack_patterns_names}
		"""
		sysmon_instruction_host = f"""
Context:
{sysmon_context}

Use these examples of NetworkConnect for your final result:
{networkConnect_examples}

Instruction:
Based on the security analysis previously done before
Provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements. 
Try to avoid isolate rules that can produce a lot of noise, like isolating port 8080 in an open include box.
Follow the example format and populate the name attribute of the tags with the corresponding technique_id and technique_name whenever applicable.
Use the xml comment syntax to refer the attack pattern or vulnerability being dealt with. And at the end of the XML file, still with the comment syntax, explain the what you used and not used from the security analysis.
Do NOT implement monitoring rules outside of the reported attack patterns: {network_attack_patterns_names}
		"""

		messages2_normal = messages + [{'role':'assistant', 'content': security_analysis}, {'role':'user','content': sysmon_instruction_normal}]
		messages2_host = messages + [{'role':'assistant', 'content': security_analysis}, {'role':'user','content': sysmon_instruction_host}]

		try:
			init_time = mark_time()
			response2 = client.chat(model, messages=messages2_normal)
			final_time = mark_time()

			sysmon_res_normal = response2['message']['content']
			print("\n\n" + sysmon_res_normal)
			print_time_it_took(init_time, final_time)
			
			
		except Exception as e:
			print(f"Error while trying to call model '{model}' in kag_test8_dump_version: {e}")
			return

		try:
			init_time = mark_time()
			response2 = client.chat(model, messages=messages2_host)
			final_time = mark_time()

			sysmon_res_host = response2['message']['content']
			print("\n\n" + sysmon_res_host)
			print_time_it_took(init_time, final_time)


			try:
				host_instruction = f"""
Base your answer in the security analysis and sysmon configuration snippet done before.
Consider the host's state:
{host_state}
Alter the sysmon configuration file (or not) as you see fit to monitor the attack patterns' behavior.
				"""
				messages3 = messages2_host + [{'role':'assistant', 'content': sysmon_res_host}, {'role':'user','content': host_instruction}]
				init_time = mark_time()
				response3 = client.chat(model, messages=messages3)
				final_time = mark_time()

				sysmon_host_res = response3['message']['content']
				print("\n\n" + sysmon_host_res)
				print_time_it_took(init_time, final_time)

				
				with open("KAG_test_9_context.md", "a") as f:
					f.write("\n## Test case HOST \n\n### Host Instruction\n\n```")
					f.write(host_instruction + "\n```")
					f.write(f"\n## Test case HOST answer\n{sysmon_host_res}")
				
				
			except Exception as e:
				print(f"Error while trying to call model '{model}' in kag_test9: {e}")
				return
			
			
		except Exception as e:
			print(f"Error while trying to call model '{model}' in kag_test9: {e}")
			return

			
	except Exception as e:
		print(f"Error while trying to call model '{model}' in kag_test9: {e}")
		return

# =================================================================================================================================================================================================================================

def kag_test9(misp_event_id, model = "gemma4:31b-cloud"):

	attack_patterns_from_event, attack_pattern_names_from_event = get_attack_patterns_from_MISP_event(misp_event_id)
	ioc_context, ioc_dict = create_network_ioc_context(misp_event_id)
	vul_context, cves = create_vulnerability_context(misp_event_id)

	context_dict = {}
	print("Producing context...")
	network_attack_patterns_names, context_dict["attack_pattern_context"] = create_attack_pattern_context(attack_patterns_from_event, 3)
	context_dict["ioc_context"] = ioc_context
	context_dict["vul_context"] = vul_context
	ports = list_network_exposure()
	context_dict["ip_context"] = get_ips_information(ports)
	print("Context building done!")


	host_dict = {
		"programs": list_installed_programs(),
		"services": list_services(),
		"running_processes": list_running_processes(),
		"ports": ports
	}
	

	kag_test9_aux(misp_event_id, model, context_dict, network_attack_patterns_names, ioc_dict, cves, host_dict)

#====================================================================================

if __name__ == "__main__":
	misp_event_id = "7227"
	kag_test9(misp_event_id)