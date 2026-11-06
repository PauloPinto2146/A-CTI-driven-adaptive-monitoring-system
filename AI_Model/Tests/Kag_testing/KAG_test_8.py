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
	1. Giving attack patterns individually and ask for monitoring rules for each specific attack pattern 
	2. Dump all attack patterns (as it is being done now)
"""

# =================================================================================================================================================================================================================================

def kag_test8_chunked_version(misp_event_id, model, context_dict, network_attack_patterns_names, ioc_dict, cves, host_dict):

	print( "===================================================================")
	print(f"CHUNKED version...")

	for ap in network_attack_patterns_names:
		attack_pattern_name, attack_pattern_context = create_attack_pattern_context([ap], 3)
		if len(attack_pattern_name) == 0:
			continue 
		ap_name = attack_pattern_name[0]

		data_to_consider = f"""
Consider:
	The attack pattern {ap_name}
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

		print(f"Attack pattern context for {ap_name}:")
		print("=================")
		print(attack_pattern_context)
		print("=================")

		client = Client(
			host="https://ollama.com",
			headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
		)

		host_state = f"""
The host's: 
	installed programs: {host_dict.get("programs")}
	services: {host_dict.get("services")}
	running processes: {host_dict.get("running_processes")}
	ports: {host_dict.get("ports")}\n
	"""

		try:
			messages = [{'role': 'user','content': first_prompt}]
			
			init_time = mark_time()
			response = client.chat(model, messages=messages)
			final_time = mark_time()

			security_analysis = response['message']['content']
			print(f"=========== Test case B: Chunk {ap_name} ===========")
			print(security_analysis+"\n")
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
	The host's: 
		installed programs: {host_dict.get("programs")}
		services: {host_dict.get("services")}
		running processes: {host_dict.get("running_processes")}
		ports: {host_dict.get("ports")}\n
	"""

			# With test 7 the intruction now explicitely says to just use attack patterns reported
			sysmon_instruction = f"""
	Context:
	{sysmon_context}

	Use these examples of NetworkConnect for your final result:
	{networkConnect_examples}

	Instruction:
	Based on the security analysis previously done before and the host state:
	{host_state}

	Provide a NetworkConnect snippet of the sysmon configuration file that would monitor the attack pattern behavior. 
	Try to avoid isolate rules that can produce a lot of noise.
	Follow the example format and give names on the <Rule> tags with the corresponding technique_id and technique_name whenever applicable.
	Use the xml comment syntax to refer the attack pattern or vulnerability being dealt with. And at the end of the XML file, still with the comment syntax, explain the what you used and not used from the security analysis.
	The generated XML must only contain metadata referencing ATT&CK technique {ap_name}. Do not use any other ATT&CK techniques, unless they are commonly used during exploitation of {ap_name}
			"""

			messages2 = messages + [{'role':'assistant', 'content': security_analysis}, {'role':'user','content': sysmon_instruction}]

			try:
				init_time = mark_time()
				response2 = client.chat(model, messages=messages2)
				final_time = mark_time()

				sysmon_res = response2['message']['content']

				print("\n\n" + sysmon_res)
				print_time_it_took(init_time,final_time)
				
				with open("KAG_test_8_context.md", "a") as f:
					f.write(f"## Test case B security analysis ({ap_name})\n\n```{security_analysis}```")
					f.write(f"\n## Test case B sysmon ({ap_name})\n\n{sysmon_res}\n")
				
			except Exception as e:
				print(f"Error while trying to call model '{model}' in kag_test8_chunked_version: {e}")
				return

				
		except Exception as e:
			print(f"Error while trying to call model '{model}' in kag_test8_chunked_version: {e}")
			return


# =================================================================================================================================================================================================================================

def kag_test8_dump_version(misp_event_id, model, context_dict, network_attack_patterns_names, ioc_dict, cves, host_dict):

	print( "===================================================================")
	print(f"Building query for dump version...")
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
		print("=========== Test case A: Dump the attack patterns into a single prompt ===========")
		print(security_analysis)
		print_time_it_took(init_time, final_time)

		with open("KAG_test_8_context.md", "w") as f:
			f.write("# Test 8 context\n\n# Initial Prompt\n\n")
			f.write(first_prompt+"\n")
			f.write(f"# Security analysis\n\n{security_analysis}")

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
The host's: 
	installed programs: {host_dict.get("programs")}
	services: {host_dict.get("services")}
	running processes: {host_dict.get("running_processes")}
	ports: {host_dict.get("ports")}\n
"""

		# With test 7 the intruction now explicitely says to just use attack patterns reported
		sysmon_instruction = f"""
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

		messages2 = messages + [{'role':'assistant', 'content': security_analysis}, {'role':'user','content': sysmon_instruction}]

		try:
			init_time = mark_time()
			response2 = client.chat(model, messages=messages2)
			final_time = mark_time()

			sysmon_res = response2['message']['content']
			print("\n\n" + sysmon_res)
			print_time_it_took(init_time, final_time)

			
			with open("KAG_test_8_context.md", "w") as f:
				f.write("\n## Test case A\n\n### Sysmon Instruction A\n\n```")
				f.write(sysmon_instruction + "\n```")
				f.write(f"## Test case A answer\n{sysmon_res}")
			
			
		except Exception as e:
			print(f"Error while trying to call model '{model}' in kag_test8_dump_version: {e}")
			return

			
	except Exception as e:
		print(f"Error while trying to call model '{model}' in kag_test8_dump_version: {e}")
		return

# =================================================================================================================================================================================================================================

def kag_test8(misp_event_id, model = "gemma4:31b-cloud"):

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
	

	kag_test8_dump_version(misp_event_id, model, context_dict, network_attack_patterns_names, ioc_dict, cves, host_dict)
	with open("KAG_test_8_context.md", "a") as f:
		f.write("\n---\n## Test case B\n\n")
	kag_test8_chunked_version(misp_event_id, model, context_dict, attack_patterns_from_event, ioc_dict, cves, host_dict)


#====================================================================================

if __name__ == "__main__":
	misp_event_id = "7227"
	kag_test8(misp_event_id)