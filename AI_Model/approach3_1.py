import ollama
import json

from ollama import chat
from AI_utils import mark_time, list_services, list_network_exposure, listRegistryNetwork, listRegistryVulnerabilities, print_time_it_took

def phase1(model, needsExample):

    first_prompt = f"""
You are a strict Cyber Security Expert and Risk Analyst. Your task is to analyze threat intelligence against a host's current state and justify which Indicators of Compromise (IoCs) are critical to monitor.

Your task is to Provide a detailed analysis of the vulnerabilities recently, which include:
    1. The potential attack vectors
    2. Based on the potential attack vectors, provide indicators of compromise that should be monitored
    3. Based on the current services running on the host, describe what services should be monitored.

Vulnerabilities reported:
{json.dumps(listRegistryVulnerabilities())}

Host's running services:
{list_services()}

Strict Rules to Follow:
    1. Start your response directly with the technical analysis sections. 
    2. Do NOT include markdown tables, "To/From" headers, dates, executive summaries, or final disclaimers. 
    
    """ 

    print("The first_prompt sent: ")    
    print("============================")
    print(first_prompt)
    print("============================")

    init_time = mark_time()
    print("Init time: ", init_time)

    try:
        response = chat(
            model = model,
            messages =  [
                {
                'role': 'user',
                'content': first_prompt
                },
            ]
        )
    except Exception as e:
        print(f"Error while trying to call model '{model}': {e}")
        return

    print(response['message']['content'])

    initial_response = response['message']['content']
    final_time = mark_time()

    print_time_it_took(init_time, final_time)

    return first_prompt, initial_response

def phase2(model, response_phase1, first_prompt):

    second_prompt = f"""
    Based on the vulnerability analysis you just performed, and knowing the how critical is the host's state, you will now analyse indicators of compromise.

- Cyber Threat Intelligence (CTI) Report containing verified IoCs (threat_level_id 3:Low, 2: Medium, 1: High)
{json.dumps(listRegistryNetwork()[0])}

    - Vulnerabilities reported:
{json.dumps(listRegistryVulnerabilities())}


    Structure example:
    <NetworkConnect onmatch="include">
        <DestinationPort>443</DestinationPort>
        <DestinationPort>80</DestinationPort>
        <Image condition="contains any">
            iexplore.exe;
            firefox.exe;
        </Image>
    </NetworkConnect>
    """

    print("The second_prompt sent: ")    
    print("============================")
    print(second_prompt)
    print("============================")

    init_time = mark_time()
    print("Init time (phase1): ", init_time)

    try:
        response = chat(
            model = model,
            messages =  [
                {
                'role': 'user',
                'content': first_prompt
                },
                {
                'role': 'assistant',
                'content': response_phase1
                },
                {
                'role': 'user',
                'content': second_prompt
                }
            ]
        )
    except Exception as e:
        print(f"Error while trying to call model '{model}': {e}")
        return

    print(response['message']['content'])

    initial_response = response['message']['content']
    final_time = mark_time()

    print_time_it_took(init_time, final_time)

    return initial_response


def final_phase(model, response_phase1, first_prompt):

    second_prompt = f"""
    Based on the security analysis you just performed, extract the selected indicators and organize them into a single, valid XML snipet that can integrate a valid sysmon configurtion file.

    Strict Rules for the Output:
    1. The XML snipet must be a NetworkConnect tag
    2. The NetworkConnect tag can include Image, Protocol, Initiated, SourceIp, SourceHostname, SourcePort, SourcePortName, DestinationIp, DestinationHostname, DestinationPort, DestinationPortName. Do NOT hallucinate other parameters
    3. Output ONLY the raw XML block. You can use the XML commentary syntax (<!-- -->) to explain your decisions.


    - Cyber Threat Intelligence (CTI) Report containing verified IoCs (threat_level_id 3:Low, 2: Medium, 1: High)
{json.dumps(listRegistryNetwork()[0])}

    - Vulnerabilities reported:
{json.dumps(listRegistryVulnerabilities())}


    Structure example:
    <NetworkConnect onmatch="include">
        <DestinationPort>443</DestinationPort>
        <DestinationPort>80</DestinationPort>
        <Image condition="contains any">
            iexplore.exe;
            firefox.exe;
        </Image>
    </NetworkConnect>
    """

    print("The second_prompt sent: ")    
    print("============================")
    print(second_prompt)
    print("============================")

    init_time = mark_time()
    print("Init time (phase1): ", init_time)

    try:
        response = chat(
            model = model,
            messages =  [
                {
                'role': 'user',
                'content': first_prompt
                },
                {
                'role': 'assistant',
                'content': response_phase1
                },
                {
                'role': 'user',
                'content': second_prompt
                }
            ]
        )
    except Exception as e:
        print(f"Error while trying to call model '{model}': {e}")
        return

    print(response['message']['content'])

    initial_response = response['message']['content']
    final_time = mark_time()

    print_time_it_took(init_time, final_time)

    return initial_response



def approach3_1(model):
    print("main approach3_1")
    first_prompt, response_phase1 = phase1(model, False)
    #response_phase2 = phase2(model, response_phase1, first_prompt)