import ollama
import json
import os

from ollama import Client
from ollama import chat
from AI_utils import mark_time, listRegistryAttackPatterns, list_network_exposure, listRegistryNetwork, listRegistryVulnerabilities, print_time_it_took

def phase1(model, needsExample, mode):

    first_prompt = f"""
    You are a strict Cyber Security Expert and Risk Analyst. Your task is to analyze threat intelligence against a host's current state and justify which Indicators of Compromise (IoCs) are critical to monitor.

    Context for your decision:
        1. Time Relevancy: How recent or applicable are the threat intelligence metrics.
        2. Vulnerabilities reported: The likelihood, impact and risk of a malicious action in the network of the host.
        3. Attack Surface: Cross-reference the host's active ports, vulnerabilities and the IoCs in the CTI report.

Data Provided:
    - Current Host Network State (Active addresses and ports):
{json.dumps(list_network_exposure())}

    - Cyber Threat Intelligence (CTI) Report containing verified IoCs (threat_level_id 3:Low, 2: Medium, 1: High)
{json.dumps(listRegistryNetwork()[0])}

    - Vulnerabilities reported:
{json.dumps(listRegistryVulnerabilities())}

    - Attack patterns reported:
{json.dumps(listRegistryAttackPatterns())}    

    Your Task step-by-step:
        1. Provide a detailed security analysis. For each category (Source IPs, Destination IPs, Ports, and Images), explain which elements from the data pose a real threat to this host and why they must be selected for monitoring (you are writin for an AI model, not a person).

    Strict Rules to Follow:
        1. Do NOT hallucinate IP addresses. Only consider the data  provided.
        2. For process images (executables), prioritize the files discovered in the CTI report. If you suggest additional system binaries, they must strictly relate to the exploitation of the listed vulnerabilities.
        3. Start your response directly with the technical analysis sections. 
        4. Do NOT include markdown tables, "To/From" headers, dates, executive summaries, or final disclaimers. 
    """ 

    print("The first_prompt sent: ")    
    print("============================")
    print(first_prompt)
    print("============================")

    init_time = mark_time()
    print("Init time (phase1): ", init_time)

    messages = [
                    {
                    'role': 'user',
                    'content': first_prompt
                    }
                ]

    initial_response = None

    if mode == "local":
        try:
            response = chat(
                model = model,
                messages =  [
                    messages
                ]
            )
            print(response['message']['content'])
            initial_response = response['message']['content']
        except Exception as e:
            print(f"Error while trying to call model '{model}': {e}")
            return
    elif mode == "cloud":
        try:
            client = Client(
                host="https://ollama.com",
                headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
            )
            response = client.chat(model, messages=messages)
            print(response['message']['content'])
            initial_response = response['message']['content']
        except Exception as e:
            print(f"Error while trying to call model '{model}': {e}")
            return
    else:
        raise ValueError(f"Invalid mode: {mode}")

    
    final_time = mark_time()

    print_time_it_took(init_time, final_time)

    return first_prompt, initial_response


def phase2(model, response_phase1, first_prompt, mode):

    if response_phase1 == None:
        print(f"Error while trying to call model '{model}': First response is None")
        return

    second_prompt = """
    Based on the security analysis you just performed, extract the selected indicators and organize them into a single, valid XML snipet that can integrate a valid sysmon configurtion file.

    Strict Rules for the Output:
    1. The XML snipet must be a NetworkConnect tag
    2. The NetworkConnect tag can include Image, Protocol, Initiated, SourceIp, SourceHostname, SourcePort, SourcePortName, DestinationIp, DestinationHostname, DestinationPort, DestinationPortName. Do NOT hallucinate other parameters
    3. Output ONLY the raw XML block. Justify each choice by using the XML comment syntax.

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
    print("Init time (phase2): ", init_time)

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

    if mode == "local":
        try:
            response = chat(
                model = model,
                messages =  messages
            )
            print(response['message']['content'])
            final_response = response['message']['content']
        except Exception as e:
            print(f"Error while trying to call model '{model}': {e}")
            return
    elif mode == "cloud":
        try:
            client = Client(
                    host="https://ollama.com",
                    headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
                )
            response = client.chat(model, messages=messages)
            print(response['message']['content'])
            final_response = response['message']['content']
        except Exception as e:
            print(f"Error while trying to call model '{model}': {e}")
            return
    else:
        raise ValueError(f"Invalid mode: {mode}")
    
    final_time = mark_time()

    print_time_it_took(init_time, final_time)

    return final_response



def approach3(model, mode):
    
    first_prompt, response_phase1 = phase1(model, False, mode)
    response_phas2 = phase2(model, response_phase1, first_prompt, mode)