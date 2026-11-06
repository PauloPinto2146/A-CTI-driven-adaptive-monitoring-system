import ollama

from ollama import Client
from ollama import chat
import os
import json
from AI_utils import mark_time, listRegistryAttackPatterns, listRegistryNetwork, print_time_it_took

def approach2(model):

    cloud = True
    
    init_time = mark_time()
    print("Init time: ", init_time)

    message = f"""
    You are generating Sysmon XML and you are bulding a part of a sysmon configuration file that will be used to monitor an host vulnerable with epss 0.93 and is very valuable to the overall system.

    Valid example:
    <NetworkConnect onmatch="include">
        <DestinationPort>443</DestinationPort>
        <DestinationPort>80</DestinationPort>
        <Image condition="contains any">
            iexplore.exe;
            firefox.exe;
        </Image>
    </NetworkConnect>

    Which means "Log the events that have image iexplore.exe OR firefox.exe AND with 433 OR 80 port".

    Rules:
    - You can use these NetworkConnect XML tags from this list:
      [Image, Protocol, Initiated, SourceIp, SourceHostname, SourcePort, DestinationIp, DestinationHostname, DestinationPort]


    - Never invent XML tags.
    - Never use placeholders.
    - Never explain.
    - Output ONLY valid XML (no formatting).

    Task:
    Create ONLY NetworkConnect rule for these attack patterns:
    {json.dumps(listRegistryAttackPatterns())}

    And catch the indicators of compromise:
    {json.dumps(listRegistryNetwork())}
    If you consider it to be worth and/or correct.

    You can also add more content if you think it needs due to its critical role in the system.
    Justify each choice using the xml comment syntax.
    """

    print("Prompt sent:")
    print("================================================")
    print(message)
    print("================================================")

    messages = [{
                'role': 'user',
                'content': message
            }]

    if cloud:
        try:
            client = Client(
                host="https://ollama.com",
                headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')}
            )
            response = client.chat(model, messages=messages)
            print(response['message']['content'])
        except Exception as e:
            print(f"Error while trying to call model '{model}': {e}")
            return
    else:
        try:
            
            response = chat(
                    model = model,
                    messages = messages
                )

            print(response['message']['content'])
        except Exception as e:
            print(f"Error while trying to call model '{model}': {e}")
            return
    final_time = mark_time()

    print_time_it_took(init_time, final_time)