import ollama
import sys

from ollama import AsyncClient

from AI_utils import mark_time, list_installed_programs, list_services, list_running_processes, list_network_exposure

from approach1 import approach1
from approach2 import approach2
from approach3 import approach3
from approach3_1 import approach3_1


# Ollama pull model
# Ollama rm model
# models testes: gemma3, qwen2.5:14b, qwen3.6, gemma4, llama3.1, qwen3.5:9b

def freetext(model, message):
    
    init_time = mark_time()
    print("Initi time: ", init_time)

    messages = [{
        'role': 'user',
        'content': message
    }]
    response = chat(
            model = model,
            messages = messages
        )

    print(response['message']['content'])
    final_time = mark_time()

    print(f"Time it took: {final_time.minute - init_time.minute} minutes and {final_time.second - init_time.second} seconds")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        model = sys.argv[2]
        if sys.argv[1] == "approach1":
            asyncio.run(approach1(sys.argv[2]))
        elif sys.argv[1] == "approach2":
            approach2(model)
        elif sys.argv[1] == "approach3":
            mode = sys.argv[3]
            approach3(model, mode)
        elif sys.argv[1] == "approach3_1":
            approach3_1(model)
        elif sys.argv[1] == "freetext":
            freetext(sys.argv[2], sys.argv[3])
            
    else:
        print("Not enough arguments")