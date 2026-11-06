import ollama
import asyncio

from AI_utils import mark_time, list_installed_programs

async def approach1(model):

    print(f"Requesting {model}...")

    initial_prompt = f"""
    You are a Sysmon configuration expert.

    Task:
    Generate a minimal Sysmon configuration focused ONLY on detection of the following MITRE ATT&CK techniques:

    - T1106 (Native API)
    - T1648 (Serverless execution)
    - T1534 (Internal Spearphishing)

    Host context:
    
    These are the programs installed on the host: {list_installed_programs()}

    Please use this context as you see fit in the sysmon configuration file (if you think some of them are not worth to consider do not use them).


    Objective:
    Use this information to build a sysmon xml cofiguration file 

    Recall how sysmon config files work:
        This is the root: "<Sysmon schemaversion="4.91">"
        In the "EventFiltering" root we can exclude or include conditions like this: 
            <EventFiltering>
                <ProcessCreate onmatch="include">
                    <Image condition="contains">timeout.exe</Image>
                </ProcessCreate>
        If you leave it like:
            <FileCreateTime onmatch="exclude" />
        it excludes no conditions, meaning it will log everything.
        If if you leave it like:
            <FileCreateTime onmatch="include" />
        it includes no conditions, meaning it will log nothing.

        Besides ProcessCreate the available events are:
            NetworkConnect
            ProcessTerminate
            DriverLoad
            ImageLoad
            CreateRemoteThread
            RawAccessRead
            ProcessAccess
            FileCreate
            RegistryEvent
            FileCreateStreamHash
            PipeEvent
            WmiEvent
            DnsQuery
            FileDelete
            ClipboardChange
            ProcessTampering
            FileDeleteDetected
            FileBlockExecutable
            FileBlockShredding
            FileExecutableDetected
    """


    print("The initial_prompt sent: ")    
    print("============================")
    print(initial_prompt)
    print("============================")

    init_time = mark_time()
    print("Initi time: ", init_time)
    client = AsyncClient()
    try:
        response = await client.generate(
            model = model,
            prompt = initial_prompt,
        )
    except:
        print(f"Model {model} not found")
        return
    print(response["response"])
    initial_response = response["response"]
    final_time = mark_time()

    print(f"Time it took: {final_time.minute - init_time.minute} minutes and {final_time.second - init_time.second} seconds")