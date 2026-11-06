from graphviz import Digraph
import re 

# ========================================================================================

def trace(activity, pid, parentProcess, res_path):
    dot = Digraph()
    i = len(activity) - 1

    # Build nodes
    before_process = (0, "", [], 0)
    nodes = []
    while i >= 0:
        event = activity[i]
        recordId = event.get("RecordId")
        match event.get("EventId"):
            case 1:
                if before_process[0] == 1 and before_process[1] == event.get("ParentImage"):
                    before_process[2].append(get_exe(event.get("Image")))
                elif before_process[0] in [7,12,13]:
                    nodes.append(recordId)
                    dot, before_process = apply_before_process(before_process, dot)
                    before_process = (1, event.get("ParentImage"), [get_exe(event.get("Image"))], recordId)
                else:
                    nodes.append(recordId)
                    before_process = (1, event.get("ParentImage"), [get_exe(event.get("Image"))], recordId)
                    if i == 0:
                        dot, before_process = apply_before_process(before_process, dot)
            case 2:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"2 (File Creation Time Changed)\nRecordId:{recordId}\n{get_exe(event.get("Image"))}\nchanged time creation of\n{get_exe(event.get("TargetFilename"))}\nfrom {event.get("PreviousCreationUtcTime")} to {event.get("CreationUtcTime")}"
                    )
                )
            case 3:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"3 (Network Connection)\nRecordId:{recordId}\n{get_exe(event.get("Image"))}\nmade a network connection from\n{event.get("SourceIp")}:{event.get("SourcePort")} {event.get("SourceHostName")}\nto{event.get("DestinationIp")}:{event.get("DestinationPort")} {event.get("DestinationHostName")}\n({event.get("Protocol")})"
                    )
                )
            case 4:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"4 (Sysmon Service State Changed)\nRecordId:{recordId}\nSysmon service changed to: {event.get("State")}\n(version {event.get("Version")})"
                    )
                )
            case 5:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"5 (Process Terminated)\nRecordId:{recordId}\n{get_exe(event.get("Image"))} was terminated"
                    )
                )
            case 6:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"6 (Kernel Driver Loaded)\nRecordId:{recordId}\n{get_exe(event.get("Image"))} was loaded with signature\n{event.get("Signature")} ({event.get("SignatureStatus")})"
                    )
                )
            case 7:
                if before_process[0] == 7 and before_process[1] == event.get("Image"):
                    before_process[2].append(get_exe(event.get("ImageLoaded")))
                elif before_process[0] in [1,12,13]:
                    nodes.append(recordId)
                    dot, before_process = apply_before_process(before_process, dot)
                    before_process = (7, event.get("Image"), [get_exe(event.get("ImageLoaded"))], recordId)
                else:
                    nodes.append(recordId)
                    before_process = (7, event.get("Image"), [get_exe(event.get("ImageLoaded"))], recordId)
                    if i == 0:
                        dot, before_process = apply_before_process(before_process, dot)
            case 8:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"8 (Remote Thread)\nRecordId:{recordId}\n{get_exe(event.get("SourceImage"))}\ncreated a thread in the process\n{get_exe(event.get("TargetImage"))} (Process ID: {event.get("TargetProcessId")})"
                    )
                )
            case 9:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"9 (Raw Access Read)\nRecordId:{recordId}\n{get_exe(event.get("Image"))}\nconducted reading operations on\n{event.get("Device")} device"
                    )
                )
            case 10:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"10 (Process Access)\nRecordId:{recordId}\n{get_exe(event.get("SourceImage"))}\ncreated a thread on\n{get_exe(event.get("TargetImage"))} (Process ID: {event.get("TargetProcessId")})"
                    )
                )
            case 11:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"11 (File Create)\nRecordId:{recordId}\n{get_exe(event.get("Image"))}\ncreated the file\n{event.get("TargetFilename")}"
                    )
                )
            case 12:
                if before_process[0] == 12 and before_process[1] == f"{event.get("Image")}\nexecuted the event {event.get("EventType")} on the object\n":
                    before_process[2].append(event.get("TargetObject"))
                elif before_process[0] in [1,7,13]:
                    nodes.append(recordId)
                    dot, before_process = apply_before_process(before_process, dot)
                    before_process = (12, f"{event.get("Image")}\nexecuted the event {event.get("EventType")} on the object\n", [event.get("TargetObject")], recordId)
                else:
                    nodes.append(recordId)
                    before_process = (12, f"{event.get("Image")}\nexecuted the event {event.get("EventType")} on the object\n", [event.get("TargetObject")], recordId)
                    if i == 0:
                        dot, before_process = apply_before_process(before_process, dot)            
            case 13:
                if before_process[0] == 13 and before_process[1] == event.get("Image"):
                    before_process[2].append(event.get("TargetObject"))
                elif before_process[0] in [1,7,12]:
                    nodes.append(recordId)
                    dot, before_process = apply_before_process(before_process, dot)
                    before_process = (13, event.get("Image"), [event.get("TargetObject")], recordId)
                else:
                    nodes.append(recordId)
                    before_process = (13, event.get("Image"), [event.get("TargetObject")], recordId)
                    if i == 0:
                        dot, before_process = apply_before_process(before_process, dot)
            case 14:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"14 (Registry event (Key and value rename))\nRecordId:{recordId}\n{get_exe(event.get("Image"))}\nrenamed\n{event.get("TargetObject")}\nto {event.get("NewName")})"
                    )
                )
            case 15:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"15 (File create stream hash)\nRecordId:{recordId}\n{get_exe(event.get("Image"))}\ncreate the named file stream\n{event.get("TargetFilename")}"
                    )
                )
            case 16:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot) 
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"16 (Sysmon config state changed)\nRecordId:{recordId}\nSysmon configuration update ({event.get("Configuration")})"
                    )
                )
            case 17:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"17 (Pipe event (Pipe Created))\nRecordId:{recordId}\n{get_exe(event.get("Image"))} created pipe {event.get("PipeName")}"
                    )
                )
            case 18:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"18 (Pipe event (Pipe Connected))\nRecordId:{recordId}\n{get_exe(event.get("Image"))} created pipe {event.get("PipeName")}"
                    )
                )
            case 19:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"19 (WMI Event (WmiEventFilter activity detected))\nRecordId:{recordId}\nUser {event.get("User")} executed operation {event.get("Operation")}\nto create {event.get("Name")}"
                    )
                )
            case 20:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"20 (WMI Event (WmiEventConsumer activity detected))\nRecordId:{recordId}\nUser {event.get("User")} executed operation {event.get("Operation")}\nto create {event.get("Name")}"
                    )
                )
            case 21:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"21 (WMI Event (WmiEventConsumerToFiler activity detected))\nRecordId:{recordId}\nUser {event.get("User")} executed operation {event.get("Operation")}\nto create {event.get("Name")}"
                    )
                )
            case 22:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"22 (DNS)\nRecordId:{recordId}\n{get_exe(event.get("Image"))} executed DNS query\n{event.get("QueryName")} (status code {event.get("QueryStatus")})\nResulted in: {event.get("QueryResults")}"
                    )
                )
            case 23:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"23 (File Delete Event)\nRecordId:{recordId}\n{get_exe(event.get("Image"))} deleted file {event.get("TargetFilename")}"
                    )
                )
            case 24:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"24 (Clipboard Event)\nRecordId:{recordId}\n{get_exe(event.get("Image"))} added data to the clipboard.\nHashes: {event.get("Hashes")}"
                    )
                )
            case 25:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"25 (Process Tampering)\nRecordId:{recordId}\n{get_exe(event.get("Image"))} tampered (type {event.get("Type")}"
                    )
                )
            case 26:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"26 (File Delete Detected)\nRecordId:{recordId}\n{get_exe(event.get("Image"))} deleted file {event.get("TargetFilename")}."
                    )    
                )
            case _:
                if before_process[0] in [1,7,12,13]:
                    dot, before_process = apply_before_process(before_process, dot)
                nodes.append(recordId)
                dot.node(
                    str(recordId),
                    gv_escape(
                        f"{event.get("EventId")}({recordId})\nAt {event.get("TimeCreated")}"
                    )
                )
        i -= 1

    i = 0
    # Build edges
    dot.edge(parentProcess, str(nodes[0]))
    while i < len(nodes)-1:
        dot.edge(
            str(nodes[i]), 
            str(nodes[i+1])
            )
        i += 1

    dot.render(f"{res_path}/trace_results/{pid}_event_tree", format="png", view=False, cleanup=True)

# ========================================================================================

def apply_before_process(before_process, dot):
    sysmon_event_id = before_process[0]
    image = before_process[1]
    pars = before_process[2]
    recordId = before_process[3]
    s = ""
    match sysmon_event_id:
        case 1:
            for par in pars:
                # "image, image, image created by ..."
                s += f"{par}\n"
            dot.node(
                    str(recordId),
                    gv_escape(
                        f"1 (Process Create)\nRecordId:{recordId}{"+(...)" if len(pars)>1 else ""}\n{s}Created by\n{image}"
                    )
                )
        case 7:
            for par in pars:
                # "Image loaded ImageLoaded, ImageLoaded, ImageLoaded, ..."
                s += f"{par}\n"
            dot.node(
                str(recordId),
                gv_escape(
                    f"7 (Image Loaded)\nRecordId:{recordId}{"+(...)" if len(pars)>1 else ""}\n{image}\nloaded\n{s}"
                    )
                )
        case 12:
            for par in pars:
                # "Image executed the event X on the object par par par..."
                s += f"{par}\n"
            dot.node(
                str(recordId),
                gv_escape(
                        f"12 (Registry event (Object create and delete)\nRecordId:{recordId}{"+(...)" if len(pars)>1 else ""}\n{image}{s}"
                    )
                )
        case 13:
            for par in pars:
                # "Image modified the registry value of par par par..."
                s += f"{par}\n"
            dot.node(
                str(recordId),
                gv_escape(
                        f"13 (Registry event (Value Set)\nRecordId:{recordId}{"+(...)" if len(pars)>1 else ""}\n{image}\nmodified the registry value of\n{s}"
                    )
                )
    return dot, (0, "", [], 0)

# ========================================================================================

def gv_escape(s):
    if s is None:
        return ""

    return (
        str(s)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
    )

# ========================================================================================

def get_exe(image):
    if isinstance(image, list):
        image = image[-1] if image else ""  # usa o último valor visto
    pattern = r"\\[^\\]+\..*"
    if re.search(pattern, image):
        return re.search(pattern, image).group(0)[1:]
    return 1