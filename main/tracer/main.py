import subprocess
import time 
import json
import sys
import re
import psutil
import os

from datetime import datetime 
from .sysmonLogExtractor import extractor
from .graph_maker import make_graph
from .tracer import trace

# ========================================================================================

def print_time_it_took(init_time, final_time, string):
    duration = final_time - init_time
    total_seconds = int(duration.total_seconds())
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    print(f"Time it took: {minutes} minutes and {seconds} seconds ({string}).")

# ========================================================================================

def kill_pid(pid_str):
    try:
        psutil.Process(int(pid_str)).kill()
    except (psutil.NoSuchProcess, ValueError):
        pass  # If it is dead leave it

# ========================================================================================

def trace_main(exe_path, time_to_sleep, res_path):

    return_dict = {}

    # 1. Run the desired process
    process = subprocess.Popen(
        exe_path
    )
    # 1.1. Store the PID
    pid = str(process.pid)
    
    try:
        # 1.2 Wait a minute to let the .exe do some things
        print(f"Process in execution for {time_to_sleep} seconds...")
        time.sleep(time_to_sleep)

        # 3. Collect the logs where PID is the main process and the parent process
        res = extractor(pid, exe_path, True)
        if res:
            logs_json, total_pid_logs, process_tree = res
        else:
            return
        print(process_tree)
        print(f"Number of the main process ({pid}) logs: {total_pid_logs}.")
        malware_log_count = {}
        malware_log_count[pid] = total_pid_logs

        # 4. Get the child log info
        child_processes_logs = {}
        number_cp_logs = 0
        if process_tree and len(process_tree) > 1:
            for cp in process_tree:
                if cp == str(pid): # Ignore the parent process
                    continue
                cp_logs, cp_count, _ = extractor(cp, process_tree[cp].get("Image"), False)
                child_processes_logs[cp] = cp_logs
                number_cp_logs += len(cp_logs)
                print(f"Child process {cp} has {len(cp_logs)} logs.")
                malware_log_count[cp] = len(cp_logs)
        else:
            print(f"Process {pid} does not have any child process.")


    finally:
        # 5. Stop the processes (main and child processes)
        print("\nStopping main process and its child tree...")
        all_pids = set(process_tree.keys()) if 'process_tree' in dir() else {pid}
        for p in all_pids:
            kill_pid(p)


    # 6. Document all the results
    return_dict["malware_log_count"] = malware_log_count

    total_logs = total_pid_logs + number_cp_logs
    if total_logs > 0:
        child_pct = f"{100 * number_cp_logs / total_logs:.2f}"
    else:
        child_pct = "N/A"

    print("==============================================")
    print(f"Total logs from main malware process {pid}: {total_pid_logs}")
    print(f"Total logs from malware child processes: {number_cp_logs}")
    print(f"Total malicious logs : {total_logs} ({child_pct}% of logs are from child processes)")
    print("==============================================")

    # 6.1. Store the results in a .json file
    os.makedirs(res_path, exist_ok=True)
    with open(os.path.join(res_path, f"{pid}_main_process.json"), "w") as f:
        json.dump(logs_json, f, indent=4)
    with open(os.path.join(res_path, f"{pid}_child_processes.json"), "w") as f:
        json.dump(child_processes_logs, f, indent=4)

    # 6.2. Build the process trees (the trace of each one and the child process tree)
    print("process_tree = ", process_tree)

    print("\nTracing main process ", str(pid)+"...")
    trace(logs_json, pid, "main.py", res_path)
    print("\nTracing child processes...")
    for child_pid, child_activity in child_processes_logs.items():
        trace(child_activity, child_pid, get_exe(child_activity[len(child_activity)-1].get("ParentImage"), child_pid), res_path)
    print("\n Producing process tree...")
    make_graph(process_tree, pid, res_path)
    print("\n Tracing done!")

    return return_dict

# ========================================================================================

def get_exe(image, child_pid):
    print(f"get_exe received: {image}")
    if isinstance(image, list):
        image = image[-1] if image else ""  # usa o último valor visto
    if isinstance(image, str):
        pattern = r"\\[^\\]+\..*"
        if re.search(pattern, image):
            return re.search(pattern, image).group(0)[1:]
    return str(child_pid)

if __name__ == "__main__":
    exe_path = sys.argv[1]
    seconds = sys.argv[2]
    res_path = sys.argv[3]
    trace_main(exe_path, int(seconds), res_path)