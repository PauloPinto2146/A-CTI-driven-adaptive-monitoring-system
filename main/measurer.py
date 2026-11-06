import psutil
import matplotlib.pyplot as plt
import os
import json
import sys
import time
import re
import subprocess
import xml.etree.ElementTree as ET

from pathlib import Path
from dotenv import load_dotenv
from collections import Counter


# ======================================================================

# This module is built to measure the CPU, disk usage and log count

# ======================================================================

def get_sysmon_process():
    sysmon_processes = []
    for p in psutil.process_iter(['name']):
        if p.info['name'] and 'Sysmon' in p.info['name']:
            sysmon_processes.append(p)

    res_sysmon_process = sysmon_processes[0]
    for p  in sysmon_processes:
        if p.memory_info().rss > res_sysmon_process.memory_info().rss:
            res_sysmon_process = p
    
    return res_sysmon_process


def get_sysmon_cpu_seconds(processes):
    """Calcula a soma do tempo acumulado de CPU (User + System) em segundos de forma nativa."""
    total_seconds = 0.0
    for p in processes:
        try:
            times = p.cpu_times()
            total_seconds += (times.user + times.system)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return total_seconds

# ======================================================================

def measure_sysmon(seconds):
    num_cores = psutil.cpu_count()
    sysmon_process = get_sysmon_process()
    print(f"sysmon process being monitored: {sysmon_process.pid}")
    print(f"! STARTED SYSMON MONITORING !")
    print(f"--- Initialized CPU monitoring for {seconds} seconds---")

    cpu_usages = []
    system_cpu_usages = []
    memory_usages = []
    io_before = sysmon_process.io_counters()
    cpus_s_before = get_sysmon_cpu_seconds([sysmon_process])
    
    sysmon_process.cpu_percent(interval=None) # Avoid meaningless 0.0 value
    psutil.cpu_percent(interval=None)

    start_time = time.perf_counter()
    target_end_time = start_time + seconds

    cpu_stats_start = psutil.cpu_stats()

    it = 1

    for it in range(1, seconds +1):
    # for i in range(seconds):
        print("it = ", it)

        target_tick = start_time + it
    
        # 1 second intervals
        # It calculates the average between the CPU usage value in the start of the functiom call
        # and the CPU usage value in that same start time +1 second
        # "When interval is > 0.0 compares system CPU times elapsed before and after the interval (blocking)" - https://psutil.readthedocs.io/stable/ 
        cpu_usage = round(sysmon_process.cpu_percent(interval=None) / num_cores, 4)
        system_cpu_usage = psutil.cpu_percent(interval=None)
        mem_usage = sysmon_process.memory_info().private # The memory_info() function call is instantaneous
        print(mem_usage)

        cpu_usages.append(cpu_usage)
        memory_usages.append(mem_usage)
        system_cpu_usages.append(system_cpu_usage)
        print(f"({it:02d}s): {cpu_usage}% sysmon CPU usage")
        print(f"({it:02d}s): {system_cpu_usage}% system CPU usage", flush = True)

        sleep_needed = target_tick - time.perf_counter()
        if sleep_needed > 0:
            time.sleep(sleep_needed)
        it += 1

    end_time = time.perf_counter()
    actual_duration = end_time - start_time
    cpu_stats_end = psutil.cpu_stats()

    io_after = sysmon_process.io_counters()
    read_bytes = io_after.read_bytes - io_before.read_bytes
    write_bytes = io_after.write_bytes - io_before.write_bytes
    cpus_s_after = get_sysmon_cpu_seconds([sysmon_process])

    total_cpu_seconds_spent = cpus_s_after - cpus_s_before
    total_cpu_percent = (total_cpu_seconds_spent / seconds / num_cores) * 100

    samples_count = len(cpu_usages)
    cpu_average = total_cpu_seconds_spent / actual_duration * 100 / num_cores
    system_cpu_average = sum(system_cpu_usages) / samples_count
    mem_average = sum(memory_usages) / samples_count

    print("\n\n")
    print("-" * 40)
    print(f"Measurement concluded.")
    print(f"Sysmon CPU usage average per second: {cpu_average:.2f}%")
    print(f"System CPU usage average per second: {system_cpu_average:.2f}%")
    print(f"Memory average usage: {mem_average}B")

    print(f"Read bytes: {read_bytes}B")
    print(f"Write bytes: {write_bytes}B")
    
    print("-" * 20 + "Sysmon process" + "-" * 20)
    print(f"Cpu before (s): ", cpus_s_before)
    print(f"Cpu after (s): ", cpus_s_after)
    print(f"CPU(s) total: {total_cpu_seconds_spent:.2f} segundos")
    print(f"CPU(%) total : {total_cpu_percent:.6f}%")
    print("-" * 54)

    print("-" * 20 + "System" + "-" * 20)
    print(f"Cpu stats before: ", cpu_stats_start)
    print(f"Cpu stats after: ", cpu_stats_end)
    print("-" * 46)

    print("Time before: ", start_time)
    print(f"Time after: ", end_time)

    print("\n\n", flush = True)
    
    return cpu_average, cpu_usages, cpus_s_before, cpus_s_after, system_cpu_usages, system_cpu_average, mem_average, memory_usages, read_bytes, write_bytes, cpu_stats_start, cpu_stats_end

# ======================================================================

def save_plot(res_path, res_tag, type):
    plt.tight_layout()
    filepath = os.path.join(
        res_path,
        f"{res_tag}{type}_graphic.png"
    )
    plt.savefig(filepath)
    print(f"Saved comparisons in {filepath}")

def plot_CPU(res_path, res_tag, cpu_values, cpu_average, system_cpu_values, system_cpu_average):
    # Sysmon CPU plotting
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.plot(cpu_values, label="CPU usage", color="blue")
    ax.axhline(y=cpu_average, label="Average CPU usage", color="red")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Sysmon CPU (%)")
    ax.set_ylim(-10, 100)
    ax.legend()
    ax.set_title("Average CPU usage")

    save_plot(res_path, res_tag, "sysmon_cpu")

    # System CPU plotting
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.plot(system_cpu_values, label="CPU usage", color="blue")
    ax.axhline(y=system_cpu_average, label="Average CPU usage", color="red")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("System CPU (%)")
    ax.set_ylim(-10, 100)
    ax.legend()
    ax.set_title("Average CPU usage")

    save_plot(res_path, res_tag, "system_cpu")

def plot_logs(res_path, res_tag, log_count):
    fig, ax = plt.subplots(figsize=(12, 5))
    
    labels = []
    lc = []
    total_malware_logs = 0 # For the next graph
    i = 0

    for pid, count in log_count.items():
        # Differ the main process from child processes
        if i == 0:
            labels.append(f"{pid} (main)")
            i +=1
        else:
            labels.append(pid)
        lc.append(count) 
        total_malware_logs += count

    ax.bar(labels, lc)
    ax.set_title("Log Count Comparison")
    ax.set_ylabel("Number of Logs")
    ax.tick_params(axis='x', rotation=60)

    save_plot(res_path, res_tag, "log_count")
    return total_malware_logs

def plot_disk(res_path, res_tag, memory_usage_values, memory_average):
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.plot(memory_usage_values, label="Memory usage", color="blue")
    ax.axhline(y=memory_average, label="Average memory usage", color="red")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Memory usage")
    ax.legend()
    ax.set_title("Average memory usage")

    save_plot(res_path, res_tag, "memory")


def plot_log_comparison(res_path, res_tag, total_malware_logs, total_log_count):
    fig, ax = plt.subplots(figsize=(12, 5))
    
    ax.bar(
        [f"# Malware logs ({(total_malware_logs / total_log_count) * 100:.2f}%)", f"# Non-malware logs ({((total_log_count-total_malware_logs) / total_log_count)* 100:.2f}%)",], 
        [total_malware_logs, total_log_count-total_malware_logs]
    )
    ax.set_title("Log type Comparison")
    ax.set_ylabel("Logs")
    ax.tick_params(axis='x', rotation=90)

    save_plot(res_path, res_tag, "log_comparion")

# ==========================================

import subprocess
import xml.etree.ElementTree as ET
import json
import os
from collections import Counter


def extract_sysmon_stats(res_path, res_tag):
    print("Extracting sysmon logs...", flush=True)

    cmd = [
        "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
        "/f:xml",      # formato XML (o mesmo que "Save all events as XML")
        "/e:Events",   # envolve tudo num root <Events> para ser XML válido
        "/uni:true",   # força saída em Unicode (evita problemas de codepage)
    ]

    proc = subprocess.run(cmd, capture_output=True)

    if proc.returncode != 0:
        print(f"Erro ao correr o wevtutil: {proc.stderr.decode('utf-16', errors='replace')}", flush=True)

    logs_data = []
    if proc.stdout:
        try:
            # /uni:true produz saída UTF-16LE
            xml_text = proc.stdout.decode("utf-16")
            root = ET.fromstring(xml_text)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            for event in root.findall("e:Event", ns):
                obj = {}
                system = event.find("e:System", ns)
                if system is not None:
                    rec_id = system.find("e:EventRecordID", ns)
                    ev_id = system.find("e:EventID", ns)
                    time_created = system.find("e:TimeCreated", ns)

                    if rec_id is not None and rec_id.text:
                        obj["RecordId"] = int(rec_id.text) if rec_id.text.isdigit() else rec_id.text
                    if ev_id is not None and ev_id.text:
                        obj["EventId"] = int(ev_id.text) if ev_id.text.isdigit() else ev_id.text
                    if time_created is not None:
                        raw_time = time_created.attrib.get("SystemTime", "")
                        obj["TimeCreated"] = raw_time.split(".")[0].replace("T", " ") if raw_time else ""

                event_data = event.find("e:EventData", ns)
                if event_data is not None:
                    for data in event_data.findall("e:Data", ns):
                        name = data.attrib.get("Name")
                        if name:
                            obj[name] = data.text if data.text is not None else ""

                logs_data.append(obj)

        except ET.ParseError as e:
            print(f"Erro ao processar XML do Sysmon: {e}", flush=True)
    else:
        print("Nenhum evento Sysmon foi extraído.", flush=True)

    with open(os.path.join(res_path, f"{res_tag}sysmon_logs.json"), "w", encoding="utf-8") as f:
        json.dump(logs_data, f, indent=4, ensure_ascii=False)

    total_logs = len(logs_data)
    event_counter = Counter(event.get("EventId") for event in logs_data if event.get("EventId") is not None)

    res_stats = {}
    for event_id, count in sorted(event_counter.items(), key=lambda x: x[0]):
        percentage = round((count / total_logs) * 100, 2) if total_logs > 0 else 0
        res_stats[str(event_id)] = {"count": count, "percentage": percentage}

    with open(os.path.join(res_path, f"{res_tag}sysmon_stats.json"), "w", encoding="utf-8") as f:
        json.dump(res_stats, f, indent=4)

    print("Sysmon log extraction complete!", flush=True)

# ==========================================

def plot_measurements(log_data, seconds, res_path, res_tag):
    print("Entered plot_measurements", flush= True)
    load_dotenv()
    log_path = Path(os.getenv("SYSMON_EVTX"))

    os.makedirs(res_path, exist_ok=True)
    
    #Count the logs produced through powershell command
    command = [
        "powershell",
        "-Command",
        "(Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational').RecordCount"
        ]
    result = subprocess.run(command, capture_output=True, text=True)
    total_log_count = int(result.stdout.strip())

    log_size = log_path.stat().st_size
    print(f"Log size: {log_size / 1048476}MB ({log_size} bytes)", flush= True)
    print(f"Total log count: {total_log_count} logs", flush= True)

    # 4 graphs - CPU usage over time / Log count comparison / Comparison of logs from malware and not from malware / Byte count (write, read and disk)
    flag = False
    print("Plotting cpu usages...", flush= True)
    plot_CPU(res_path, res_tag, log_data.get("cpu_values"), log_data.get("cpu_average"), log_data.get("system_cpu_usages"), log_data.get("system_cpu_average"))
    # If not tracing the malware execution then no need for ploting no data
    if "log_count" in log_data:
        flag = True
        total_malware_logs = plot_logs(res_path, res_tag, log_data.get("malware_log_count"))
        plot_log_comparison(res_path, res_tag, total_malware_logs, total_log_count)
    print("Plotting disk usages...", flush= True)
    plot_disk(res_path, res_tag, log_data.get("memory_usages"), log_data.get("mem_average"))

    with open(f"{res_path}\\{res_tag}res.json", "w") as f:
        json.dump({
            "cpu_values": log_data.get("cpu_values"),
            "cpu_average": log_data.get("cpu_average"),
            "cpus_s_before": log_data.get("cpus_s_before"),
            "cpus_s_after":log_data.get("cpus_s_after"),
            "cpus_s_diff": log_data.get("cpus_s_after") - log_data.get("cpus_s_before"),
            "system_cpu_usages": log_data.get("system_cpu_usages"),
            "system_cpu_average": log_data.get("system_cpu_average"),
            "malware_log_count": log_data.get("malware_log_count") if flag else 0,
            "total_malware_logs": total_malware_logs if flag else 0,
            "total_log_count": total_log_count,
            "log_size": log_size,
            "memory_usages": log_data.get("memory_usages"), 
            "mem_average": log_data.get("mem_average"),
            "cpu_stats_start": log_data.get("cpu_stats_start"),
            "cpu_stats_end": log_data.get("cpu_stats_end")
            }, f, indent=4)

    extract_sysmon_stats(res_path, res_tag)