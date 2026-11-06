import json
import os
import subprocess
import xml.etree.ElementTree as ET
import sys
import time

from concurrent.futures import ProcessPoolExecutor
from dotenv import load_dotenv
from utils import mark_time, print_time_it_took
from measurer import measure_sysmon, plot_measurements
from sysmon_utils import apply_config_file, clear_sysmon_logs


def main(seconds, monitoring_option, misp_event_id, malware_exe, res_path, res_tag):
	load_dotenv()
	cm = os.getenv("CONFIG_MAKER_PATH")
	
	# First of all make sure nothing is getting logged and clean everything
	apply_config_file("Nothing")
	clear_sysmon_logs()

	init_time_total = mark_time()


	match monitoring_option:
		case "All":
			# Monitor everything
			apply_config_file("All")
		case "Nothing":
			# Monitor nothing
			apply_config_file("Nothing")
		case "Default":
			# Monitor with default settings of sysmon
			apply_config_file("Default")
		case "MISP":
			
			# =======================
			# 0. Get MISP threat report
			# =======================
			load_dotenv()
			file_path = os.path.join(os.getenv("CASE_STUDIES_PATH"), f"misp.event.{misp_event_id}.json") 
			
			with open(file_path, "r", encoding="utf-8") as f:
				misp_event_data = json.load(f)
			
			ioc_extraction_file = f"execution_results_{misp_event_id}_dissertation/ioc_extraction_{misp_event_id}.json"
			if not os.path.exists(ioc_extraction_file):
				print("Did not find IoC extraction file, running IoC extraction builder...")

				# ===============
				# 1. IOC EXTRACTOR
				# ===============
				try:
					from step1_indicator_extractor import get_misp_data
					init_misp_process_time = mark_time()

					ioc_extraction = get_misp_data(misp_event_data)

					with open(ioc_extraction_file, "w") as f:
						json.dump(ioc_extraction, f, indent = 4)
					
					final_misp_process_time = mark_time()
					print_time_it_took(init_misp_process_time, final_misp_process_time, "extracting IoCs")
				except Exception as e:
					print(f"Error while getting MISP threat data: {e}")
			else:
				print("Found IoC extraction file file, retrieving it...")
				with open(ioc_extraction_file, "r") as f:
					ioc_extraction = json.load(f)
				print("(Skipped IoC extraction)\n")
				
			# ===============
			# 2. CONTEXT BUILDER
			# ===============
			context_file = f"execution_results_{misp_event_id}_dissertation/context_built_{misp_event_id}.json"
			if not os.path.exists(context_file):
				try:
					from step2_0_context_builder import build_context_dict
					
					init_context_time = mark_time()
					context_dict = build_context_dict(ioc_extraction)

				except Exception as e:
					print(f"Error while creating context: {e}")
					return 0
				final_context_time = mark_time()
				print_time_it_took(init_context_time, final_context_time, "building context")
				with open(context_file, "w") as f:
					json.dump(context_dict, f, indent = 4)
			else:
				print("Found context file, retrieving it...")
				with open(context_file, "r") as f:
					context_dict = json.load(f)
				print("(Skipped context gathering)")

			# ======================================
			# 3. MONITORING CONFIGURATION GENERATOR
			# ======================================
			
			sysmon_snippets_file = f"execution_results_{misp_event_id}_dissertation/sysmon_snippets_{misp_event_id}.json"
			if not os.path.exists(sysmon_snippets_file):
				sysmon_snippets = []
				try:
					from step3_0_monitoring_configuration_generator import produce_sysmon_snippets
					init_llm_time = mark_time()
					sysmon_snippets = produce_sysmon_snippets(context_dict, misp_event_id)
					final_llm_time = mark_time()
					print_time_it_took(init_llm_time, final_llm_time, "LLM")
				except Exception as e:
					print(f"Error while calling the LLM model: {e}")
					return 0
			else:
				with open(sysmon_snippets_file, "r", encoding="utf-8") as f:
					sysmon_snippets = json.load(f)
					print("(Skipped LLM call)")
			# =======================================
			# 4. Aggregator
			# =======================================

			from step4_aggregator import aggregator
			valid_signal = aggregator(sysmon_snippets, misp_event_id, context_dict["sysmon_hash_algorithms_to_consider"])

			print("valid_signal from aggregator is ", valid_signal)

			if not valid_signal:
				print("Error in aggregator.")
				return

			final_time_total = mark_time()
			print_time_it_took(init_time_total, final_time_total, "whole process")

		case _:
			print(f"Error: {monitoring_option} is not a valid monitoring option.")
			return 0

	# Tracing
	if malware_exe.startswith("C:\\"):
		from tracer.main import trace_main

		# Fires up trace_main and measure_sysmon in paralel
		with ProcessPoolExecutor(max_workers=2) as executor:
			future_log_data = executor.submit(trace_main, [malware_exe], seconds, res_path)
			future_sysmon_data = executor.submit(measure_sysmon, seconds)

			log_data = future_log_data.result()
			cpu_average, cpu_usages, cpus_s_before, cpus_s_after, system_cpu_usages, system_cpu_average, mem_average, memory_usages, read_bytes, write_bytes, cpu_stats_start, cpu_stats_end = future_sysmon_data.result()

		subprocess.run(["python", cm, "Nothing"])
	else:
		cpu_average, cpu_usages, cpus_s_before, cpus_s_after, system_cpu_usages, system_cpu_average, mem_average, memory_usages, read_bytes, write_bytes, cpu_stats_start, cpu_stats_end = measure_sysmon(seconds)
		subprocess.run(["python", cm, "Nothing"])
	
	log_data = {}
	log_data["cpu_values"] = cpu_usages
	log_data["cpu_average"] = cpu_average

	log_data["cpus_s_before"] = cpus_s_before
	log_data["cpus_s_after"] = cpus_s_after

	log_data["system_cpu_usages"] = system_cpu_usages
	log_data["system_cpu_average"] = system_cpu_average

	log_data["memory_usages"] = memory_usages
	log_data["mem_average"] = mem_average

	log_data["read_bytes"] = read_bytes
	log_data["write_bytes"] = write_bytes

	log_data["cpu_stats_start"] = cpu_stats_start
	log_data["cpu_stats_end"] = cpu_stats_end
	
	plot_measurements(log_data, seconds, res_path, res_tag)
	return 1

if __name__ == "__main__":

	"""
	How to run:
	main.py <seconds> <MonitoringOption> <MISP_Event_ID> <malware_exe> <res_dir_path> <res_tag>

	Option:
	1. "All" monitoring configuration
	2. "Empty" configuration
	3. "MISP" configuration
	4. "Default" configuration
	"""
	seconds = int(sys.argv[1])
	monitoring_option = sys.argv[2]
	misp_event_id = sys.argv[3]
	malware_exe = sys.argv[4]
	res_path = sys.argv[5]
	res_tag = sys.argv[6]


	res = 0
	times_failed = 0

	while res == 0:
		res = main(seconds, monitoring_option, misp_event_id, malware_exe, res_path, res_tag)
		if res == 0:
			print("The process failed.")
			times_failed += 1
			break

	print(f"Monitoring process suceeded.", flush = True)