import sys
import os
import json
from statistics import mean, stdev

from dotenv import load_dotenv


def average_sysmon_stats(stats_array):
	"""
	Recebe uma lista com um dicionário de stats por run
	({event_id: {"count": int, "percentage": float}}) e devolve, para cada EventId,
	a média e o desvio-padrão do count e da percentage.
	Um EventId que não aparece numa run conta como 0 nessa run.
	"""
	event_ids = sorted({eid for run in stats_array for eid in run}, key=int)

	def summarize(values):
		return {
			"mean": round(mean(values), 4),
			"std": round(stdev(values), 4) if len(values) > 1 else 0.0,
		}

	events = {}
	for eid in event_ids:
		counts = [run.get(eid, {}).get("count", 0) for run in stats_array]
		percentages = [run.get(eid, {}).get("percentage", 0) for run in stats_array]
		events[eid] = {
			"count": summarize(counts),
			"percentage": summarize(percentages),
			"runs_present": sum(1 for run in stats_array if eid in run),
		}

	return {"n_runs": len(stats_array), "events": events}


def print_data_for_excel(monitoring_option, trafficN, misp_event_id, malware):
	load_dotenv()
	res_path = os.getenv("RES_PATH")

	if trafficN == 0:
		traffic_option = "Idle"
	elif trafficN == 1:
		traffic_option = "Moderate"
	elif trafficN == 2:
		traffic_option = "Stressed"

	end_of_dir = ""
	if monitoring_option == "MISP":
		end_of_dir = f"\\{misp_event_id}"

	full_path = res_path + f"\\{monitoring_option}" + f"\\{traffic_option}" + end_of_dir
	stats_array = []
	for i in range(1, 11):
		file_path = full_path + f"\\run{i}\\run{i}_res.json"
		with open(file_path, "r") as f:
			d = json.load(f)
			print(f"RUN {i}")
			print("-------------------------------")
			print(str(d.get("system_cpu_average")).replace(".", ",") + "%")
			print(str(d.get("cpus_s_diff")).replace(".", ","))
			print(str(d.get("mem_average")).replace(".", ","))
			print(str(d.get("log_size")).replace(".", ","))
			print(str(d.get("total_log_count")).replace(".", ","))
			print("\n")

		stats_path = full_path + f"\\run{i}\\run{i}_sysmon_stats.json"
		with open(stats_path, "r") as f:
			stats_array.append(json.load(f))

	avg_stats = average_sysmon_stats(stats_array)
	out_path = os.path.join(full_path, "avg_sysmon_stats.json")
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(avg_stats, f, indent=4)
	print(f"Saved averaged sysmon stats in {out_path}")


if __name__ == "__main__":
	monitoring_option = sys.argv[1]
	trafficN = sys.argv[2]
	misp_event_id = sys.argv[3]
	malware = sys.argv[4]

	print_data_for_excel(monitoring_option, int(trafficN), int(misp_event_id), int(malware))