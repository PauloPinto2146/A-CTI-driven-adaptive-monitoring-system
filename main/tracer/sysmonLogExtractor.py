import subprocess
import json
import time

from datetime import datetime, timezone

# ========================================================================================

def extractor(process_id, exe_path, get_process_tree_bool):

	# process_id is the pid from each we want to extract info
	# exe_path is just for readability really
	# get_process_tree_bool is a boolean value to differentiate from when it is needed to extract the process tree or not
		# for example, we don't need the process tree from child processes, just the logs

	xpath_filter = f"*[EventData[Data[@Name='ProcessId']='{process_id}']]"

	print("Extracting sysmon log data...", flush = True)

	ps_script = (
		f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath \"{xpath_filter}\" | "
		f"ForEach-Object {{ "
		f"  $obj = [ordered]@{{ 'RecordId' = $_.RecordId; 'EventId' = $_.Id; 'TimeCreated' = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}; "
		f"  $xml = [xml]$_.ToXml(); "
		f"  $xml.Event.EventData.Data | ForEach-Object {{ $obj[$_.Name] = $_.'#text' }}; "
		f"  [PSCustomObject]$obj "
		f"}} | ConvertTo-Json -Depth 3"
	)

	print("Done extracting sysmon log data.", flush = True)

	res = subprocess.run(
		["powershell", "-Command", ps_script], 
		capture_output=True, 
		text=True, 
		encoding="cp850" 
	)

	if res.returncode == 0:
		output = res.stdout.strip()
		if not output:
			print(f"No sysmon event for process ID: {process_id}.")
			return

		try:
			logs_json = json.loads(output)

			if isinstance(logs_json, dict):
				logs_json = [logs_json]

			logs_json = filter_logs_by_process_guid(logs_json)

			if get_process_tree_bool:
				return logs_json, len(logs_json), get_process_tree(process_id, exe_path)
			else:
				return logs_json, len(logs_json), None

		except json.JSONDecodeError:
			try:
				logs_json = json.loads(f"[{output}]")
				print(json.dumps(logs_json, indent=4, ensure_ascii=False))
				return logs_json
			except Exception as e:
				print("Error while decofing JSON generated:", e)
				print(output)
				return
	else:
		# Most of the "errors" that I got are just pids that are not parents of any process
		print("\n--- Error ---")
		print(res.stderr)
		return

# ========================================================================================

def get_process_tree(pid, exe_path):
	# Breadth-First Search (BFS) 

	pids_to_analyse = [(pid, exe_path)]
	res_tree = {}
	while len(pids_to_analyse) > 0:
		# Expected entry is {pid: {"Image" : "C:\\..."}, "Children" : [pid1, pid2, ...]}

		# Get all the children value
		pid_to_analyse, image = pids_to_analyse.pop(0)
		c = get_child_pids(pid_to_analyse)
		if c:
			children_values = []
			for i, p in c:
				children_values.append(i) 
			
			res_tree[str(pid_to_analyse)] = {"Image": image, "Children": children_values}
			pids_to_analyse = c + pids_to_analyse
		else:
			res_tree[str(pid_to_analyse)] = {"Image": image, "Children": []}
		

	return res_tree

# ========================================================================================

def get_child_pids(pid):
	print(f" 			Getting child processes from {pid}...", flush = True)
	child_processes = []

	# Get all the processes which pid is the parent process
	xpath_filter = f"*[EventData[Data[@Name='ParentProcessId']='{pid}']]"
	ps_script = (
		f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath \"{xpath_filter}\" | "
		f"ForEach-Object {{ "
		f"  $obj = [ordered]@{{ 'RecordId' = $_.RecordId; 'EventId' = $_.Id; 'TimeCreated' = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}; "
		f"  $xml = [xml]$_.ToXml(); "
		f"  $xml.Event.EventData.Data | ForEach-Object {{ $obj[$_.Name] = $_.'#text' }}; "
		f"  [PSCustomObject]$obj "
		f"}} | ConvertTo-Json -Depth 3"
	)

	res = subprocess.run(
		["powershell", "-Command", ps_script], 
		capture_output=True, 
		text=True, 
		encoding="cp850" 
	)

	if res.returncode == 0:
		output = res.stdout.strip()
		if not output:
			print(f"No sysmon event for process ID: {process_id}.")
			return

		try:
			logs_json = json.loads(output)

			if isinstance(logs_json, dict):
				logs_json = [logs_json]
			for log in logs_json:
				res_pid = log.get("ProcessId")
				res_image = log.get("Image")

				child_processes.append((res_pid, res_image))

			return child_processes

		except json.JSONDecodeError:
			try:
				logs_json = json.loads(f"[{output}]")
				print(json.dumps(logs_json, indent=4, ensure_ascii=False))
				return logs_json
			except Exception as e:
				print("Error while decofing JSON generated:", e)
				print(output)
	else:
		print(f"\n------{pid}---")
		print(res.stderr.split("\n")[0])
		print("---------\n")


# ========================================================================================

def filter_logs_by_process_guid(logs_json):
	# There was a bug in the extractor which it captured reutilized pid's, so, to counter that this function
	#  captures the first log and the processguid, which is unique, even when the pid is reused
	process_guid = None

	if isinstance(logs_json, dict):
		
		len_before = 0
		len_total = 0

		res_logs_json = {}
		for pid, logs in logs_json.items():
			len_before += len(logs)
			logs = logs[::-1]
			for log in logs:
				if log.get("EventId") == 1:
					process_guid = log.get("ProcessGuid")
					break

			if process_guid is None:
				print("Could not find ProcessGuid from Event ID 1.")
				return []

			# Keep only logs associated with this exact process instance
			filtered_logs = [
				log for log in logs
				if log.get("ProcessGuid") == process_guid
			]
			res_logs_json[pid] = filtered_logs
			len_before += len(filtered_logs)

		diff_len = len_before - len(filtered_logs)


	else:
		len_before = len(logs_json)
		logs_json = logs_json[::-1]

		for log in logs_json:
			if log.get("EventId") == 1:
				process_guid = log.get("ProcessGuid")
				break

		if process_guid is None:
			print("Could not find ProcessGuid from Event ID 1.")
			return []


		# Keep only logs associated with this exact process instance
		res_logs_json = [
			log for log in logs_json
			if log.get("ProcessGuid") == process_guid
		][::-1]

		diff_len = len_before - len(res_logs_json)
	print(f"Removed {diff_len} logs that were having its pid reused")
	with open("logs_json.json", "w") as f:
		json.dump(logs_json, f, indent = 4)
	with open("res_logs_json.json", "w") as f:
		json.dump(res_logs_json, f, indent = 4)
	return res_logs_json

# ========================================================================================
