import sys
import os
import json

def parse_line(line):
	words = line.split(",")
	return words[2], words[1] 

def calculate_average(labels_elapsed):
	res = {}
	for label, elapsed_array in labels_elapsed.items():
		if not label.startswith("SETUP"):
			t = 0
			for elapsed in elapsed_array:
				t += int(elapsed)
			r = round(t/(len(elapsed_array)*1000),3)
			res[label] = r

	res = dict(sorted(res.items()))
	for label, r in res.items():
		print(f"Label {label} has an average response time of {r}s.")
	return res

def request_metric_extractor(monitoring_option, trafficN):

	labels_elapsed = {}

	if trafficN == 0:
		directory = f"no_action-no_traffic/{monitoring_option}"
	else:
		directory = f"no_action-with_traffic/{monitoring_option}/traffic{trafficN}"

	for dirpath, dirnames, filenames in os.walk(directory):
		for f in filenames:
			if f.endswith(".jtl"):
				with open(f"{directory}/{f}", "r") as f:
					fileContent = f.read()
					fileLines = fileContent.split("\n")
					if fileLines[-1] != "":
						print("============================================")
						print(f"FOUND A PROBLEM WITH LAST LINE IN {str(f)}")
						print(fileLines[-1])
						print("============================================")
					fileLines = fileLines[1:][:-1]
					for fl in fileLines:
						label, elapsed = parse_line(fl)
						if label not in labels_elapsed:
							labels_elapsed[label] = [elapsed]
						else:
							labels_elapsed[label].append(elapsed) 

	avg_dict = calculate_average(labels_elapsed)

	with open(f"avg_times/{monitoring_option}_traffic{trafficN}.json","w") as f:
		json.dump(avg_dict, f)



if __name__ == "__main__":
	
	monitoring_option = sys.argv[1]
	trafficN = sys.argv[2]

	request_metric_extractor(monitoring_option, trafficN)
	"""
	line = "1789741301072,80,ACTION 3,200,OK,Action 3 - Check IP addresses 5-2,text,true,,227,156,2,62,http://localhost:8000/checkips?filename=ThreatReportSETUP_7,58,0,43"
	print(parse_line(line))
	
	# py request_matric_extractor.py "1789741301072,80,ACTION 3,200,OK,Action 3 - Check IP addresses 5-2,text,true,,227,156,2,62,http://localhost:8000/checkips?filename=ThreatReportSETUP_7,58,0,43"
	"""