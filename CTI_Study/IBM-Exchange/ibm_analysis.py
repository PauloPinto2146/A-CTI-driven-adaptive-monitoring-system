import json
import os
from collections import Counter
import re

directory_str = "/home/paulopinto2146/IBM-exchange/manual_extraction"
directory = os.fsencode(directory_str)
    
objects = []

if not os.path.exists("ibm_all.json"):
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        if filename.endswith(".json"): 
            with open(os.path.join(directory_str, filename)) as json_file:
                data = json.load(json_file)
                objects.extend(data.get("objects", []))
        else:
            print("Found a non-json file: " + filename)
        print(f"File: {filename} - Total items: {len(objects)}")
        with open("ibm_all.json", "w", encoding="utf-8") as f:
            json.dump({"objects": objects}, f, ensure_ascii=False, indent=4)
        
file = "ibm_all.json"

def remove_duplicates():
    counter = Counter()
    write_objects = []
    processed_items = 0
    print(f"Removing duplicates from {file} file...")
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            processed_items += 1
            if "id" in obj:
                counter[obj["id"]] += 1
                if counter[obj["id"]] == 1:
                    print("Adding object with ID: ", obj["id"])
                    write_objects.append(obj)
                else:
                    print("Duplicate found with ID: ", obj["id"])  
            with open("ibm_no_dups.json", "w", encoding="utf-8") as f:
                json.dump({"objects": write_objects}, f, ensure_ascii=False, indent=4)
    print(f"Total items processed: {sum(counter.values())}")
    print(f"Total unique items: {len(counter)}")
    print(f"Total duplicate items removed: {len(write_objects) - len(counter)}")


def print_percentage():
    counter = Counter()
    total_length = 0
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            total_length += 1
            counter[obj.get("type")] += 1
    sorted_counter = counter.most_common()
    for obj, count in sorted_counter: 
        print(f"{obj} : {count} ( {count/total_length:.2%} )")
    print("Total items: ", total_length)

def print_percentage_params():
    obj_type = input("Which object type do you want to analyze? ")
    counter_params = Counter()
    total_length = 0
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if obj.get("type") == obj_type:
                total_length += 1
                for key in obj.keys():
                    counter_params[key] += 1
    if sum(counter_params.values()) == 0:
        print(f"No parameters found for object type '{obj_type}'.")
    else:
        for obj in counter_params:
            print(f"{obj} : {counter_params[obj]} ( {counter_params[obj]/total_length:.2%} )")
        print("Total items: ", total_length)

def print_value_all_frequency():
    parameter_type = input("Which parameter do you want to analyze? ")
    counter_params = Counter()
    total_length = 0
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if parameter_type in obj:
                if isinstance(obj[parameter_type], dict):
                    for item in obj[parameter_type].values():
                        print("In isitance(dicy): ", item)
                        counter_params[item] += 1
                        total_length += 1
                elif isinstance(obj[parameter_type], list):
                    for item in obj[parameter_type]:
                        if isinstance(item, dict):
                            item = item.get("phase_name") or str(item)
                        counter_params[item] += 1
                        total_length += 1
                else:
                    counter_params[obj[parameter_type]] += 1
                    total_length += 1
    sorted_counter = counter_params.most_common()
    for obj in sorted_counter:
        print(f"{obj[0]} : {obj[1]} ( {obj[1]/total_length:.2%} )")
    print("Total items: ", total_length)

def print_value_by_type_frequency():
    parameter_type = input("Which parameter do you want to analyze? ")
    type_obj = input("From which object type do you want to analyze? ")
    counter_params = Counter()
    total_length = 0
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if obj.get("type") == type_obj and parameter_type in obj:
                if isinstance(obj[parameter_type], list):
                    for item in obj[parameter_type]:
                        if isinstance(item, dict):
                            item = item.get("phase_name") or str(item)
                        counter_params[item] += 1
                        total_length += 1 
                elif isinstance(obj[parameter_type], dict):
                    for item in obj[parameter_type].values():
                        counter_params[item] += 1
                        total_length += 1
                else:
                    counter_params[obj[parameter_type]] += 1
                    total_length += 1
    sorted_counter = counter_params.most_common()
    for obj in sorted_counter:
        print(f"{obj[0]} : {obj[1]} ( {obj[1]/total_length:.2%} )")
    print("Total items: ", total_length)

def countIDs():
    total_length = 0
    repeated_ids = 0
    counter_ids = Counter()
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            total_length += 1
            if "id" in obj:
                counter_ids[obj["id"]] += 1
    dups = 0
    unique_ids = []
    dup_ids = []
    for id, count in counter_ids.items():
        if count > 1:
            dup_ids.append(id)
            repeated_ids += (count - 1)
            #print(f"{id} : {count}")
        else:
            unique_ids.append(id)
    print(f"IDs that appear only once: {len(unique_ids)}")
    print(f"Total unique items: {total_length - repeated_ids}")
    print(f"Total duplicate IDs: {repeated_ids}")
    print(f"Total items processed: {total_length}")

import ijson
import json

def writeTypeToFile():
    obj_type = input("Which object type do you want to write to file? ")
    filtered_objects = []
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if obj.get("type") == obj_type:
                filtered_objects.append(obj)
    file_name = file.split(".")[0]
    print("File name:", file_name)
    with open(f"{file_name}_{obj_type}.json", "w", encoding="utf-8") as f:
        json.dump(filtered_objects, f, ensure_ascii=False, indent=4)

    print(f"{len(filtered_objects)} objects of type '{obj_type}' were written to {obj_type}.json")

def getFrequencyByYear():
    counter = Counter()
    total_length = 0
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if "modified" in obj:
                total_length += 1
                modified_date = obj.get("modified")
                year = modified_date.split("-")[0]
                counter[year] += 1
    sorted_counter = counter.most_common()
    for obj, count in sorted_counter: 
        print(f"{obj} : {count} ( {count/total_length:.2%} )")
    print("Total items: ", total_length)


def diff_dates():
    total_length = 0
    
    dont_have_dates = 0
    created_equal_modified = 0
    created_diff_modified = 0

    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if "created" in obj and "modified" in obj:
                total_length += 1
                if obj["created"] == obj["modified"]:
                    created_equal_modified += 1
                else:
                    created_diff_modified += 1
            else:
                total_length += 1
                dont_have_dates += 1
    print(f"Total items: {total_length}")
    print(f"Items with created and modified dates: {total_length - dont_have_dates}")
    print(f"Items with equal created and modified dates: {created_equal_modified}")
    print(f"Items with different created and modified dates: {created_diff_modified}")

def count_external_references():
    ref_count = {}
    ref_count_url = {}
    
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if obj.get("external_references"):
                ex_ref_obj = obj.get("external_references")
                for ex_ref in ex_ref_obj:

                    if ex_ref.get("external_id") in ref_count_url:
                        ref_count[ex_ref.get("external_id")] += 1
                    else:
                        ref_count[ex_ref.get("external_id")] = 1

                    if ex_ref.get("url"):
                        if ex_ref.get("url") in ref_count_url:
                            ref_count_url[ex_ref.get("url")] += 1
                        else:
                            ref_count_url[ex_ref.get("url")] = 1
    not_unique_count = 0
    for elem in ref_count:
        print(f"{elem} : {ref_count[elem]}")
        not_unique_count += ref_count[elem]
    not_unique_count_url = 0
    for elem in ref_count_url:
        print(f"{elem} : {ref_count_url[elem]}")
        not_unique_count += ref_count_url[elem]

    
    print("ref_count: ", len(ref_count))
    print("not_unique_count: ", not_unique_count)
    print("ref_count_url: ", len(ref_count_url))
    print("not_unique_count_url: ", not_unique_count_url)

"""

Os padrões de indicadores são:

SCO:parâmetro = ...
Por sua vez o parâmetro pode também ser um SCO que tem parâmetros, e.g.:
    network-traffic:dst_ref.type = 'ipv4-addr'
O SCO principal é network-traffic que tem o parâmetro de dst_ref que por sua vez tem um tipo de ipv4

"""

def indicator_pattern_stats():
    
    total_length = 0
    counter = Counter()

    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")

        for obj in objects:
            if obj["type"] == "indicator":
                matches = re.findall(r"([a-z0-9\-]+:[\w\.]+)\s*=", obj["pattern"])
                for m in matches:
                    counter[m] += 1
                    total_length += 1

    sorted_counter = counter.most_common()
    print("Field usage:")
    for pat, count in sorted_counter:
        print(f"    {pat} : {count} ({count/total_length:.2%})")
    print(f"Total indicator patterns: {total_length}\n")
    for pat, count in sorted_counter:
        print(pat)
    for pat, count in sorted_counter:
        print(count)

input_string = """
Which function do you want to run? (1-8)

1. Remove duplicates
2. Print percentage of each object type
3. Print percentage of parameters for a specific object type
4. Print frequency of values for a specific parameter
5. Print frequency of values for a specific parameter by object type
6. Count unique and duplicate IDs
7. Write objects of a specific type to a new file
8. Know the dates of the reports
9. Analyse indicator patterns
10. Count external references

"""


x = input(input_string)

if x == "1":
    remove_duplicates()
elif x == "2":
    print_percentage()
elif x == "3":
    print_percentage_params()
elif x == "4":
    print_value_all_frequency()
elif x == "5":
    print_value_by_type_frequency() 
elif x == "6":
    countIDs()
elif x == "7":
    writeTypeToFile()
elif x == "8":
    getFrequencyByYear()
elif x == "9":
    indicator_pattern_stats()
elif x == "10":
    count_external_references()
else:
    print("Invalid option. Please enter a number between 1 and 7.")