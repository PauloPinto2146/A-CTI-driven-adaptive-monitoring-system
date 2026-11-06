import ijson
import json
import re
from collections import Counter

def remove_duplicates():
    counter = Counter()
    write_objects = []
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if "id" in obj:
                counter[obj["id"]] += 1
                if counter[obj["id"]] == 1:
                    write_objects.append(obj)
        with open("misp_1000_events_no_duplicates.json", "w", encoding="utf-8") as f:
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
    print("Total indicator patterns: ", total_length)
    for pat, count in sorted_counter:
        print(pat)
    for pat, count in sorted_counter:
        print(count)

def find_value():
    value = input("Which value you want to see? ")
    filtered_objects = []
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            for parameter in obj:
                if obj[parameter] == value:
                    filtered_objects.append(obj)
    print(f"{len(filtered_objects)} objects were found with that value:")
    for obj in filtered_objects:
        print(json.dumps(filtered_objects, indent=4) + "\n")

def count_external_references():
    ref_count = {}
    ref_count_url = {}
    
    with open(file, "rb") as f:
        objects = ijson.items(f, "objects.item")
        for obj in objects:
            if obj.get("external_references"):
                ex_ref_obj = obj.get("external_references")
                for ex_ref in ex_ref_obj:
                    if ex_ref.get("external_id") in ref_count:
                        ref_count[f"{ex_ref.get("source_name")}+{ex_ref.get("external_id")}"] += 1
                    else:
                        ref_count[f"{ex_ref.get("source_name")}+{ex_ref.get("external_id")}"] = 1
                    if ex_ref.get("url"):
                        if ex_ref.get("url") in ref_count_url:
                            ref_count[f"{ex_ref.get("source_name")}+{ex_ref.get("url")}"] += 1
                            ref_count_url[ex_ref.get("url")] += 1
                        else:
                            ref_count[f"{ex_ref.get("source_name")}+{ex_ref.get("url")}"] = 1
                            ref_count_url[ex_ref.get("url")] = 1
    not_unique_count = 0
    for elem in ref_count:
        print(f"{elem} : {ref_count[elem]}")
        not_unique_count += ref_count[elem]
    not_unique_count_url = 0
    for elem in ref_count_url:
        print(f"{elem} : {ref_count_url[elem]}")
        not_unique_count_url += ref_count_url[elem]

    
    print("ref_count: ", len(ref_count))
    print("not_unique_count: ", not_unique_count)
    print("ref_count_url: ", len(ref_count_url))
    print("not_unique_count_url: ", not_unique_count_url)
            

input_string_1 = """
Which file to operate on? \n
    1. stix2_30d.json \n
    2. misp_1000_events_no_duplicates.json \n
    3. stix2_90d.json \n
"""

input_string_2 = """
Which statistic do you want to see? \n 
    1. Frequency of each object type \n 
    2. Frequency of parameters of a specific object type \n 
    3. Frequency values of a given parameter \n 
    4. Frequency of values of a given parameter and type\n 
    5. Count IDs \n 
    6. Write object type to file\n
    7. Get frequency of objects by year \n
    8. Get frequency of items with created and modified dates equal or different \n
    9. Analyse indicator patterns\n
    10. Find objects with specific value \n
    11. Count external references \n
"""

x1 = input(input_string_1)

if x1 == "1":
    file = "stix2_30d.json"
elif x1 == "2":
    file = "misp_1000_events_no_duplicates.json"
elif x1 == "3":
    file = "stix2_90d.json"

x2 = input(input_string_2)

if x2 == "1":
    print_percentage()
elif x2 == "2":
    print_percentage_params()
elif x2 == "3":
    print_value_all_frequency()
elif x2 == "4":
    print_value_by_type_frequency()
elif x2 == "5":
    countIDs()
elif x2 == "6":
    writeTypeToFile()
elif x2 == "7":
    getFrequencyByYear()
elif x2 == "8":
    diff_dates()
elif x2 == "9":
    indicator_pattern_stats()
elif x2 == "10":
    find_value()
elif x2 == "11":
    count_external_references()
        
else:
    print("Invalid input. Please enter 1, 2, 3, 4, 5, 6, or 7.")

