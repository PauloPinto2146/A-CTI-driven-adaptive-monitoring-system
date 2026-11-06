from urllib.parse import urlencode 
from urllib.request import Request, urlopen
import json
import datetime
import os

url			= 'https://vuldb.com/?api'
API_key		= os.getenv('API_KEY')

def day_month_year():
    now = datetime.datetime.now()

    year = now.year
    month = now.month
    day = now.day
    hour = now.hour
    minute = now.minute

    return [day, month, year, hour, minute]

def fetch_recent_vulnerabilities(recent_quantity, detail_value):
    
    if int(recent_quantity) > 7:
        print("Maximum vulnerability query limit is 7")
        recent_quantity = "7"
    
    post_fields	= { 'apikey': API_key, 'recent': recent_quantity, 'details': detail_value}

    if detail_value == "1":
        print("It is detailed")
        detail_string = "detailed"
    elif detail_value == "0":
        print("It is not detailed")
        detail_string = "not_detailed"
    else:
        raise ValueError("detail_value must be '0' or '1'")

    request = Request(url, urlencode(post_fields).encode())
    json_content = urlopen(request).read().decode()

    data = json.loads(json_content)

    [day, month, year, hour, minute] = day_month_year()
    date_string = f"{year}-{month}-{day}_{hour}h{minute}"

    with open(f"{recent_quantity}_recent_vulnerabilities_{detail_string}_{date_string}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def fetch_CTI(activitiestop_value, detail_value):
    
    if int(activitiestop_value) > 50:
        print("Maximum cti query limit is 50")
        activitiestop_value = "50"

    post_fields	= { 'apikey': API_key, 'activitiestop': activitiestop_value, 'details': detail_value, 'cti': 1}

    if detail_value == "1":
        print("It is detailed")
        detail_string = "detailed"
    elif detail_value == "0":
        print("It is not detailed")
        detail_string = "not_detailed"
    else:
        raise ValueError("detail_value must be '0' or '1'")

    request = Request(url, urlencode(post_fields).encode())
    json_content = urlopen(request).read().decode()

    data = json.loads(json_content)

    [day, month, year, hour, minute] = day_month_year()
    date_string = f"{year}-{month}-{day}_{hour}h{minute}"

    with open(f"{activitiestop_value}_recent_cti_{detail_string}_{date_string}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def fetch_events(events_value, detail_value):

    if int(events_value) > 10:
        print("Maximum event query limit is 10")
        events_value = 10

    post_fields	= { 'apikey': API_key, 'events': events_value, 'details': detail_value}

    if detail_value == "1":
        print("It is detailed")
        detail_string = "detailed"
    elif detail_value == "0":
        print("It is not detailed")
        detail_string = "not_detailed"
    else:
        raise ValueError("detail_value must be '0' or '1'")

    request = Request(url, urlencode(post_fields).encode())
    json_content = urlopen(request).read().decode()

    data = json.loads(json_content)

    [day, month, year, hour, minute] = day_month_year()
    date_string = f"{year}-{month}-{day}_{hour}h{minute}"

    with open(f"{events_value}_recent_events_{detail_string}_{date_string}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


input_string_1 = """
Which type of request? \n
    1. Recent vulnerabilities\n
    2. CTI\n
    3. Events \n
"""

x = input(input_string_1)

if x == "1":
    input_string_2 ="How many? "
    recent_value = input(input_string_2)
    input_string_3 = "Detailed, 0 or 1? "
    detail_value = input(input_string_3)
    fetch_recent_vulnerabilities(recent_value, detail_value)
elif x == "2":
    input_string_2 ="How many? "
    activitiestop_value = input(input_string_2)
    input_string_3 = "Detailed, 0 or 1? "
    detail_value = input(input_string_3)
    fetch_CTI(activitiestop_value, detail_value)
elif x == "3":
    input_string_2 ="How many? "
    events_value = input(input_string_2)
    input_string_3 = "Detailed, 0 or 1? "
    detail_value = input(input_string_3)
    fetch_events(events_value, detail_value)