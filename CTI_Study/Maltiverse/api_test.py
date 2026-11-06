from dotenv import load_dotenv
import os
import json
import requests


load_dotenv()
api_key = os.getenv("API_KEY")

url = "https://api.maltiverse.com/feed"

malware_url = "https://api.maltiverse.com/feed/WZ0XJHIB8jmkCY9eLpr0/download?filetype=stix2"
c2c_url = "https://api.maltiverse.com/feed/VdhZV34B4jHUXfKt_gDi/download?filetype=stix2"
malware_distribution_url = "https://api.maltiverse.com/feed/ZtjCV34B4jHUXfKtjWdD/download?filetype=stix2"
apt_url = "https://api.maltiverse.com/feed/RbSs1YUBYAdeK0KL3rUf/download?filetype=stix2"
cybercrime_url = "https://api.maltiverse.com/feed/04xeknEB8jmkCY9eOoUv/download?filetype=stix2"

conti_url = "https://api.maltiverse.com/feed/oEJZt4gBgHqbhTfSIaGY/download?filetype=stix2"

headers = {
    "Authorization": f"Bearer {api_key}"
}

def write_feed_on_file(feed_url, file_string):
    response = requests.get(feed_url, headers=headers)
    feed_json = response.json()
    with open(file_string, "w", encoding="utf-8") as f:
        json.dump(feed_json, f, ensure_ascii=False, indent=4)
    print(f"Wrote {file_string}")

write_feed_on_file(malware_url, "malware_feed-WZ0XJHIB8jmkCY9eLpr0.json")
write_feed_on_file(c2c_url, "c2c_feed-VdhZV34B4jHUXfKt_gDi.json")
write_feed_on_file(malware_distribution_url, "malware_distribution_feed-ZtjCV34B4jHUXfKtjWdD.json")
write_feed_on_file(apt_url, "apt_feed-RbSs1YUBYAdeK0KL3rUf.json")
write_feed_on_file(cybercrime_url, "cybercrime_feed-04xeknEB8jmkCY9eOoUv.json")
write_feed_on_file(conti_url, "conti_feed-oEJZt4gBgHqbhTfSIaGY.json")
