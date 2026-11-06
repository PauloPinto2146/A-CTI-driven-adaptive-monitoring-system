import random
from fastapi import FastAPI

app = FastAPI()

FAKE_LOCATIONS = [
    {"country": "Portugal", "regionName": "Braga", "city": "Braga", "lat": 41.5454, "lon": -8.4265, "isp": "MEO"},
    {"country": "Germany", "regionName": "Bavaria", "city": "Munich", "lat": 48.1351, "lon": 11.5820, "isp": "Deutsche Telekom"},
    {"country": "United States", "regionName": "California", "city": "Los Angeles", "lat": 34.0522, "lon": -118.2437, "isp": "AT&T"},
    {"country": "Japan", "regionName": "Tokyo", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "isp": "NTT"},
    {"country": "Brazil", "regionName": "Sao Paulo", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "isp": "Vivo"},
]


@app.get("/json/{ip}")
async def geolocate(ip: str):
    print("Received request!")
    location = random.choice(FAKE_LOCATIONS)
    return {
        "status": "success",
        "query": ip,
        **location
    }

# Giving a 200 OK status to know if server is up (for testing purposes)
@app.get("/check")
async def check():
    return 200