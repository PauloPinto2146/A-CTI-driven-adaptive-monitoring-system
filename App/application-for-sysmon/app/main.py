import os
import asyncio
import win32pipe, win32file, pywintypes

from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from fastapi import FastAPI
from app import actions
from fastapi import FastAPI, HTTPException, UploadFile
from pathlib import Path


app = FastAPI()

TEMP_STORAGE = Path(__file__).parent / "TEMP_STORAGE"
TEMP_STORAGE.mkdir(exist_ok=True)


"""
Actions:

1 - Create a threat report description file (Triggers events 1, 5 and 11) 
2 - Adding IP address meta data with file streams.(Triggers event 15)
3 - Consulting mock-ip-api to get ip info (Trigger events 1, 3, 5, 10 and 22)
4 - Read threat reports. Which can be implemented with pipes (Trigger events 17 and 18)
5 - Upload files and generate hashes (Trigger events 1, 5, 7 , 11, 26, 29)
6 - Clean the storage (Triggers event 26)
"""


@app.on_event("startup")
async def startup():
    loop = asyncio.get_event_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=1000))
    actions.ip_process_pool = ProcessPoolExecutor(max_workers=8)  # workers persistentes

@app.on_event("shutdown")
async def shutdown():
    actions.ip_process_pool.shutdown(wait=True)

# 1
@app.post("/upload")
async def upload_report_description(text: str, title: str, uuid: str):
    target_path = actions.STORAGE_DIR / f"{title}_{uuid}.txt"
    if target_path.exists():
        raise HTTPException(status_code=409, detail="File title already claimed")
    
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, actions.save_file, f"{title}_{uuid}.txt", text.encode("utf-8"))
    return {"status": "saved", "filename": f"{title}_{uuid}", "size": len(text)}

# 2
@app.post("/attach_ips")
async def attach_ip(filename: str, ip: str):
    file_path = actions.STORAGE_DIR / f"{filename}.txt"
    if not file_path.exists():
        return {"status": "Error", "message": f"File {filename}.txt does not exist in the storage."}
    
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, actions.attach_ip, file_path, ip)
    if res:
        return {"status": "attached", "filename": f"{filename}.txt", "ip": ip}
    return {"status": "Error"}

# 3
@app.get("/checkips")
async def check_ips(filename: str):
    file_path = actions.STORAGE_DIR / f"{filename}.txt"
    if not file_path.exists():
        return {"status": "Error", "message": f"Stream {filename}.txt:ip_addrs does not exist in the storage."}
    
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, actions.get_ips, file_path)
    ips = await loop.run_in_executor(None, actions.get_ips_info, res)
    return {"status": "Ok", "ips": ips}

# 4
@app.get("/read")
async def read_threat_report(filename: str, uuid: str):
    file_path = actions.STORAGE_DIR / f"{filename}.txt"

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="CTI file not found.")

    loop = asyncio.get_event_loop()

    # 1 unique pipe per user. The cti_worker_server finds the file, gives to the cti_client_read and he exposes the description
    server_task = loop.run_in_executor(None, actions.cti_worker_server, str(file_path), uuid)
    await asyncio.sleep(0.1)
    result = await loop.run_in_executor(None, actions.cti_client_read, uuid)
    await server_task

    return result

# 5
@app.get("/hash")
async def get_hash(filename: str, uuid: str):
    file_path = actions.STORAGE_DIR / f"{filename}.txt"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File {filename}.txt does not exist in storage.")
    
    loop = asyncio.get_event_loop()
    h = await loop.run_in_executor(None, actions.get_hashfile, file_path, uuid)
    if not h:
        return {"status": "Error"}
    return {"status": "Ok", "MD5hash": h}

# 6
@app.delete("/backups")
async def delete():
    loop = asyncio.get_event_loop()
    ok = await loop.run_in_executor(None, actions.delete_directory)
    return {"status": "deleted" if ok else "not_found"}

# Cleaning everything action (for testing purposes)
@app.delete("/clean")
async def clean():
    print("Entrei no clean")
    loop = asyncio.get_event_loop()
    ok = await loop.run_in_executor(None, actions.clean_app)
    return {"status": "cleaned" if ok else "not_found"}

# Giving a 200 OK status to know if server is up (for testing purposes)
@app.get("/check")
async def check():
    return 200

