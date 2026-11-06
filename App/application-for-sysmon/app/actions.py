import subprocess
import socket
import os
import requests
import random
import multiprocessing
import psutil
import json
import win32pipe, win32file
import sys

from pathlib import Path
from dotenv import load_dotenv
from concurrent.futures import ProcessPoolExecutor

ip_process_pool = None  # inicializado no startup do main.py

APP_dir = Path(__file__).parent

STORAGE_DIR = Path(__file__).parent / "storage"
STORAGE_DIR.mkdir(exist_ok=True)

TEMP_STORAGE = Path(__file__).parent / "temp_storage"
TEMP_STORAGE.mkdir(exist_ok=True)

BACKUPS_DIR = Path(__file__).parent / "backups"
BACKUPS_DIR.mkdir(exist_ok=True)

SIG_TOOL = Path(__file__).parent / "Sigtool"
SIG_TOOL.mkdir(exist_ok=True)

# 1 ==================================================================

def save_file(filename: str, content: bytes):
    cmd = [
        sys.executable, "-c",
        f"from pathlib import Path; Path(r'{STORAGE_DIR / filename}').write_bytes({content!r})"
    ]
    cmd_backup = [
        sys.executable, "-c",
        f"from pathlib import Path; Path(r'{BACKUPS_DIR / filename}').write_bytes({content!r})"
    ]
    subprocess.run(cmd)
    subprocess.run(cmd_backup)

# ====================================================================
# ////////////////////////////////////////////////////////////////////
# 2 ==================================================================

def attach_ip(target_file_path: Path, ip: str):
    target_stream = f"{target_file_path}:ip_addrs"
    try:
        # O modo "a" cria a stream se não existir ou junta ao fim se já existir
        with open(target_stream, "a", encoding="utf-8") as f:
            f.write(f"{ip}\n")
        return 1
    except Exception as e:
        print(f"Erro ao gravar na stream ADS: {e}")
        return 0

# ====================================================================
# ////////////////////////////////////////////////////////////////////
# 3 ==================================================================

def get_ips(target_file_path: str):
    target_stream = Path(f"{target_file_path}:ip_addrs")

    try:
        if target_stream.exists():
            print("Stream definetely exists.")
            res = []
            with open(target_stream, "r") as f:
                lines = f.readlines()
                for l in lines:
                    res.append(l.strip())
        else:
            print("Stream does not exist.")
            return []
    except:
        return []
    return res

def fetch_ip_info_sync(ip: str):
    mock_hosts = ["mock-ip-api-1.local", "mock-ip-api-2.local", "mock-ip-api-3.local"]
    host = random.choice(mock_hosts)
    try:
        response = requests.get(f"http://{host}:9000/json/{ip}", timeout=5)
        return response.json()
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def get_ips_info(ip_list: list):
    if not ip_list:
        return []
    futures = [ip_process_pool.submit(fetch_ip_info_sync, ip.strip()) for ip in ip_list]
    return [f.result() for f in futures]

# ====================================================================
# ////////////////////////////////////////////////////////////////////
# 4 ==================================================================

def cti_worker_server(file_path: str, uuid: str) -> str:
    pipe_name = f"\\\\.\\pipe\\CTI_IOC_Extractor_Pipe_{uuid}"
    
    pipe = win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 65536, 65536, 0, None
    )

    try:
        # Awaits HTTP request
        win32pipe.ConnectNamedPipe(pipe, None)

        # Reads CTI file
        content = Path(file_path).read_text(encoding="utf-8", errors="ignore")

        # Writes result
        response_data = json.dumps({"status": "success", "description": content}).encode('utf-8')
        win32file.WriteFile(pipe, response_data)

    finally:
        win32file.CloseHandle(pipe)


def cti_client_read(uuid: str) -> dict:
    pipe_name = f"\\\\.\\pipe\\CTI_IOC_Extractor_Pipe_{uuid}"
    """
    Cliente do Pipe: Conecta-se ao pipe (Event ID 18) para obter os resultados.
    """
    # 2. Conecta-se ao Named Pipe -> Dispara Sysmon Event ID 18
    handle = win32file.CreateFile(
        pipe_name,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None, win32file.OPEN_EXISTING, 0, None
    )

    # Lê os dados processados pelo Worker
    _, data = win32file.ReadFile(handle, 65536)
    win32file.CloseHandle(handle)
    
    return json.loads(data.decode('utf-8'))

def trigger_sysmon_pipe_events():
    pipe_name = r'\\.\pipe\TestSysmonPipe'

    # 1. Servidor cria o pipe -> Dispara Event ID 17 (PipeCreated)
    pipe = win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 65536, 65536, 0, None
    )

    # 2. Cliente conecta-se ao pipe -> Dispara Event ID 18 (PipeConnected)
    handle = win32file.CreateFile(
        pipe_name,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None, win32file.OPEN_EXISTING, 0, None
    )

    # Limpeza de handles
    win32file.CloseHandle(handle)
    win32file.CloseHandle(pipe)

# ====================================================================
# ////////////////////////////////////////////////////////////////////
# 5 ==================================================================

def get_hashfile(filepath: str, uuid: str):
    filepath = Path(filepath)
    if filepath.exists():
        temp_sigtool_path = Path(APP_dir) / f"TEMP_Sigtool_STORAGE_{uuid}"

        powershell_copy_Sigtool = ["powershell", "-Command", f"New-Item -ItemType Directory -Force -Path '{temp_sigtool_path}'; Copy-Item -Path '{SIG_TOOL}\\*' -Destination '{temp_sigtool_path}' -Recurse -Force"]
        
        sigtool_bin = temp_sigtool_path / "sigtool.exe"
        sigtool_command = [str(sigtool_bin), "--md5", str(filepath)]

        powershell_delete_tempSigtool = ["powershell", "-Command", f"Remove-Item -Path '{temp_sigtool_path}' -Recurse -Force"]

        try:
            # Copy sigtool into a dedicated directory
            subprocess.run(powershell_copy_Sigtool, check = True)
            # Use the copied sigtool to generate the hash
            result = subprocess.run(sigtool_command, capture_output=True, text=True, check = True)

            return result.stdout.strip()

        finally:
            # Get rid of the temporary directory
            if temp_sigtool_path.exists():
                subprocess.run(powershell_delete_tempSigtool)

        return ""

# ====================================================================
# ////////////////////////////////////////////////////////////////////
# 6 ==================================================================

def delete_directory():
    try:
        if not os.listdir(BACKUPS_DIR):
            print("The backup directory is empty.")
        else:
            print("The backup directory is not empty. Cleaning it.")
            for filename in os.listdir(BACKUPS_DIR):
                file_path = BACKUPS_DIR / filename
                os.remove(file_path) 
            return 1
    except:
        return 0

# ====================================================================

def clean_app():
    res = True
    try:
        if not os.listdir(BACKUPS_DIR):
            print("The backup directory is already clean.")
        else:
            print("The backup directory is not clean.\nCleaning it...")
            for filename in os.listdir(BACKUPS_DIR):
                file_path = BACKUPS_DIR / filename
                os.remove(file_path) 
    except:
        print("Something went wrong while trying to clean backups.")
        res = False

    try:
        if not os.listdir(STORAGE_DIR):
            print("The storage directory is already clean.")
        else:
            print("The storage directory is not clean.\nCleaning it...")
            for filename in os.listdir(STORAGE_DIR):
                file_path = STORAGE_DIR / filename
                os.remove(file_path) 
    except:
        print("Something went wrong while trying to storage.")
        res = False

    try:
        if not os.listdir(TEMP_STORAGE):
            print("The temporary storage directory is already clean.")
        else:
            print("The temporary storage directory is not clean.\nCleaning it...")
            for filename in os.listdir(TEMP_STORAGE):
                file_path = TEMP_STORAGE / filename
                os.remove(file_path) 
    except:
        print("Something went wrong while trying to clean temp storage.")
        res = False
    return res


if __name__ == "__main__":
    trigger_sysmon_pipe_events()