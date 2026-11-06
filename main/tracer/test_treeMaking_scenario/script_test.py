import os
import subprocess
import time
from dotenv import load_dotenv
from pathlib import Path


print(os.getcwd())
print(__file__)

load_dotenv()

dir = Path("C:\\Users\\Paulo\\Desktop\\Monitorizacao_adaptativa\\main\\tracer\\testMaking_scenario")
# Simulate creation, writing and reading of a test_file
with open(f"{dir}\\test_file.txt", "w") as f:
	f.write("Primeira escrita\n")
with open(f"{dir}\\test_file.txt", "a") as f:
	f.write("Segunda escrita\n")
with open(f"{dir}\\cwd.txt", "w") as f:
    f.write(os.getcwd())
with open(f"{dir}\\test_file.txt", "r") as f:
	print("O script leu o ficheiro test_file:\n", f.read())


# Simulate a subprocess
subprocess.run([
    "cmd",
    "/c",
    "echo Hello > output.txt && timeout /t 5"
])