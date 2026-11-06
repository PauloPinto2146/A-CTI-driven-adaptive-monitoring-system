Set shell = CreateObject("WScript.Shell")

base = "C:\Users\Paulo\Desktop\Monitorizacao_adaptativa\main\tracer\test_treeMaking_scenario"

shell.Run "notepad.exe"

shell.Run "firefox.exe"

shell.Run "cmd /k cd /d """ & base & """ && python script_test.py"