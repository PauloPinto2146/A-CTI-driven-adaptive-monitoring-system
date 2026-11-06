[BEHAVIOR] EventType=RenameKey; Image=sc.exe; TargetObject=HKLM\System\CurrentControlSet\Services\*; NewName=* | Source: T1543.003  
[BEHAVIOR] EventType=RenameKey; Image=reg.exe; TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run*; NewName=* | Source: T1547.001  
[IOC] EventType=RenameKey; Image=*; TargetObject=*; NewName=wiseman.EXE | Source: wiseman.EXE  
[IOC] EventType=RenameKey; Image=*; TargetObject=*; NewName=wininet.dll | Source: wininet.dll