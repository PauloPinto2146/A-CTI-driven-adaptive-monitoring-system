[BEHAVIOR] EventType=SetValue, Image=* , TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* , Details=* | Source: T1112  
[BEHAVIOR] EventType=SetValue, Image=* , TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\* , Details=* | Source: T1112  
[BEHAVIOR] EventType=SetValue, Image=* , TargetObject=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit , Details=* | Source: T1112  
[BEHAVIOR] EventType=SetValue, Image=* , TargetObject=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell , Details=* | Source: T1112  
[BEHAVIOR] EventType=SetValue, Image=* , TargetObject=HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath , Details=* | Source: T1569.002  
[BEHAVIOR] EventType=SetValue, Image=* , TargetObject=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode , Details=* | Source: T1112  
[DERIVED] EventType=SetValue, Image=* , TargetObject=HKLM\BCD00000000\Objects\*\Elements\*\ , Details=* | Source: T1490  