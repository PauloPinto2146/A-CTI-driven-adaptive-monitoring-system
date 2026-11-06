<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="is any">sc.exe;powershell.exe;cmd.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is any">sc.exe;powershell.exe;cmd.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
        <TargetObject condition="end with">\Type</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is any">reg.exe;powershell.exe;wmic.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows</TargetObject>
        <TargetObject condition="end with">\SafeDllSearchMode</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is any">reg.exe;powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <TargetObject condition="end with">\Notify</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>