<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="is any">services.exe;sc.exe;net.exe;psexec.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>