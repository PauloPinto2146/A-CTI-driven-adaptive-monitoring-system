<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- T1112 – Registry rename of autorun entries -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is any">reg.exe;powershell.exe;wmic.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is any">reg.exe;powershell.exe;wmic.exe</Image>
        <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1569.002 – Registry rename of service definitions -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is any">sc.exe;services.exe;psexec.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- DERIVED – Detect hidden keys created by prefixing a null character -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <NewName condition="contains">\0</NewName>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>