<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="ServiceRename" groupRelation="and">
      <RegistryEvent onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="RunKeyRename" groupRelation="and">
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="WisemanRename" groupRelation="and">
      <RegistryEvent onmatch="include">
        <NewName condition="is">wiseman.EXE</NewName>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="WininetRename" groupRelation="and">
      <RegistryEvent onmatch="include">
        <NewName condition="is">wininet.dll</NewName>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>