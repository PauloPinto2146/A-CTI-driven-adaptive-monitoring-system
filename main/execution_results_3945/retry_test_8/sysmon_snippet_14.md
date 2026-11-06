<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="is">wiseman.exe</Image>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="is">wininet.dll</Image>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>