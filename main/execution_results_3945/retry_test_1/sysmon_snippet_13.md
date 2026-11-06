<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">services.exe</Image>
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>