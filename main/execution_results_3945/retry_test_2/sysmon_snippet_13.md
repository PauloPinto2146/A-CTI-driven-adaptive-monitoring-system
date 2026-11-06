<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.EXE and wininet.dll writing DWORD/QWORD values -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">wiseman.exe;wininet.dll</Image>
      </RegistryEvent>

      <!-- BEHAVIOR: Service creation/modification – change service Startup type -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">sc.exe;powershell.exe</Image>
        <TargetObject condition="contains">\Start</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Service creation/modification – change service Type value -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">sc.exe;powershell.exe</Image>
        <TargetObject condition="contains">\Type</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Modification of SafeDllSearchMode (DWORD/QWORD) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">SafeDllSearchMode</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>