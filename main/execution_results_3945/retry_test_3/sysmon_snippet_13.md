<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Service start‑type modification (T1543.003) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>

      <!-- Service type modification (T1543.003) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Type</TargetObject>
      </RegistryEvent>

      <!-- Service error‑control modification (T1543.003) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\ErrorControl</TargetObject>
      </RegistryEvent>

      <!-- Registry Run key persistence (T1547.001) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- Policy‑based Run key persistence (T1547.001) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>

      <!-- SafeDllSearchMode toggle (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\SafeDllSearchMode</TargetObject>
      </RegistryEvent>

      <!-- EnableLUA toggle (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\EnableLUA</TargetObject>
      </RegistryEvent>

      <!-- BootExecute modification for boot‑time persistence (T1547.001) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\BootExecute</TargetObject>
      </RegistryEvent>

      <!-- IOC: wiseman.EXE registered in a Run key -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <Details condition="contains">wiseman.EXE</Details>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <Details condition="contains">wiseman.EXE</Details>
      </RegistryEvent>

      <!-- IOC: wininet.dll registered in a Run key -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <Details condition="contains">wininet.dll</Details>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <Details condition="contains">wininet.dll</Details>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>