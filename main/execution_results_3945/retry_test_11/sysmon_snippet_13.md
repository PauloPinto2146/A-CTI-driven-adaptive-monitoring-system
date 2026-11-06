<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.exe written to a registry value -->
      <RegistryEvent onmatch="include">
        <Details condition="contains">wiseman.exe</Details>
      </RegistryEvent>

      <!-- IOC: wininet.dll written to a registry value -->
      <RegistryEvent onmatch="include">
        <Details condition="contains">wininet.dll</Details>
      </RegistryEvent>

      <!-- BEHAVIOR: Modification of Run/RunOnce keys (HKLM) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Modification of Run/RunOnce keys (HKCU) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Service ImagePath changes (service creation / modification) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\ImagePath</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Persistence via RunServices / RunServicesOnce -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: BootExecute modification for auto‑run at boot -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>