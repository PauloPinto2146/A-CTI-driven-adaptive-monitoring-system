<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Service registry keys (T1543.003) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- Run/RunOnce keys (T1547.001) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- BootExecute key (T1547.001) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>

      <!-- Hidden key names using leading null character (T1112) -->
      <RegistryEvent onmatch="include">
        <NewName condition="contains">\0</NewName>
      </RegistryEvent>

      <!-- IOC: malicious processes performing renames -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">wiseman.EXE</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">wininet.dll</Image>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>