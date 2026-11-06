<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Persistence via Run keys (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <!-- Persistence via RunOnce keys (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
      <!-- Service creation / modification (T1569.002) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
      <!-- Winlogon userinit and shell hijack (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
      </RegistryEvent>
      <!-- SafeDllSearchMode tampering (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode</TargetObject>
      </RegistryEvent>
      <!-- Service start type changes (may signal disabling/re‑enabling services) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>