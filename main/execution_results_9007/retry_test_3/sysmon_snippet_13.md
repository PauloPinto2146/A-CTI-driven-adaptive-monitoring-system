<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Persistence via Run keys (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <!-- Persistence via RunOnce keys (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\</TargetObject>
      </RegistryEvent>
      <!-- Winlogon Userinit hijack (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>
      </RegistryEvent>
      <!-- Winlogon Shell hijack (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
      </RegistryEvent>
      <!-- Service ImagePath modification (T1569.002) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
        <TargetObject condition="end with">\ImagePath</TargetObject>
      </RegistryEvent>
      <!-- SafeDllSearchMode tampering (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode</TargetObject>
      </RegistryEvent>
      <!-- BCD manipulation to inhibit recovery (T1490) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\BCD00000000\Objects\</TargetObject>
        <TargetObject condition="contains">\Elements\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>