<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- T1112 – Registry rename for autorun/persistence via reg.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>

      <!-- T1112 – Registry rename for autorun/persistence via PowerShell -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>

      <!-- T1112 – Registry rename targeting service keys via wmic.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">wmic.exe</Image>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- T1569.002 – Service execution manipulation via sc.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- T1112 – Registry rename of policy settings via reg.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\</TargetObject>
      </RegistryEvent>

      <!-- T1112 – Registry rename of policy settings via PowerShell -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>