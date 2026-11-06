<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.exe modifying any registry value -->
      <RegistryEvent onmatch="include">
        <Image condition="contains">wiseman.exe</Image>
      </RegistryEvent>

      <!-- BEHAVIOR: Service creation/modification via sc.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Service creation/modification via PowerShell -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Startup/Run key persistence via sc.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Startup/Run key persistence via PowerShell -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: svchost.exe modifying registry (e.g., keylogging related) -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">svchost.exe</Image>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>