<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.EXE -->
      <RegistryEvent onmatch="include">
        <Image condition="image">wiseman.EXE</Image>
      </RegistryEvent>

      <!-- IOC: wininet.dll -->
      <RegistryEvent onmatch="include">
        <Image condition="image">wininet.dll</Image>
      </RegistryEvent>

      <!-- T1543.003 – Service ImagePath -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\</TargetObject>
        <TargetObject condition="end with">\ImagePath</TargetObject>
      </RegistryEvent>

      <!-- T1543.003 – Service Type -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\</TargetObject>
        <TargetObject condition="end with">\Type</TargetObject>
      </RegistryEvent>

      <!-- T1547.001 – HKLM Run keys -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- T1547.001 – HKCU Run keys -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- T1112 – Explorer Run policies -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>

      <!-- T1112 – BootExecute -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>