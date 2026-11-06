<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.EXE -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">wiseman.EXE</Image>
      </RegistryEvent>

      <!-- IOC: wininet.dll -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">wininet.dll</Image>
      </RegistryEvent>

      <!-- BEHAVIOR: Service creation/modification (ImagePath or any value) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: HKLM Run / RunOnce keys -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: HKCU Run / RunOnce keys -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Policy Run key -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: BootExecute -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Winlogon Userinit -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Winlogon Shell -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>