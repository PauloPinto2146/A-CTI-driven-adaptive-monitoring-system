<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">wiseman.exe</Image>
      </RegistryEvent>
      <!-- IOC: wininet.dll -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">wininet.dll</Image>
      </RegistryEvent>
      <!-- BEHAVIOR: HKLM Run keys -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: HKCU Run keys -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: HKLM RunOnce -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: HKCU RunOnce -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: HKLM Policy Run -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: HKCU Policy Run -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: Service ImagePath -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services</TargetObject>
        <TargetObject condition="contains">\ImagePath</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: Service Type -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services</TargetObject>
        <TargetObject condition="contains">\Type</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: Service Start -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services</TargetObject>
        <TargetObject condition="contains">\Start</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: BootExecute -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: RunServices -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices</TargetObject>
      </RegistryEvent>
      <!-- BEHAVIOR: RunServicesOnce -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>