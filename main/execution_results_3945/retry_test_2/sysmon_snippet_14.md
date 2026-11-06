<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.exe -->
      <RegistryEvent onmatch="include">
        <Image condition="is">wiseman.exe</Image>
      </RegistryEvent>
      <!-- IOC: wininet.dll -->
      <RegistryEvent onmatch="include">
        <Image condition="is">wininet.dll</Image>
      </RegistryEvent>

      <!-- BEHAVIOR: Service creation/modification (T1543.003) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Registry Run Keys / Startup Folder (T1547.001) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>