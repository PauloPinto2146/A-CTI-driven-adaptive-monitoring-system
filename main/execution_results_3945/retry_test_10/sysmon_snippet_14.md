
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">

      <!-- IOC: rename to wiseman.EXE in Run keys -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">reg.exe;powershell.exe;cmd.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <NewName condition="is">wiseman.EXE</NewName>
      </RegistryEvent>

      <!-- IOC: rename to wininet.dll in Run keys -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">reg.exe;powershell.exe;cmd.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <NewName condition="is">wininet.dll</NewName>
      </RegistryEvent>

      <!-- BEHAVIOR: Service registry rename (T1543.003) -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">svchost.exe;services.exe</Image>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Run‑key/Startup folder rename (T1547.001) -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">explorer.exe;userinit.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- DERIVED: BootExecute rename for persistence -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">services.exe;sc.exe</Image>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>

    </RuleGroup>
  </EventFiltering>
</Sysmon>
