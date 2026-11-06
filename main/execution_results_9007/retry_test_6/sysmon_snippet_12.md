<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- IOC: specific malicious executables creating/deleting Run keys -->
    <RuleGroup name="" groupRelation="and">
      <RegistryEvent onmatch="include">
        <Image condition="is any">h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2qfguc.exe;7hhel.exe;3ctjhm3.exe;bjiw49.exe;7l73h.exe;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- BEHAVIOR: creation/deletion of service keys (persistence) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: creation/deletion of user Run keys -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>