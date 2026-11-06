<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: malicious executables modifying any registry value -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;win.bin;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</Image>
      </RegistryEvent>

      <!-- BEHAVIOR: Autorun persistence (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Service creation / execution (T1569.002) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\ImagePath</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Winlogon hijacking (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Winlogon\Userinit</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Winlogon\Shell</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\Winlogon\Notify\</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: Disable SafeDllSearchMode (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode</TargetObject>
      </RegistryEvent>

      <!-- BEHAVIOR: UAC manipulation (T1112) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="is">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>