<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC – specific executables that may rename registry keys/values -->
      <RegistryEvent onmatch="include">
        <Image condition="is">x86_64-unknown-linux-esxi.elf</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">h3odp7l2u.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">hi9lezv.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">072wiof7.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">k0d649u.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">2qfguc.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">7hhel.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">3ctjhm3.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">bjiw49.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">7l73h.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">0m6m882x2.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">inc.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">61pd6n3t.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">mk1yd.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">a3mnw9.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">win.bin</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">vw06lg0y.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">qgp2s6z.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="is">tt24n8xsl.exe</Image>
      </RegistryEvent>

      <!-- BEHAVIOR – registry locations commonly abused for persistence, privilege escalation, or service execution -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">SafeDllSearchMode</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>