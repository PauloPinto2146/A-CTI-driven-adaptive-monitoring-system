<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC file‑based rename operations -->
      <RegistryEvent onmatch="include">
        <Image condition="end with">x86_64-unknown-linux-esxi.elf</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">h3odp7l2u.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">hi9lezv.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">072wiof7.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">k0d649u.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">2qfguc.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">7hhel.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">3ctjhm3.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">bjiw49.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">7l73h.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">0m6m882x2.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">inc.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">61pd6n3t.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">mk1yd.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">a3mnw9.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">win.bin</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">vw06lg0y.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">qgp2s6z.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">tt24n8xsl.exe</Image>
      </RegistryEvent>

      <!-- Behavior: Registry keys modified for persistence, privilege escalation, or service execution (T1112, T1569.002) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>