<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Service execution via sc.exe (T1569.002) -->
      <RegistryEvent onmatch="include">
        <Image condition="image">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- Recovery disabling via bcdedit.exe (T1490) -->
      <RegistryEvent onmatch="include">
        <Image condition="image">bcdedit.exe</Image>
        <TargetObject condition="begin with">HKLM\BCD00000000\Elements\</TargetObject>
      </RegistryEvent>

      <!-- Recovery disabling via REAgentC.exe (T1490) -->
      <RegistryEvent onmatch="include">
        <Image condition="image">REAgentC.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Recovery\</TargetObject>
      </RegistryEvent>

      <!-- Persistence via Run key (T1112) -->
      <RegistryEvent onmatch="include">
        <Image condition="image">reg.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- Modification of Userinit (T1112) -->
      <RegistryEvent onmatch="include">
        <Image condition="image">reg.exe</Image>
        <TargetObject condition="end with">\Userinit</TargetObject>
      </RegistryEvent>

      <!-- Modification of Shell (T1112) -->
      <RegistryEvent onmatch="include">
        <Image condition="image">reg.exe</Image>
        <TargetObject condition="end with">\Shell</TargetObject>
      </RegistryEvent>

      <!-- Disabling SafeDllSearchMode (T1112) -->
      <RegistryEvent onmatch="include">
        <Image condition="image">reg.exe</Image>
        <TargetObject condition="end with">SafeDllSearchMode</TargetObject>
      </RegistryEvent>

      <!-- IOC files potentially modifying registry -->
      <RegistryEvent onmatch="include">
        <Image condition="is any">h3odp7l2u.exe;inc.exe;win.bin;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>