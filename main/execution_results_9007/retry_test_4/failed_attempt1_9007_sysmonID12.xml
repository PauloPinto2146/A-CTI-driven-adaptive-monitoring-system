<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC – monitor processes that may create/delete registry keys -->
      <RegistryEvent onmatch="include">
        <Image condition="ends with">h3odp7l2u.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">hi9lezv.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">072wiof7.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">k0d649u.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">2qfguc.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">7hhel.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">3ctjhm3.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">bjiw49.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">7l73h.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">0m6m882x2.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">inc.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">61pd6n3t.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">mk1yd.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">a3mnw9.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">win.bin</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">vw06lg0y.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">qgp2s6z.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="ends with">tt24n8xsl.exe</Image>
      </RegistryEvent>

      <!-- BEHAVIOR – monitor autostart and service registry locations used by Remote Access Tools (T1219) -->
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>