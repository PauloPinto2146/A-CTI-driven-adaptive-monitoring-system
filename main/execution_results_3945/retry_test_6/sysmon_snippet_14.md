<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Include rename operations performed by the malicious process wiseman.exe -->
    <RuleGroup name="IOC-wiseman" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="is">wiseman.exe</Image>
      </RegistryEvent>
    </RuleGroup>

    <!-- Include rename of service registry keys (T1543.003 – Windows Service) -->
    <RuleGroup name="Service-rename" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Include rename of Run key entries under HKLM (T1547.001 – Registry Run Keys / Startup Folder) -->
    <RuleGroup name="RunKey-HKLM-rename" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Include rename of Run key entries under HKCU (T1547.001 – Registry Run Keys / Startup Folder) -->
    <RuleGroup name="RunKey-HKCU-rename" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Exclude well‑known benign noise (system processes) -->
    <RuleGroup name="Benign-Exclude" groupRelation="or">
      <RegistryEvent onmatch="exclude">
        <Image condition="is">System</Image>
        <Image condition="is">svchost.exe</Image>
        <Image condition="is">services.exe</Image>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>