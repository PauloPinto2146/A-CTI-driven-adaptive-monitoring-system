<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Rename of Run key entries (HKLM) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Rename of Run key entries (HKCU) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Rename of service registry keys -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Rename of registry keys/values via PowerShell (system hive) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Rename of registry keys/values via PowerShell (user hive) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKCU\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Rename of registry keys/values via WMIC (system hive) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">wmic.exe</Image>
        <TargetObject condition="begin with">HKLM\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Rename of registry keys/values via WMIC (user hive) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">wmic.exe</Image>
        <TargetObject condition="begin with">HKCU\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>