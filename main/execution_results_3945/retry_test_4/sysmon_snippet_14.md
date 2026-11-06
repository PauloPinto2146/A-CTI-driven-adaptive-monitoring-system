
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Persistence via Windows Services (T1543.003) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Persistence via Run/RunOnce keys (T1547.001) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Boot Execute persistence (T1547.001) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Policies Run persistence (T1547.001) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- IOC: rename operations performed by known malicious binaries -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">wiseman.exe</Image>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <Image condition="end with">wininet.dll</Image>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
