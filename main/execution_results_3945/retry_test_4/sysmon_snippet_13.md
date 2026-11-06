<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Include_Run_Keys" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\</TargetObject>
        <TargetObject condition="contains">\Depend</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <RuleGroup name="Include_Service_Creation" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\ImagePath</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Start</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Type</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <RuleGroup name="Include_Boot_Execute" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\BootExecute</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <RuleGroup name="Include_Winlogon_Tampering" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Userinit</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\Shell</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <RuleGroup name="Include_SafeDllSearchMode" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="end with">\SafeDllSearchMode</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <RuleGroup name="IOC_wiseman_EXE" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="image">wiseman.EXE</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <RuleGroup name="IOC_wininet_DLL" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Details condition="contains">wininet.dll</Details>
        <TargetObject condition="end with">\ImagePath</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>