<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- T1112 – Persistence via Run key -->
    <RuleGroup name="T1112_RunKey" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1569.002 – Service configuration modifications (any process) -->
    <RuleGroup name="T1569_ServiceConfig" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1569.002 – Service creation/modification via sc.exe -->
    <RuleGroup name="T1569_sc_exe_Service" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1112 – Winlogon Notify modification via PowerShell -->
    <RuleGroup name="T1112_PowerShell_Notify" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1112 – Winlogon Userinit modification via PowerShell -->
    <RuleGroup name="T1112_PowerShell_Userinit" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1112 – Winlogon Notify modification via WMIC -->
    <RuleGroup name="T1112_Wmic_Notify" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">wmic.exe</Image>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1112 – SafeDllSearchMode toggle via reg.exe -->
    <RuleGroup name="T1112_reg_SafeDllSearchMode" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="end with">SafeDllSearchMode</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1219 – SimpleHelp remote‑support auto‑start entry -->
    <RuleGroup name="T1219_SimpleHelp_Run" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">SimpleHelp.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1219 – PowerShell creating auto‑run entry (potential RAT persistence) -->
    <RuleGroup name="T1219_PowerShell_Run" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1112 – EnableLUA toggle via reg.exe -->
    <RuleGroup name="T1112_reg_EnableLUA" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <TargetObject condition="end with">EnableLUA</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>