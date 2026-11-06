
<Sysmon schemaversion="4.30">
  <EventFiltering>

    <!-- T1219 – Autostart Run key (create or delete) -->
    <RuleGroup name="T1219_Autostart_Run" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is any">CreateKey;DeleteKey</EventType>
        <TargetObject condition="end with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- T1219 – Service registration (create or delete) -->
    <RuleGroup name="T1219_Service_Registration" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is any">CreateKey;DeleteKey</EventType>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- CVE-2024-57727 – SimpleHelp creates its own registry key -->
    <RuleGroup name="CVE-2024-57727_SimpleHelp" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <Image condition="is">C:\Program Files\SimpleHelp\SimpleHelp.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\SimpleHelp</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- CVE-2023-48788 – FortiClientEMS creates its own registry key -->
    <RuleGroup name="CVE-2023-48788_FortiClientEMS" groupRelation="or">
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <Image condition="is">C:\Program Files\Fortinet\FortiClientEMS.exe</Image>
        <TargetObject condition="begin with">HKLM\Software\Fortinet\FortiClientEMS</TargetObject>
      </RegistryEvent>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
