<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <!-- Persistence via Run / RunOnce -->
        <TargetObject name="technique_id=T1112,technique_name=Modify Registry" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
        <TargetObject name="technique_id=T1112,technique_name=Modify Registry" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\</TargetObject>

        <!-- Winlogon hijack -->
        <TargetObject name="technique_id=T1112,technique_name=Modify Registry" condition="is">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
        <TargetObject name="technique_id=T1112,technique_name=Modify Registry" condition="is">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>

        <!-- Service creation / modification (T1569.002) -->
        <TargetObject name="technique_id=T1569.002,technique_name=Service Execution" condition="contains">\ImagePath</TargetObject>
        <TargetObject name="technique_id=T1569.002,technique_name=Service Execution" condition="contains">\Start</TargetObject>
        <TargetObject name="technique_id=T1569.002,technique_name=Service Execution" condition="contains">\ErrorControl</TargetObject>

        <!-- Disable UAC / privilege escalation -->
        <TargetObject name="technique_id=T1112,technique_name=Modify Registry" condition="is">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>