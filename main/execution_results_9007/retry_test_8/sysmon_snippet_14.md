<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- T1569.002 – Service execution via renamed service keys -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- T1112 – Registry modifications for persistence (Run keys) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>

      <!-- T1112 – Registry modifications for security policy changes -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>