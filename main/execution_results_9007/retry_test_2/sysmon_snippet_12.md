<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Autostart Run keys – HKLM -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <EventType condition="is">DeleteKey</EventType>
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>

      <!-- Autostart Run keys – HKCU -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <EventType condition="is">DeleteKey</EventType>
        <TargetObject condition="begin with">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>

      <!-- Service registration – HKLM\System\CurrentControlSet\Services -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <EventType condition="is">DeleteKey</EventType>
        <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>