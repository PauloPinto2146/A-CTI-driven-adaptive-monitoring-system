<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Persistence via service creation (T1219) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <EventType condition="is">DeleteKey</EventType>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>

      <!-- Persistence via Run autostart (T1219) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <EventType condition="is">DeleteKey</EventType>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
      </RegistryEvent>

      <!-- Persistence via RunOnce autostart (T1219) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">CreateKey</EventType>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\</TargetObject>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <EventType condition="is">DeleteKey</EventType>
        <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>