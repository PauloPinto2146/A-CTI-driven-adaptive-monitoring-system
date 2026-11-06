<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Rename Run key via reg.exe (T1547.001) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is">reg.exe</Image>
        <TargetObject condition="is">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <!-- Rename RunOnce key via reg.exe (T1547.001) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is">reg.exe</Image>
        <TargetObject condition="is">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
      <!-- Rename user Run key via powershell.exe (T1547.001) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is">powershell.exe</Image>
        <TargetObject condition="is">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
      <!-- Rename service keys via sc.exe (T1543.003) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is">sc.exe</Image>
        <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\</TargetObject>
      </RegistryEvent>
      <!-- Rename Explorer policy Run key via reg.exe (T1112) -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is">reg.exe</Image>
        <TargetObject condition="is">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</TargetObject>
      </RegistryEvent>
      <!-- IOC: wiseman.EXE renaming any registry key -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is">wiseman.EXE</Image>
      </RegistryEvent>
      <!-- IOC: wininet.dll renaming any registry key -->
      <RegistryEvent onmatch="include">
        <EventType condition="is">RenameKey</EventType>
        <Image condition="is">wininet.dll</Image>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>