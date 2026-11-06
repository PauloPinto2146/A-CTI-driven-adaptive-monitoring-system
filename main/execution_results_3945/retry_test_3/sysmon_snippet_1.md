<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- IOC: wiseman.exe with specific hash -->
        <Rule groupRelation="and">
          <Image condition="is">wiseman.EXE</Image>
          <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
        </Rule>
        <!-- IOC: wininet.dll with specific hash -->
        <Rule groupRelation="and">
          <Image condition="is">wininet.dll</Image>
          <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
        </Rule>
        <!-- T1033 – System Owner/User Discovery -->
        <Rule groupRelation="or">
          <CommandLine condition="contains">whoami</CommandLine>
        </Rule>
        <Rule groupRelation="or">
          <CommandLine condition="contains">query user</CommandLine>
        </Rule>
        <Rule groupRelation="or">
          <CommandLine condition="contains">net user</CommandLine>
        </Rule>
        <!-- T1218.011 – Rundll32 Abuse -->
        <Rule groupRelation="and">
          <Image condition="is">rundll32.exe</Image>
          <CommandLine condition="contains">.dll</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">rundll32.exe</Image>
          <CommandLine condition="contains">.cpl</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">rundll32.exe</Image>
          <CommandLine condition="contains">javascript:</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">rundll32.exe</Image>
          <CommandLine condition="contains">mshtml</CommandLine>
        </Rule>
        <!-- T1543.003 – Windows Service Creation/Modification -->
        <Rule groupRelation="and">
          <Image condition="is">sc.exe</Image>
          <CommandLine condition="contains">create</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">sc.exe</Image>
          <CommandLine condition="contains">config</CommandLine>
        </Rule>
        <!-- T1082 – System Information Discovery -->
        <Rule groupRelation="or">
          <Image condition="is">systeminfo.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <CommandLine condition="contains">systeminfo</CommandLine>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">hostname.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <CommandLine condition="contains">hostname</CommandLine>
        </Rule>
        <!-- T1140 – Deobfuscate/Decode Files or Information -->
        <Rule groupRelation="and">
          <Image condition="is">certutil.exe</Image>
          <CommandLine condition="contains">-decode</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">powershell.exe</Image>
          <CommandLine condition="contains">-EncodedCommand</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">copy.exe</Image>
          <CommandLine condition="contains">/b</CommandLine>
        </Rule>
        <!-- T1547.001 – Registry Run Keys / Startup Folder -->
        <Rule groupRelation="and">
          <Image condition="is">reg.exe</Image>
          <CommandLine condition="contains">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">reg.exe</Image>
          <CommandLine condition="contains">HKLM\System\CurrentControlSet\Services</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">reg.exe</Image>
          <CommandLine condition="contains">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies</CommandLine>
        </Rule>
        <!-- T1016 – System Network Configuration Discovery -->
        <Rule groupRelation="or">
          <Image condition="is">ipconfig.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">ifconfig.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">netsh.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">route.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">arp.exe</Image>
        </Rule>
        <!-- T1134 – Access Token Manipulation -->
        <Rule groupRelation="or">
          <Image condition="is">runas.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">psexec.exe</Image>
          <CommandLine condition="contains">-s</CommandLine>
        </Rule>
        <!-- T1021 – Remote Services -->
        <Rule groupRelation="or">
          <Image condition="is">mstsc.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">ssh.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">rdpclip.exe</Image>
        </Rule>
        <!-- T1018 – Remote System Discovery -->
        <Rule groupRelation="and">
          <Image condition="is">net.exe</Image>
          <CommandLine condition="contains">view</CommandLine>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">ping.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">tracert.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="is">nbtstat.exe</Image>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>