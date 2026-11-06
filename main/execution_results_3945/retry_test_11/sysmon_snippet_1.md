<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- IOC: wiseman.exe with hash -->
        <Rule groupRelation="and">
          <Image condition="end with">wiseman.exe</Image>
          <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
        </Rule>

        <!-- BEHAVIOR: user discovery (whoami) -->
        <Image condition="end with">whoami.exe</Image>

        <!-- BEHAVIOR: user enumeration via query.exe -->
        <Rule groupRelation="and">
          <Image condition="end with">query.exe</Image>
          <CommandLine condition="contains">user</CommandLine>
        </Rule>

        <!-- BEHAVIOR: user enumeration via net.exe -->
        <Rule groupRelation="and">
          <Image condition="end with">net.exe</Image>
          <CommandLine condition="contains">user</CommandLine>
        </Rule>

        <!-- BEHAVIOR: rundll32 abuse -->
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <CommandLine condition="contains any">.dll;.cpl;javascript:;mshtml</CommandLine>
        </Rule>

        <!-- BEHAVIOR: Windows service creation/modification via sc.exe -->
        <Rule groupRelation="and">
          <Image condition="end with">sc.exe</Image>
          <CommandLine condition="contains any">create;config;sdset</CommandLine>
        </Rule>

        <!-- BEHAVIOR: system information discovery -->
        <Image condition="end with">systeminfo.exe</Image>

        <!-- BEHAVIOR: certutil decoding -->
        <Rule groupRelation="and">
          <Image condition="end with">certutil.exe</Image>
          <CommandLine condition="contains any">-decode;-decodehex</CommandLine>
        </Rule>

        <!-- BEHAVIOR: PowerShell obfuscation -->
        <Rule groupRelation="and">
          <Image condition="end with">powershell.exe</Image>
          <CommandLine condition="contains any">-EncodedCommand;-e</CommandLine>
        </Rule>

        <!-- BEHAVIOR: remote service clients -->
        <Image condition="end with">mstsc.exe</Image>
        <Image condition="end with">ssh.exe</Image>
        <Image condition="end with">vncviewer.exe</Image>

        <!-- BEHAVIOR: registry modification (add/delete) -->
        <Rule groupRelation="and">
          <Image condition="end with">reg.exe</Image>
          <CommandLine condition="contains any">add;delete</CommandLine>
        </Rule>

        <!-- BEHAVIOR: registry query -->
        <Rule groupRelation="and">
          <Image condition="end with">reg.exe</Image>
          <CommandLine condition="contains">query</CommandLine>
        </Rule>

        <!-- BEHAVIOR: token manipulation via runas -->
        <Image condition="end with">runas.exe</Image>

        <!-- BEHAVIOR: network configuration discovery -->
        <Image condition="end with">ipconfig.exe</Image>
        <Image condition="end with">netsh.exe</Image>
        <Image condition="end with">route.exe</Image>
        <Image condition="end with">nbtstat.exe</Image>
        <Image condition="end with">ifconfig</Image>
        <Image condition="end with">arp.exe</Image>

        <!-- BEHAVIOR: remote system discovery -->
        <Image condition="end with">ping.exe</Image>
        <Image condition="end with">tracert.exe</Image>
        <Rule groupRelation="and">
          <Image condition="end with">net.exe</Image>
          <CommandLine condition="contains">view</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>