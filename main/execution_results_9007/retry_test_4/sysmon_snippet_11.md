<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup groupRelation="or">
         <!-- IOC filenames -->
         <FileCreate onmatch="include">
            <TargetFilename condition="is any">x86_64-unknown-linux-esxi.elf;h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;win.bin;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</TargetFilename>
         </FileCreate>

         <!-- T1567 – Exfiltration over Web Service directories -->
         <FileCreate onmatch="include">
            <TargetFilename condition="contains any">Dropbox;OneDrive;Google Drive</TargetFilename>
         </FileCreate>

         <!-- T1219 – Remote access tool drop locations -->
         <FileCreate onmatch="include">
            <TargetFilename condition="contains any">\\Temp\\;\\AppData\\;\\LocalAppData\\;\\ProgramData\\</TargetFilename>
            <TargetFilename condition="end with">.exe</TargetFilename>
         </FileCreate>

         <!-- T1486 – Encrypted/locked files in Documents -->
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\\Documents\\</TargetFilename>
            <TargetFilename condition="end with">.locked</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\\Documents\\</TargetFilename>
            <TargetFilename condition="end with">.encrypted</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\\Documents\\</TargetFilename>
            <TargetFilename condition="end with">.crypt</TargetFilename>
         </FileCreate>

         <!-- T1566 – Phishing payloads in Downloads -->
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\\Downloads\\</TargetFilename>
            <TargetFilename condition="end with">.exe</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\\Downloads\\</TargetFilename>
            <TargetFilename condition="end with">.js</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\\Downloads\\</TargetFilename>
            <TargetFilename condition="end with">.vbs</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\\Downloads\\</TargetFilename>
            <TargetFilename condition="end with">.scr</TargetFilename>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>