<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileCreate onmatch="include">
            <!-- IOC filenames -->
            <Rule groupRelation="and">
               <TargetFilename condition="is">x86_64-unknown-linux-esxi.elf</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">h3odp7l2u.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">hi9lezv.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">072wiof7.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">k0d649u.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">2qfguc.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">7hhel.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">3ctjhm3.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">bjiw49.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">7l73h.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">0m6m882x2.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">inc.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">61pd6n3t.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">mk1yd.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">a3mnw9.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">win.bin</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">vw06lg0y.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">qgp2s6z.exe</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="is">tt24n8xsl.exe</TargetFilename>
            </Rule>
            <!-- Derived vulnerable software locations -->
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\FortiClientEMS\</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\SimpleHelp\</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\NetScaler\</TargetFilename>
            </Rule>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>