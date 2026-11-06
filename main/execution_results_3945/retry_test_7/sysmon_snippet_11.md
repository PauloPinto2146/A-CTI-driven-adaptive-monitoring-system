
<Sysmon schemaversion="4.30">
   <EventFiltering>

      <!-- IOC: specific filenames -->
      <RuleGroup name="ioc_filenames" groupRelation="or">
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wiseman.EXE</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wininet.dll</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- T1218.011 – Rundll32 abuse -->
      <RuleGroup name="technique_id=T1218.011,technique_name=Rundll32" groupRelation="or">
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.dll</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.cpl</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.sct</TargetFilename>
            </Rule>
         </FileCreate>
      </RuleGroup>

      <!-- T1140 – Deobfuscate/Decode Files (certutil) -->
      <RuleGroup name="technique_id=T1140,technique_name=Deobfuscate/Decode" groupRelation="or">
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">certutil.exe</Image>
               <TargetFilename condition="end with">.b64</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <Image condition="image">certutil.exe</Image>
               <TargetFilename condition="end with">.cer</TargetFilename>
            </Rule>
         </FileCreate>
      </RuleGroup>

      <!-- T1027 – Obfuscated Files (PowerShell creating archives) -->
      <RuleGroup name="technique_id=T1027,technique_name=Obfuscated_Files" groupRelation="or">
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">powershell.exe</Image>
               <TargetFilename condition="end with">.zip</TargetFilename>
            </Rule>
         </FileCreate>
      </RuleGroup>

      <!-- DERIVED – Possible persistence drop after CVE-2023-27350 exploitation -->
      <RuleGroup name="cve_2023_27350_persistence" groupRelation="or">
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <TargetFilename condition="end with">.exe</TargetFilename>
               <TargetFilename condition="contains">\Microsoft\Windows\Start Menu\Programs\Startup\</TargetFilename>
            </Rule>
         </FileCreate>
      </RuleGroup>

   </EventFiltering>
</Sysmon>
