<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup groupRelation="or">
         <!-- IOC: specific malicious filenames -->
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wiseman.EXE</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wininet.dll</TargetFilename>
         </FileCreate>

         <!-- T1218.011 – Rundll32 creating suspicious file types -->
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.dll</TargetFilename>
            </Rule>
         </FileCreate>
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.cpl</TargetFilename>
            </Rule>
         </FileCreate>
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.sct</TargetFilename>
            </Rule>
         </FileCreate>
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.hta</TargetFilename>
            </Rule>
         </FileCreate>
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">rundll32.exe</Image>
               <TargetFilename condition="end with">.js</TargetFilename>
            </Rule>
         </FileCreate>

         <!-- T1140 – Built‑in decoding tools creating executable payloads -->
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">certutil.exe</Image>
               <TargetFilename condition="end with">.exe</TargetFilename>
            </Rule>
         </FileCreate>
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">powershell.exe</Image>
               <TargetFilename condition="end with">.exe</TargetFilename>
            </Rule>
         </FileCreate>
         <FileCreate onmatch="include">
            <Rule groupRelation="and">
               <Image condition="image">copy.exe</Image>
               <TargetFilename condition="end with">.exe</TargetFilename>
            </Rule>
         </FileCreate>

         <!-- T1027 – Creation of compressed/encoded containers -->
         <FileCreate onmatch="include">
            <TargetFilename condition="end with">.zip</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="end with">.7z</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="end with">.enc</TargetFilename>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>