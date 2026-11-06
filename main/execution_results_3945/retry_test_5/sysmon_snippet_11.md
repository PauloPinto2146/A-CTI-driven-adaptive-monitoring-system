<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileCreate onmatch="include">
            <!-- IOC: wiseman.EXE -->
            <Rule groupRelation="or">
               <TargetFilename condition="contains">wiseman.EXE</TargetFilename>
            </Rule>
            <!-- IOC: wininet.dll -->
            <Rule groupRelation="or">
               <TargetFilename condition="contains">wininet.dll</TargetFilename>
            </Rule>
            <!-- BEHAVIOR: Rundll32 abuse – Control Panel Item files -->
            <Rule groupRelation="or">
               <TargetFilename condition="end with">.cpl</TargetFilename>
            </Rule>
            <!-- BEHAVIOR: Rundll32 abuse – scriptlet files -->
            <Rule groupRelation="or">
               <TargetFilename condition="end with">.sct</TargetFilename>
            </Rule>
            <!-- BEHAVIOR: Rundll32 abuse – HTML Application files -->
            <Rule groupRelation="or">
               <TargetFilename condition="end with">.hta</TargetFilename>
            </Rule>
            <!-- BEHAVIOR: Rundll32 abuse – JavaScript files -->
            <Rule groupRelation="or">
               <TargetFilename condition="end with">.js</TargetFilename>
            </Rule>
            <!-- BEHAVIOR: Deobfuscation/decoding – common encoded/obfuscated extensions -->
            <Rule groupRelation="or">
               <TargetFilename condition="contains any">.b64;.enc;.cer;.txt;.zip;.7z</TargetFilename>
            </Rule>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>