<Sysmon schemaversion="4.40">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileDelete onmatch="include">
            <!-- IOC: wiseman.EXE -->
            <Rule groupRelation="and">
               <Image condition="is any">*</Image>
               <TargetFilename condition="ends with">wiseman.EXE</TargetFilename>
               <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
               <IsExecutable condition="is">true</IsExecutable>
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- IOC: wininet.dll -->
            <Rule groupRelation="and">
               <Image condition="is any">*</Image>
               <TargetFilename condition="ends with">wininet.dll</TargetFilename>
               <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
               <IsExecutable condition="is">false</IsExecutable>
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- BEHAVIOR: cmd.exe -->
            <Rule groupRelation="and">
               <Image condition="is">C:\Windows\System32\cmd.exe</Image>
               <TargetFilename condition="is any">*</TargetFilename>
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- BEHAVIOR: PowerShell -->
            <Rule groupRelation="and">
               <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
               <TargetFilename condition="is any">*</TargetFilename>
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- BEHAVIOR: sdelete.exe -->
            <Rule groupRelation="and">
               <Image condition="contains">sdelete.exe</Image>
               <TargetFilename condition="is any">*</TargetFilename>
               <Archived condition="is">true</Archived>
            </Rule>
         </FileDelete>
      </RuleGroup>
   </EventFiltering>
</Sysmon>