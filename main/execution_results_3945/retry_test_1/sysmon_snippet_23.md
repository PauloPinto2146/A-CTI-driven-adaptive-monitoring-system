<Sysmon schemaversion="4.40">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileDelete onmatch="include">
            <!-- IOC: wiseman.EXE -->
            <Rule groupRelation="and">
               <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
               <IsExecutable condition="is">true</IsExecutable>
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- IOC: wininet.dll -->
            <Rule groupRelation="and">
               <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
               <IsExecutable condition="is">false</IsExecutable>
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- BEHAVIOR: T1070.004 – malicious executable deletion -->
            <Rule groupRelation="and">
               <IsExecutable condition="is">true</IsExecutable>
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- BEHAVIOR: AN0392 – any artifact deletion after suspicious execution -->
            <Rule groupRelation="and">
               <Archived condition="is">true</Archived>
            </Rule>
            <!-- DERIVED: post‑exploitation cleanup (CVE‑2023‑27350) -->
            <Rule groupRelation="and">
               <Archived condition="is">true</Archived>
            </Rule>
         </FileDelete>
      </RuleGroup>
   </EventFiltering>
</Sysmon>