<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.exe accessing LSASS -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <SourceImage condition="is">wiseman.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">PROCESS_VM_READ;PROCESS_DUP_HANDLE</GrantedAccess>
        </Rule>
      </ProcessAccess>

      <!-- BEHAVIOR: Any process accessing LSASS with high‑privilege rights (T1134) -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">PROCESS_QUERY_INFORMATION;PROCESS_VM_READ;PROCESS_DUP_HANDLE;PROCESS_CREATE_PROCESS</GrantedAccess>
        </Rule>
      </ProcessAccess>

      <!-- DERIVED: Post‑exploit SYSTEM‑level accesses after CVE‑2023‑27350 -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="is">services.exe</TargetImage>
          <GrantedAccess condition="contains any">PROCESS_ALL_ACCESS</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="is">winlogon.exe</TargetImage>
          <GrantedAccess condition="contains any">PROCESS_ALL_ACCESS</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>