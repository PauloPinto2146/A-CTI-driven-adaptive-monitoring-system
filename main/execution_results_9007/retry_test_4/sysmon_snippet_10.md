
<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Credential dumping: LSASS access with high‑privilege rights -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
        </Rule>
      </ProcessAccess>

      <!-- Packing/unpacking: suspicious access to non‑system executables with write/create‑thread rights -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="not begin with">C:\Windows\System32\</TargetImage>
          <TargetImage condition="end with">.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1F0FFF;0x1F1FFF;0x143A;0x1410;0x1010;0x1F2FFF;0x1F3FFF;0x1FFFFF;0x147A;0x1028</GrantedAccess>
        </Rule>
      </ProcessAccess>

      <!-- IOC: known malicious executables observed in the threat feed -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="contains any">
            h3odp7l2u.exe;
            hi9lezv.exe;
            072wiof7.exe;
            k0d649u.exe;
            2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat.exe;
            2qfguc.exe;
            7hhel.exe;
            3ctjhm3.exe;
            2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat.exe;
            bjiw49.exe;
            7l73h.exe;
            2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat.exe;
            0m6m882x2.exe;
            inc.exe;
            61pd6n3t.exe;
            mk1yd.exe;
            a3mnw9.exe;
            vw06lg0y.exe;
            qgp2s6z.exe;
            tt24n8xsl.exe
          </TargetImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
