<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Driver loaded from user profile directory -->
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="contains">C:\Users\</Image>
        </Rule>
      </DriverLoad>

      <!-- Driver loaded from temporary directory -->
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="contains">C:\Temp\</Image>
        </Rule>
      </DriverLoad>

      <!-- Unsigned or improperly signed driver -->
      <DriverLoad onmatch="include">
        <Rule groupRelation="or">
          <Signed condition="is">false</Signed>
        </Rule>
      </DriverLoad>
      <DriverLoad onmatch="include">
        <Rule groupRelation="or">
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
      </DriverLoad>
      <DriverLoad onmatch="include">
        <Rule groupRelation="or">
          <SignatureStatus condition="is">Unsigned</SignatureStatus>
        </Rule>
      </DriverLoad>

      <!-- .sys driver loaded from non‑system driver directory -->
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">.sys</Image>
          <Image condition="not begin with">%SystemRoot%\System32\drivers\</Image>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>