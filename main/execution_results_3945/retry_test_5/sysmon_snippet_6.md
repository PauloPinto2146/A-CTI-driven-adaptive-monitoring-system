<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Unsigned driver load (T1543.003) -->
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <Signed condition="is">false</Signed>
        </Rule>
      </DriverLoad>

      <!-- Driver loaded from uncommon locations (T1543.003) -->
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="contains">C:\Users\</ImageLoaded>
        </Rule>
      </DriverLoad>

      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="contains">C:\Temp\</ImageLoaded>
        </Rule>
      </DriverLoad>

      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="contains">%AppData%\</ImageLoaded>
        </Rule>
      </DriverLoad>

      <!-- Driver with problematic or missing signature (derived from CVE‑2023‑27350) -->
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <SignatureStatus condition="is any">Invalid;Unknown</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>