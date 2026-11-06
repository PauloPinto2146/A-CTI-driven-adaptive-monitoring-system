<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <!-- Drivers loaded from user‑writable locations -->
        <Rule groupRelation="or">
          <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
        </Rule>
        <Rule groupRelation="or">
          <ImageLoaded condition="begin with">C:\Temp\</ImageLoaded>
        </Rule>

        <!-- Unsigned drivers -->
        <Rule groupRelation="and">
          <Signed condition="is">false</Signed>
        </Rule>

        <!-- Drivers with invalid or missing signatures -->
        <Rule groupRelation="and">
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>