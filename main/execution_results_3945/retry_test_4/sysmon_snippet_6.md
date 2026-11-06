<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad>
        <!-- Unsigned driver with .sys extension -->
        <Rule groupRelation="and">
          <ImageLoaded condition="end with">.sys</ImageLoaded>
          <Signed condition="is">false</Signed>
        </Rule>
        <!-- Driver with non‑valid signature and .sys extension -->
        <Rule groupRelation="and">
          <ImageLoaded condition="end with">.sys</ImageLoaded>
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
        <!-- Driver loaded from uncommon user directory -->
        <Rule groupRelation="and">
          <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
          <ImageLoaded condition="end with">.sys</ImageLoaded>
        </Rule>
        <!-- Driver loaded from uncommon temp directory -->
        <Rule groupRelation="and">
          <ImageLoaded condition="begin with">C:\Temp\</ImageLoaded>
          <ImageLoaded condition="end with">.sys</ImageLoaded>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>