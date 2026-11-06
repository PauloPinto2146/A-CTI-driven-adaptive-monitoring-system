<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="end with">.sys</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Signed condition="is">false</Signed>
        </Rule>
        <Rule groupRelation="and">
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="begin with">C:\Temp\</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="begin with">C:\ProgramData\</ImageLoaded>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>