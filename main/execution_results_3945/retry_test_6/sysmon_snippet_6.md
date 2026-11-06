<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <Signed condition="is not">true</Signed>
        </Rule>
      </DriverLoad>
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="not begin with">C:\Windows\System32\drivers</ImageLoaded>
        </Rule>
      </DriverLoad>
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>