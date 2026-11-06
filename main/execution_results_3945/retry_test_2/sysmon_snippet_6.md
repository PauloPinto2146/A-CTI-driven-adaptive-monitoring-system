<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <!-- Unsigned drivers (.sys) -->
        <Rule groupRelation="and">
          <Image condition="end with">.sys</Image>
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is">Unsigned</SignatureStatus>
        </Rule>
        <!-- Drivers with invalid signature -->
        <Rule groupRelation="and">
          <Image condition="end with">.sys</Image>
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
        <!-- Drivers loaded from user profile directories -->
        <Rule groupRelation="and">
          <Image condition="begin with">C:\Users\</Image>
          <Image condition="end with">.sys</Image>
        </Rule>
        <!-- Drivers loaded from temporary directories -->
        <Rule groupRelation="and">
          <Image condition="begin with">C:\Temp\</Image>
          <Image condition="end with">.sys</Image>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>