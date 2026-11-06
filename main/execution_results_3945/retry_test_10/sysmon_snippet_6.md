<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <!-- Path contains C:\Users\ -->
        <Rule groupRelation="and">
          <Image condition="contains">C:\Users\</Image>
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
        <!-- Path contains C:\Temp\ -->
        <Rule groupRelation="and">
          <Image condition="contains">C:\Temp\</Image>
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
        <!-- Suspicious driver name svhostx.sys -->
        <Rule groupRelation="and">
          <Image condition="image">svhostx.sys</Image>
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
        <!-- Suspicious driver name winhelp.sys -->
        <Rule groupRelation="and">
          <Image condition="image">winhelp.sys</Image>
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
        <!-- Driver name contains the word “service” -->
        <Rule groupRelation="and">
          <Image condition="contains">service</Image>
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
        <!-- Any unsigned/invalid .sys driver -->
        <Rule groupRelation="and">
          <Image condition="end with">.sys</Image>
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is">Invalid</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>