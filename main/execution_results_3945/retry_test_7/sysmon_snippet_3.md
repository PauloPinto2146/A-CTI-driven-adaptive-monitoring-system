<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Include_Malicious_NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: specific malicious executable -->
        <Rule name="IOC_wiseman" groupRelation="and">
          <Image condition="image">wiseman.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: rundll32 used for any outbound connection -->
        <Rule name="Behavior_rundll32_any" groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: rundll32 DNS queries (port 53) -->
        <Rule name="Behavior_rundll32_dns" groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <DestinationPort condition="is">53</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: PowerShell DNS queries (port 53) -->
        <Rule name="Behavior_powershell_dns" groupRelation="and">
          <Image condition="image">powershell.exe</Image>
          <DestinationPort condition="is">53</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Python DNS queries (port 53) -->
        <Rule name="Behavior_python_dns" groupRelation="and">
          <Image condition="image">python.exe</Image>
          <DestinationPort condition="is">53</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: Remote Services – RDP -->
        <Rule name="Derived_RDP" groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: Remote Services – SSH -->
        <Rule name="Derived_SSH" groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">22</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: Remote Services – VNC -->
        <Rule name="Derived_VNC" groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">5900</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: SMB enumeration via net.exe -->
        <Rule name="Derived_SMB_netexe" groupRelation="and">
          <Image condition="image">net.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: SMB enumeration via cmd.exe -->
        <Rule name="Derived_SMB_cmdexe" groupRelation="and">
          <Image condition="image">cmd.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: SMB enumeration via powershell.exe -->
        <Rule name="Derived_SMB_powershell" groupRelation="and">
          <Image condition="image">powershell.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: Dead‑drop resolver – HTTP (port 80) via rundll32 -->
        <Rule name="Derived_HTTP_deadDrop_rundll32" groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">80</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: Dead‑drop resolver – HTTPS (port 443) via rundll32 -->
        <Rule name="Derived_HTTPS_deadDrop_rundll32" groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">443</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>