<Sysmon schemaversion="4.30">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <DnsQuery>
                <Image condition="contains">wiseman.exe</Image>
            </DnsQuery>
            <DnsQuery>
                <Image condition="end with">rundll32.exe</Image>
            </DnsQuery>
            <DnsQuery>
                <Image condition="contains any">mstsc.exe;ssh.exe;plink.exe</Image>
            </DnsQuery>
            <DnsQuery>
                <Image condition="contains any">net.exe;ping.exe;tracert.exe</Image>
            </DnsQuery>
        </RuleGroup>
    </EventFiltering>
</Sysmon>