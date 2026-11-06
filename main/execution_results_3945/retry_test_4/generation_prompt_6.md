
.Context:
	EventID 6: The driver loaded events provides information about a driver being loaded on the system. The configured hashes are provided as well as signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading.

	These are the applicable tags that you can use:
	ImageLoaded: File path of the driver loaded
Hashes: Hashes captured by Sysmon driver
Signed: Is the driver loaded signed
Signature: Signer name of the driver
SignatureStatus: Status of the signature

	ONLY use these conditions:
	Condition: Description
is: Default, values are equals
is any: The field is one of the ; delimited values
is not: Values are different
contains: The field contains this value
contains any: The field contains any of the ; delimited values
contains all: The field contains all of the ; delimited values
excludes: The field does not contain this value
excludes any: The field does not contain one or more of the ; delimited values
excludes all: The field does not contain any of the ; delimited values
begin with: The field begins with this value
end with: The field ends with this value
not begin with: The field does not begin with this value
not end with: The field does not end with this value
less than: Lexicographical comparison is less than zero
more than: Lexicographical comparison is more than zero
image: Match an image path (full path or only image name)
	Do NOT use any other variation like "end with any" or "image any". That will result in an invalid output.

.Examples
	Examples of rules that exclude benign noise:
	<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="exclude">
        <!--Exclude Intel drivers with valid signature-->
        <Rule groupRelation="and">
          <Signature condition="begin with">Intel </Signature>
          <SignatureStatus condition="is">Valid</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <DriverLoad onmatch="exclude">
                <!--COMMENT:	Because drivers with bugs can be used to escalate to kernel permissions, be extremely selective
				about what you exclude from monitoring. Low event volume, little incentive to exclude.-->
                <!--Exclude Microsoft drivers with valid signature-->
                <Rule groupRelation="and">
                    <Signature condition="contains">Microsoft</Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
            </DriverLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon DriverLoad snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1543.003']
	- Remember to consider the reported indicators of compromise: ['ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205', 'wiseman.EXE', 'fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c', 'wininet.dll']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	