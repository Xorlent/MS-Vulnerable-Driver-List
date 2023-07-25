# This tool is for machines that do not support Microsoft's vulnerable driver blocklist.
# The resulting SHA256 hash list can be loaded into many EDR products for detection and/or blocking.
 
<#
FROM https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936
--------------------------------------------------------------------------------------------------------------------
Microsoft introduced the vulnerable driver blocklist as an optional feature in Windows 10, version 1809.
The blocklist is enabled on systems that enable Hypervisor-protected Code Integrity (HVCI) or run Windows in S Mode.
Starting with Windows 11, version 22H2, the blocklist is also enabled by default on all devices.
#>
 
# The vulnerable driver blocklist can be downloaded from https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml
 
# Load the XML file
$DefaultxmlFilePath = './MSHashes.xml'
$xmlFilePath=Read-Host -Prompt "Enter the Microsoft vulnerable drivers source file name or press enter to accept the default of [$($DefaultxmlFilePath)]"
if ($xmlFilePath.Length -eq 0) {$xmlFilePath = $DefaultxmlFilePath}
$xml = [xml](Get-Content $xmlFilePath)
 
# Define the namespace used in the XML file
$ns = New-Object Xml.XmlNamespaceManager($xml.NameTable)
$ns.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy")
 
# Select <Deny> nodes that have a Hash attribute
$denyNodes = $xml.SelectNodes("//ns:Deny[@Hash]", $ns)
 
# Filter and extract only the SHA256 hash values
$output = $denyNodes | Where-Object {
   $_.Hash.Length -eq 64  # Filter by hash length
} | ForEach-Object {
   $_.Hash
}
 
# Output the extracted SHA256 hash values to a text file
$LaunchDTS = (Get-Date).ToString("MMddyy-HHmmss")
$outputFilePath = "./MS-Hashes-" + $LaunchDTS + ".txt"
$output | Out-File -FilePath $outputFilePath -Encoding UTF8