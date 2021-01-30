<# 
.SYNOPSIS 
    Get the DNS information from each domain controller to a CSV file
.DESCRIPTION 
    PS Remote into each domain controller (that is expected to be a 
	DNS server) and get DNS information for interfaces and forwarders
.EXAMPLE 
    PS Get-DcDnsInformation.ps1 'mycsvfile.csv'
    
		HostName       : hostnamehere
		OsVersionName  : Microsoft Windows Server 2008 R2 Standard 
		InterfaceName  : HP Network Team #1
		InterfaceIp    : iphere
		InterfaceDns   : dns1, dns2, dns3, etc  # (a string)
		DnsForwarders  : dnsfwd1, dnsfwd2, dnsfwd3, etc  # (a string)
		PSComputerName : pscompnamehere
		RunspaceId     : biglongstring
.NOTES 
	Author: Don Hess
    Version History:
    1.0    2016-07-03   Release
#>
Param(
    [Parameter(Mandatory=$true,
			   ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=0,
			   HelpMessage='Full path of CSV output file')]
    [ValidateNotNullOrEmpty()]
    [Alias('Path')]
    [string] $CsvFile,

    [Parameter(Mandatory=$false,
			   ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=1,
			   HelpMessage='PS remoting credential object')]
    [System.Management.Automation.PSCredential] $Cred
)

$scriptBlock1 = [System.Management.Automation.ScriptBlock]::Create(@'
function fHostObjectFactory() {
	$oReturned = New-Object -TypeName System.Management.Automation.PSObject
	Add-Member -InputObject $oReturned -MemberType NoteProperty -Name "HostName" -Value $null
	Add-Member -InputObject $oReturned -MemberType NoteProperty -Name "OsVersionName" -Value $null
	Add-Member -InputObject $oReturned -MemberType NoteProperty -Name "InterfaceName" -Value $null
	Add-Member -InputObject $oReturned -MemberType NoteProperty -Name "InterfaceIp" -Value $null
	Add-Member -InputObject $oReturned -MemberType NoteProperty -Name "InterfaceDns" -Value $null
	Add-Member -InputObject $oReturned -MemberType NoteProperty -Name "DnsForwarders" -Value $null
	return $oReturned
}
'@) # End scriptblock1
$scriptBlock2 = [System.Management.Automation.ScriptBlock]::Create(@'
# Get the interface information  
$aInterfaces = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq "True"})
$aInterfaces | ForEach-Object {
	$oInterface = $_

    $oHost = fHostObjectFactory
    $oHost.HostName = $env:ComputerName
    # Get the readable OS version
    $oHost.OsVersionName = (Get-WmiObject -Class Win32_OperatingSystem).Caption

    # Get the DNS Server forwarders
    $oDnsServer = Get-WmiObject -Namespace "root\MicrosoftDNS" -Class MicrosoftDNS_server
    $oHost.DnsForwarders = @($oDnsServer.Forwarders) -join ', '

	$oHost.InterfaceName = $oInterface.Description                  
	$oHost.InterfaceIp = @($oInterface.IPAddress) -join ','
	$oHost.InterfaceDns = @($oInterface.DNSServerSearchOrder) -join ', '
    $oHost
}
'@) # End scriptblock2
if ($null -eq $Cred) {
	$Cred = Get-Credential
}
Import-Module ActiveDirectory
. $scriptBlock1 # Import our functions into this session
$aResults = @()
# Get all DCs (in our case, they are also all the DNS servers)
$aDcs = Get-ADDomainController -Filter * | Select -Expand Name | Sort
$aDcs | ForEach-Object {
	$sDcName = $_
	Write-Host "Working on $sDcName"
	try {
		$sessionSrv1 = New-PSSession -ComputerName $sDcName -Credential $Cred -ErrorAction Stop
		Write-Host "  Session created for $sDcName"
		Invoke-Command -Session $sessionSrv1 -ScriptBlock $scriptBlock1 -ErrorAction Stop
		$oSingeResult = (Invoke-Command -Session $sessionSrv1 -ScriptBlock $scriptBlock2 -ErrorAction Stop)
		Write-Host "  Results returned for $sDcName"
	}
	catch { # Just set up a dummy object so the user sees something didn't work
		$err = $_
		$oSingeResult = fHostObjectFactory
		$oSingeResult.HostName = $sDcName
		if ($err.Exception.ErrorRecord.ToString().Length -gt 80) {
			$iErrLen = 80
		} else {
			$iErrLen = $err.Exception.ErrorRecord.ToString().Length
		}
		$oSingeResult.OsVersionName = $err.Exception.ErrorRecord.ToString().Substring(0,$iErrLen)
	}
	if ($oSingeResult.HostName -ne $sDcName) {
		$textOut = "Server name mismatch, expected '$sDcName' but logged into '"+$oSingeResult.HostName+"'"
		throw $textOut
	}
	$aResults += $oSingeResult
	Remove-PSSession $sessionSrv1 -ErrorAction SilentlyContinue
}
$aResults | Export-Csv -Path $CsvFile
