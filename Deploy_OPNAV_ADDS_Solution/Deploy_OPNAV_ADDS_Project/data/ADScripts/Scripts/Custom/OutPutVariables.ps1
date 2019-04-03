#Include PS Functions
$sLocalDir = Split-Path $MyInvocation.MyCommand.Path
Set-Location $sLocalDir
. .\PSUtility.ps1
try{
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    Write-Host $tsenv.Value("_SMSTSLogPath")
    Write-Host "DHCPStartSubnet="$tsenv.Value("DHCPStartSubnet")
    Write-Host "DHCPEndSubnet="$tsenv.Value("DHCPEndSubnet")
    Write-Host "DHCPSubnetMask=" $tsenv.Value("DHCPSubnetMask")
    Write-Host "DomainName=" $tsenv.Value("DomainName")
}
catch{
    AddLog "Not in TS environment.  Cannot Proceed"
}