#region Includes
#Include PS Environment
. ..\..\Scripts\Custom\PSEnvironment.ps1
. ..\..\Scripts\Custom\ADEnvironment.ps1
#Exit the script if previous one in a Task Sequence failed
try{If ($Global:TSEnv.Value("ContinueOnError") -eq "NO" -and $Global:TSEnv.Value("LastActionStatus") -eq "ERROR"){
        $Global:ErrorCode = -9999;$Global:ErrorMessage = "The last action failed.  Terminating this script.";Exit-Script}}catch{}

#Set the trap
trap{try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
    $Global:ErrorCode = 3;$Global:ErrorMessage = "Exception: $($_.Exception.GetType().FullName) $($_.Exception.Message)";Exit-Script}
#endregion---------------------------------------------------------------------------------------------------------------------------------------------

Import-module AdmPwd.PS
Add-Log -LogEntry ("Updating AD Schema for LAPS")
Update-AdmPwdADSchema

# Get the OU with ESAE Objects.
#$DomainName = (Get-ADDomain).NetBIOSName
#$DN = (Get-ADDomain).DistinguishedName
#$Adminou = "OU=Admin," + $DN
#Add-Log -LogEntry ("Setting Permissions for LAPS on: " + $Adminou)
#Set-AdmPwdComputerSelfPermission -OrgUnit $Adminou
#$WorkstationOU = "OU=Devices," + $DN
#Add-Log -LogEntry ("Setting Permissions for LAPS on: " + $Workstationou)
#Set-AdmPwdComputerSelfPermission -OrgUnit $Workstationou
#$Tier1ServersOU = "OU=Tier 1 Servers," + $DN
#Add-Log -LogEntry ("Setting Permissions for LAPS on: " + $Tier1ServersOU)
#Set-AdmPwdComputerSelfPermission -OrgUnit $Tier1ServersOU