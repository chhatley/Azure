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
$DomainName = (Get-ADDomain).NetBIOSName
$DN = (Get-ADDomain).DistinguishedName
$ou = "OU=" + $DomainName + " Objects," + $DN
Add-Log -LogEntry ("Setting Permissions for LAPS on: " + $ou)
Set-AdmPwdComputerSelfPermission -OrgUnit $ou