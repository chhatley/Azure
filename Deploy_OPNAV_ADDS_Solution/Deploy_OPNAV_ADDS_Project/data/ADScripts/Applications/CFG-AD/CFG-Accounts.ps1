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

#Configure Local Variables
$sSourceDir = $sLocalDir + "\Source"

(Get-OU("Breakglass*"))

#Move the administrator account to the Breakglass OU
#Move-ADObject -Identity (Get-User("administrator")) -TargetPath (Get-OU("Breakglass*"))
$sid = (Get-ADDomain).domainsid 
$sid = $sid.ToString() + "-500" 
Move-ADObject -Identity (Get-ADUser -Identity $sid) -TargetPath (Get-OU("Breakglass*"))

#Add the administrator to the SCOM\SQL groups
#Add-ADGroupMember -Identity "SQLAdmins" -Members "Administrator"
#Add-ADGroupMember -Identity "SCOMAdmins" -Members "Administrator"
Add-ADGroupMember -Identity "SQLAdmins" -Members $sid
Add-ADGroupMember -Identity "SCOMAdmins" -Members $sid

Exit-Script