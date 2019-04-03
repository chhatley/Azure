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
$DomainName = (Get-ADDomain).Name

$oComputers = Import-Csv $sSourceDir"\Computers.csv"
foreach ($oComputer in $oComputers){
	#use Regular expression to validate the computer name
	$RegEx = "^[a-zA-Z0-9_\-]{1,15}"
	$oComputer.Name -match $RegEx
	if ($oComputer.Name -eq $matches[0])
	{	
		Add-Log -LogEntry("Creating the computer " + $oComputer.Name + " in " + (Get-OU($oComputer.OU)))    
		New-ADComputer -Name $oComputer.Name -samAccountName $oComputer.Name -Path (Get-OU($oComputer.OU)) -Enabled $true
		If ($oComputer.Membership -ne ""){
			Add-Log -LogEntry("Adding " + $oComputer.Name + "$ to " + $oComputer.Membership)
			Add-ADPrincipalGroupMembership -Identity ($oComputer.Name + "$") -MemberOf $oComputer.Membership
		}
		$error.Clear()
		#Grant-Permissions($oComputer.Name)
	}
}    

Exit-Script