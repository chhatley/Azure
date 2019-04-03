#region Includes
#Include PS Environment
. ..\..\Scripts\Custom\PSEnvironment.ps1
. ..\..\Scripts\Custom\ADEnvironment.ps1
#Exit the script if previous one in a Task Sequence failed
#try{If ($Global:TSEnv.Value("ContinueOnError") -eq "NO" -and $Global:TSEnv.Value("LastActionStatus") -eq "ERROR"){
#        $Global:ErrorCode = -9999;$Global:ErrorMessage = "The last action failed.  Terminating this script.";Exit-Script}}catch{}

#Set the trap
#trap{try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
#    $Global:ErrorCode = 3;$Global:ErrorMessage = "Exception: $($_.Exception.GetType().FullName) $($_.Exception.Message)";Exit-Script}
#endregion---------------------------------------------------------------------------------------------------------------------------------------------

#Configure Local Variables
$sSourceDir = $sLocalDir + "\Source"
$sPWDFilePath = "C:\Windows\Temp\PWD.txt"

#Add-Log -LogEntry("!!!!!!WARNING!!!!! The Administrator password will be stored in " + $sPWDFilePath)
#Add-Log -LogEntry("Document the password then permanantly delete the file.")
  
$Accounts = Import-Csv $sSourceDir"\Accounts.csv"
foreach ($oAccounts in $Accounts){
    $oPWD = (Generate-PWD)
    #Add-Content $sPWDFilePath ($oAccounts.samAccountName + " " + $oPWD)
    Add-Log -LogEntry("Creating the account " + $oAccounts.Name + " in " + (Get-OU($oAccounts.OU)))
    New-ADUser -Name $oAccounts.Name -samAccountName $oAccounts.samAccountName -Description $oAccounts.Description -Path (Get-OU($oAccounts.OU)) -AccountPassword (ConvertTo-SecureString $oPWD -AsPlainText -force) -Enabled $true -PasswordNeverExpires $true -ErrorAction SilentlyContinue

    If ($oAccounts.Membership -ne ""){
        Add-Log -LogEntry("Adding " + $oAccounts.Name + " to " + $oAccounts.Membership)
        Add-ADPrincipalGroupMembership -Identity $oAccounts.samAccountName -MemberOf $oAccounts.Membership -ErrorAction SilentlyContinue
    }
    $error.Clear()

 }

Exit-Script