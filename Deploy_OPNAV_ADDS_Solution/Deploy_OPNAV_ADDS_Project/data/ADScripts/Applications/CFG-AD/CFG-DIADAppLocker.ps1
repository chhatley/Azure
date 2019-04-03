#region Includes
#Include PS Environment
. ..\..\Scripts\Custom\PSEnvironment.ps1
#Exit the script if previous one in a Task Sequence failed
try{If ($Global:TSEnv.Value("ContinueOnError") -eq "NO" -and $Global:TSEnv.Value("LastActionStatus") -eq "ERROR"){
        $Global:ErrorCode = -9999;$Global:ErrorMessage = "The last action failed.  Terminating this script.";Exit-Script}}catch{}

#Set the trap
trap{try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
    $Global:ErrorCode = 3;$Global:ErrorMessage = "Exception: $($_.Exception.GetType().FullName) $($_.Exception.Message)";Exit-Script}
#endregion---------------------------------------------------------------------------------------------------------------------------------------------

#Configure Local Variables
#$currentDir = (Get-Item -Path ".\" -Verbose).FullName
$sSourceDir = $sLocalDir + "\ExportImportAD"
Add-log -LogEntry ("source folder = $sSourceDir")
$sGPODir = $sSourceDir + "\GPO"
$sAppLockerDir = $sSourceDir + "\Applocker"
$sEMETDir = $sSourceDir + "\EMET"
Add-log -LogEntry ("GPO folder = $sGPODir")


# Start MAIN

#$sCMD = "$sSourceDir\ExportImport-AD.ps1 -restore -backupfolder $sGPODir -restorepolicies -linkGPOs -restoreous -restoreusers -restoregroups -restorememberships -settingsfile settings.xml -RestorePermissions -PermissionsFile $sSourceDir\RoleDefinitions.xml -Force"

#$sCMD = "$sSourceDir\ExportImport-AD.ps1 -RestoreAll -backupfolder $sSourceDir -linkGPOs -settingsfile settings.xml -PermissionsFile $sSourceDir\RoleDefinitions.xml -Force"

#Add-log -LogEntry ("command is $sCMD")

#Invoke-Expression $sCMD

#set-location $currentdir
#$sSourceDir = $currentDir
#$sSourceDir = $currentdir + "\ExportImportAD"
$sCMD1 = "$sSourceDir\ImportAppLocker.ps1 -backupfolder $sSourceDir"

Add-log -LogEntry ("command is $sCMD1")

Invoke-Expression $sCMD1

#$sCMD2 = "$sSourceDir\ImportEMET55.ps1 -backupfolder $sSourceDir"

#Add-log -LogEntry ("command is $sCMD2")

#Invoke-Expression $sCMD2

#$DomainDN = get-ADDomain |select -ExpandProperty DistinguishedName

#Set-GPLink -Name "MSFT Windows Server 2012 R2 Domain Controller Baseline" -Target "ou=Domain Controllers,$DomainDN" -LinkEnabled Yes

#Set-XADWellKnownContainer ComputersContainer "OU=Computer Quarantine,$DomainDN"

#END MAIN



Exit-Script

