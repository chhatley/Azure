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
$currentDir = (Get-Item -Path ".\" -Verbose).FullName
$sSourceDir = "C:\ExportImportAD"
Add-log -LogEntry ("source folder = $sSourceDir")
$sGPODir = $sSourceDir + "\GPO"
$sAppLockerDir = $sSourceDir + "\Applocker"
$sEMETDir = $sSourceDir + "\EMET"
Add-log -LogEntry ("GPO folder = $sGPODir")

#Functions

Function Add-XADEnum ($name, [string[]]$values) {
$code = @"
  public enum $name : int {
      $($values -join ",`n")
  }
"@
Add-Type $code
}

Add-XADEnum WellKnownGuid UsersContainer, ComputersContainer, SystemsContainer, DCContainer, InfrastructureContainer, DeletedObjectsContainer, LostAndFoundContainer, ForeignSecurityPrincipalContainer, ProgramDataContainer, MicrosoftProgramDataContainer, NtdsQuotasContainer, ManagedServiceAccountContainer

Function Get-XADWellKnownGuid ([WellKnownGuid] $wkGuidEnum) {
switch ($wkGuidEnum) {
   UsersContainer { return "A9D1CA15768811D1ADED00C04FD8D5CD" } 
   ComputersContainer { return  "AA312825768811D1ADED00C04FD8D5CD" }
   SystemsContainer { return  "AB1D30F3768811D1ADED00C04FD8D5CD" }
   DCContainer { return  "A361B2FFFFD211D1AA4B00C04FD7D83A" }
   InfrastructureContainer { return  "2FBAC1870ADE11D297C400C04FD8D5CD" }
   DeletedObjectsContainer { return  "18E2EA80684F11D2B9AA00C04F79F805" }
   LostAndFoundContainer { return  "AB8153B7768811D1ADED00C04FD8D5CD" }
   ForeignSecurityPrincipalContainer { return  "22B70C67D56E4EFB91E9300FCA3DC1AA" }
   ProgramDataContainer { return  "09460C08AE1E4A4EA0F64AEE7DAA1E5A"}
   MicrosoftProgramDataContainer { return  "F4BE92A4C777485E878E9421D53087DB" }
   NtdsQuotasContainer { return  "6227F0AF1FC2410D8E3BB10615BB5B0F" }
   ManagedServiceAccountContainer { return  "1EB93889E40C45DF9F0C64D23BBB6237" }
}
throw New-Object System.Management.Automation.PSArgumentException("Invalid wkGuid")
}


Function Get-XADWellKnownContainer ([WellKnownGuid] $wkGuidEnum) {
   if ($wkGuidEnum -eq $null)
   {
       [Enum]::GetNames([WellKnownGuid]) | %{ $_.PadRight(30) + " : "+(Get-XADWellKnownContainer $_)}
   }
   else
   {
       $wkGuid = Get-XADWellKnownGuid $wkGuidEnum
       $rootDSE = Get-ADRootDSE
       $currentWellKnownObjectList = New-Object -Type System.Collections.ArrayList
       $currentWellKnownObjectList.AddRange((Get-ADObject $rootDSE.DefaultNamingContext -Properties wellKnownObjects).wellKnownObjects)
       $currentWellKnownObjectList.AddRange((Get-ADObject $rootDSE.DefaultNamingContext -Properties otherWellKnownObjects).otherWellKnownObjects)
       foreach ($wkObj in $currentWellKnownObjectList) {
          $idx = $wkObj.IndexOf($wkGuid, [StringComparison]::OrdinalIgnoreCase)
          if ($idx  -ne -1) {
              $wkObj.SubString($idx + $wkGuid.Length + 1)
          }
       }
   }
}

Function Set-XADWellKnownContainer ([WellKnownGuid] $wkGuidEnum, [Object] $newContainer) {
    $rootDSE = Get-ADRootDSE
    $newContainerDN = (Get-ADObject $newContainer).DistinguishedName
    $wkGuid = Get-XADWellKnownGuid $wkGuidEnum
    $currContainerDN = Get-XADWellKnownContainer $wkGuidEnum
    $newContainerValue = "B:32:" + $wkGuid + ":" + $newContainerDN
    $currContainerValue = "B:32:" + $wkGuid + ":" + $currContainerDN
    $pdcServer = (Get-ADDomain).PDCEmulator
    $wellKnownObjAttributeName = "wellKnownObjects"
    if ($wkGuidEnum -eq [WellKnownGuid]::ManagedServiceAccountContainer) {
        $wellKnownObjAttributeName = "otherWellKnownObjects"
    }
    
    Set-ADObject $rootDSE.DefaultNamingContext -Add @{ $wellKnownObjAttributeName = $newContainerValue } -Remove @{ $wellKnownObjAttributeName = $currContainerValue } -server $pdcServer
}


# END Functions

# Start MAIN

#$sCMD = "$sSourceDir\ExportImport-AD.ps1 -restore -backupfolder $sGPODir -restorepolicies -linkGPOs -restoreous -restoreusers -restoregroups -restorememberships -settingsfile settings.xml -RestorePermissions -PermissionsFile $sSourceDir\RoleDefinitions.xml -Force"

$sCMD = "$sSourceDir\ExportImport-AD.ps1 -RestoreAll -backupfolder $sSourceDir -linkGPOs -settingsfile settings.xml -PermissionsFile $sSourceDir\RoleDefinitions.xml -Force"

Add-log -LogEntry ("command is $sCMD")

Invoke-Expression $sCMD

#set-location $currentdir
#$sSourceDir = $currentDir
#$sSourceDir = $currentdir + "\ExportImportAD"
#$sCMD1 = "$sSourceDir\ImportAppLocker.ps1 -backupfolder $sSourceDir"

#Add-log -LogEntry ("command is $sCMD1")

#Invoke-Expression $sCMD1

#$sCMD2 = "$sSourceDir\ImportEMET55.ps1 -backupfolder $sSourceDir"

#Add-log -LogEntry ("command is $sCMD2")

#Invoke-Expression $sCMD2

#$DomainDN = get-ADDomain |select -ExpandProperty DistinguishedName

#Set-GPLink -Name "MSFT Windows Server 2012 R2 Domain Controller Baseline" -Target "ou=Domain Controllers,$DomainDN" -LinkEnabled Yes

#Set-XADWellKnownContainer ComputersContainer "OU=Computer Quarantine,$DomainDN"

#END MAIN



Exit-Script

