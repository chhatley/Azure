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


$DomainName = (Get-ADDomain).NetBIOSName
$sDSE = (Get-ADRootDSE).defaultNamingContext

#$sPath = ("OU="+ $DomainName + " Objects," + $($sDSE))

#Creating Top Level OUs

New-ADOrganizationalUnit -Name "Admin" -Path $($sDSE)
New-ADOrganizationalUnit -Name "Groups" -Path $($sDSE)
New-ADOrganizationalUnit -Name "Tier 1 Servers" -Path $($sDSE)
New-ADOrganizationalUnit -Name "Workstations" -Path $($sDSE)
New-ADOrganizationalUnit -Name "User Accounts" -Path $($sDSE)
New-ADOrganizationalUnit -Name "Computer Quarantine" -Path $($sDSE)


#Creating Sub OUs for Top Level Admin OU

    New-ADOrganizationalUnit -Name "Tier 0" -Path ("OU=Admin," + $($sDSE))
    New-ADOrganizationalUnit -Name "Tier 1" -Path ("OU=Admin," + $($sDSE))
    New-ADOrganizationalUnit -Name "Tier 2" -Path ("OU=Admin," + $($sDSE))
    New-ADOrganizationalUnit -Name "Staging" -Path ("OU=Admin," + $($sDSE))
#Creating Sub OUs for Admin\Tier 0 OU

        New-ADOrganizationalUnit -Name "Accounts" -Path ("OU=Tier 0,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Groups" -Path ("OU=Tier 0,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Service Accounts" -Path ("OU=Tier 0,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Devices" -Path ("OU=Tier 0,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Tier 0 Servers" -Path ("OU=Tier 0,OU=Admin," + $($sDSE))

#Creating Sub OUs for Admin\Tier 1 OU

        New-ADOrganizationalUnit -Name "Accounts" -Path ("OU=Tier 1,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Groups" -Path ("OU=Tier 1,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Service Accounts" -Path ("OU=Tier 1,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Devices" -Path ("OU=Tier 1,OU=Admin," + $($sDSE))

#Creating Sub OUs for Admin\Tier 1\Groups OU

        New-ADOrganizationalUnit -Name "Admins" -Path ("OU=Groups,OU=Tier 1,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Users" -Path ("OU=Groups,OU=Tier 1,OU=Admin," + $($sDSE))

#Creating Sub OUs for Admin\Tier 2 OU

        New-ADOrganizationalUnit -Name "Accounts" -Path ("OU=Tier 2,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Groups" -Path ("OU=Tier 2,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Service Accounts" -Path ("OU=Tier 2,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Devices" -Path ("OU=Tier 2,OU=Admin," + $($sDSE))

#Creating Sub OUs for Admin\Tier 2\Groups OU

        New-ADOrganizationalUnit -Name "Admins" -Path ("OU=Groups,OU=Tier 2,OU=Admin," + $($sDSE))
        New-ADOrganizationalUnit -Name "Users" -Path ("OU=Groups,OU=Tier 2,OU=Admin," + $($sDSE))

#Creating Sub OUs for Top Level Groups OU

    New-ADOrganizationalUnit -Name "Security Groups" -Path ("OU=Groups," + $($sDSE))
    New-ADOrganizationalUnit -Name "Distribution Groups" -Path ("OU=Groups," + $($sDSE))
    New-ADOrganizationalUnit -Name "Contacts" -Path ("OU=Groups," + $($sDSE))

#Creating Sub OUs for Top Level Tier 1 Servers OU

    New-ADOrganizationalUnit -Name "Application" -Path ("OU=Tier 1 Servers," + $($sDSE))
    New-ADOrganizationalUnit -Name "Collaboration" -Path ("OU=Tier 1 Servers," + $($sDSE))
    New-ADOrganizationalUnit -Name "Database" -Path ("OU=Tier 1 Servers," + $($sDSE))
    New-ADOrganizationalUnit -Name "Messaging" -Path ("OU=Tier 1 Servers," + $($sDSE))
    New-ADOrganizationalUnit -Name "Staging" -Path ("OU=Tier 1 Servers," + $($sDSE))

#Creating Sub OUs for Top Level Workstations OU

    New-ADOrganizationalUnit -Name "Desktops" -Path ("OU=Workstations," + $($sDSE))
    New-ADOrganizationalUnit -Name "Kiosks" -Path ("OU=Workstations," + $($sDSE))
    New-ADOrganizationalUnit -Name "Laptops" -Path ("OU=Workstations," + $($sDSE))
    New-ADOrganizationalUnit -Name "Staging" -Path ("OU=Workstations," + $($sDSE))

#Creating Sub OUs for Top Level User Accounts OU

    New-ADOrganizationalUnit -Name "Enabled Users" -Path ("OU=User Accounts," + $($sDSE))
    New-ADOrganizationalUnit -Name "Disabled Users" -Path ("OU=User Accounts," + $($sDSE))

#Block inheritance for PAW OUs

    Import-Module ServerManager
    Add-WindowsFeature Gpmc | Out-Null
    Import-Module GroupPolicy

    Set-GpInheritance -target "OU=Devices,OU=Tier 0,OU=Admin,$sDSE" -IsBlocked Yes | Out-Null
    Set-GpInheritance -target "OU=Devices,OU=Tier 1,OU=Admin,$sDSE" -IsBlocked Yes | Out-Null
    Set-GpInheritance -target "OU=Devices,OU=Tier 2,OU=Admin,$sDSE" -IsBlocked Yes | Out-Null

#Exit-Script