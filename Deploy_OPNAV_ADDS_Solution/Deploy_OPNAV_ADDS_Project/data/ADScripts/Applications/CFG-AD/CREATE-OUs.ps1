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

$sPath = ("OU="+ $DomainName + " Objects," + $($sDSE))

New-ADOrganizationalUnit -Name "$DomainName Objects" -Path $($sDSE)
New-ADOrganizationalUnit -Name "Staging" -Path ("OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "Groups" -Path ("OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "Service Accounts" -Path ("OU="+ $DomainName + " Objects," + $($sDSE))

New-ADOrganizationalUnit -Name "Production Administration" -Path ("OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "Admin Desktops" -Path ("OU=Production Administration,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "Breakglass Accounts" -Path ("OU=Production Administration,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "Gold Card Administration" -Path ("OU=Production Administration,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "Red Card Administration" -Path ("OU=Production Administration,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "White Card Administration" -Path ("OU=Production Administration,OU="+ $DomainName + " Objects," + $($sDSE))
#New-ADOrganizationalUnit -Name "Secure Server Administration" -Path ("OU=Production Administration,OU="+ $DomainName + " Objects," + $($sDSE))
#New-ADOrganizationalUnit -Name "Secure Workstation Administration" -Path ("OU=Production Administration,OU="+ $DomainName + " Objects," + $($sDSE))

New-ADOrganizationalUnit -Name "Servers" -Path ("OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "CA Servers" -Path ("OU=Servers,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "SCOM Servers" -Path ("OU=Servers,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "SQL Servers" -Path ("OU=Servers,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "WSUS Servers" -Path ("OU=Servers,OU="+ $DomainName + " Objects," + $($sDSE))
New-ADOrganizationalUnit -Name "Hyper-V Servers" -Path ("OU=Servers,OU="+ $DomainName + " Objects," + $($sDSE))

Exit-Script