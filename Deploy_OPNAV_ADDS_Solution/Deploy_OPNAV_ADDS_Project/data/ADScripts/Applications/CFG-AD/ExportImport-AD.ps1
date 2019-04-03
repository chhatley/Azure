<#
    .NOTES
        Copyright (c) Microsoft Corporation.  All rights reserved.

        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code. For the terms of the license,
        please see the license agreement between you and Microsoft or, if applicable,
        see the LICENSE.RTF on your install media or the root of your tools installation.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.
       
    .DESCRIPTION 
		V1.9 11 Aug 2015  - Added code for ProtectedFromAccidentalDeletion for OUs
        V1.8 25 July 2016 - Added WMIFilter Import/Export
                          - Fixed the issue where users were not imported because of invalid UPN
                          - Removed the requirements to specify $Backup or $Restore. The script now defines the mode depending on other parameters you pass to it.
		V1.7 21 July 2016 - Added Backup/Restore for Group Description
		V1.6 21 June 2016 - Added -BackupAll and -RestoreAll options
        V1.5 11 May 2016   - Change the code for UpdateMigrationTable to check if the user has write permissions in the local folder. If
                                not, then create the migration table in the %temp% folder
        V1.4 28 April 2016 - Added code for DomainJoin
                           - Added code to backup/restore the following user attributes: CannotChangePassword, PasswordNeverExpires, ChangePasswordAtLogon
                           - Change the export code to remove the local DC path. Using only relative paths now. Removed ForceLocalDomain
                           - Backup/Restore Block GPO Inheritance
        V1.3 23 April 2016 - Added code for BitLocker and TPM
        V1.2 22 April 2016 - Added code to manage OU delegations
        V1.1 21 April 2016 - Added a prompt to use ForceLocalDomain when the local domain is different than the domain in the xml file.
                           - Fixed a bug with ForceLocalDomain
                           - Added code for Get-GPOLink
        V1.0 30 March 2016

FUTURE:
- backup/restore GPO permissions
#>

[CmdLetBinding(DefaultParameterSetName="Backup")]
param(

    [Parameter(Mandatory=$false)]
    [string] $SearchBase,
    [Parameter(Mandatory=$true)]
    [string] $BackupFolder,
    [Parameter(Mandatory=$true)]
    [string] $SettingsFile,
    #[string] $MigrationTable="MigrationTable.migtable",
    [string] $MigrationTable,
    [switch] $Force,

    [Parameter(Mandatory=$false,ParameterSetName="Backup")]
    [switch] $BackupAll,
	[switch] $Backup,
    [switch] $BackupPolicies,
    [switch] $BackupOUs,
    [switch] $BackupUsers,
    [switch] $BackupGroups,
    [switch] $BackupMemberships,
 
    [Parameter(Mandatory=$false,ParameterSetName="Restore")]
	[switch] $RestoreAll,
    [switch] $Restore,
    [switch] $RestoreOUs,
    [switch] $RestoreUsers,
    [switch] $RestoreGroups,
    [switch] $RestoreMemberships,
    [switch] $RestorePolicies,
    [switch] $OverwriteExistingPolicies,
    [switch] $LinkGPOs,
    [string] $TargetDomain,
    #[string] $GroupPolicyFilter,
    [switch] $RestorePermissions,
    [string] $PermissionsFile,
	[bool] $ProtectedFromAccidentalDeletion = $true
)

####################################################################
# Functions  
####################################################################

Function Write-Log($Msg, $category)
{  
#       
#      .DESCRIPTION  
#          Creates a log entry with time stamp
#  
    $logfile=($currentdir + "\log.log")
    $debug=$false
   
    $date = Get-Date -format dd.MM.yyyy  
    $time = Get-Date -format HH:mm:ss  
    Add-Content -Path $LogFile -Value ($date + " " + $time + "   " + $Msg)  
       
    If($debug -eq $true)
    {
       $colours = @{"INFO"="Green";"Warning"="Yellow";"ERROR"="Red"}       
       Write-host -ForegroundColor $colours[$category] $msg     
    }   
} 

Function Backup-Users($path)
{
    #Open the configuration XML file
   $configXML = [xml](Get-Content ($SettingsFile))
              
   #If a searchbase has been defined, only retrieve the searchbase OU and child OU objects           
   If($searchBase){$OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $searchBase -SearchScope Subtree }        
   #If no searchbase, return all OUs and append the domain root (for domain level policies)
   Else
   {        
       $OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase ($strDomainDN) -SearchScope Subtree                          
   }

   foreach($OU in $OUs)
   {
       $error.Clear()         
       #if you want to return any more 
       $userObjects = Get-ADUser -LDAPFilter '(name=*)' -SearchBase $OU.distinguishedName -Properties Description,Department,Title,CannotChangePassword,PasswordNeverExpires,PasswordExpired -SearchScope OneLevel
        
       Foreach ($user in $userObjects)
       {
            $userObjectElement = $configXML.CreateElement("User")
            $userObjectElement.SetAttribute("Name", $user.Name)
            $userObjectDN = $configXML.CreateElement("distinguishedName")
            #$userObjectDN.Set_InnerText($user.distinguishedName)
            $DN = $user.distinguishedName -replace((([regex]::matches(($user.distinguishedName),"(?i)DC=[^,]*") | % {$_.value}) -join ","),"")
            $userObjectDN.Set_InnerText($DN)
            $userObjectElement.AppendChild($userObjectDN) | out-null
                                  
            $userObjectUPN = $configXML.CreateElement("UserPrincipalName")
            #$userObjectUPN.Set_InnerText($user.UserPrincipalName)
            $upn = $user.UserPrincipalName -replace((([regex]::matches(($user.UserPrincipalName),"@[^,]*") | % {$_.value}) -join ""),"")
            $userObjectUPN.Set_InnerText($upn)
            $userObjectElement.AppendChild($userObjectUPN) | out-null

            $userObjectSAM = $configXML.CreateElement("SamAccountName")
            $userObjectSAM.Set_InnerText($user.SamAccountName)
            $userObjectElement.AppendChild($userObjectSAM) | out-null

            $userObjectGN = $configXML.CreateElement("GivenName")
            $userObjectGN.Set_InnerText($user.GivenName)
            $userObjectElement.AppendChild($userObjectGN) | out-null

            $userObjectSN = $configXML.CreateElement("Surname")
            $userObjectSN.Set_InnerText($user.Surname)
            $userObjectElement.AppendChild($userObjectSN) | out-null

            $userObjectDesc = $configXML.CreateElement("Description")
            $userObjectDesc.Set_InnerText($user.Description)
            $userObjectElement.AppendChild($userObjectDesc) | out-null 
            

            $userObjectCCP = $configXML.CreateElement("CannotChangePassword")
            $userObjectCCP.Set_InnerText($user.CannotChangePassword)
            $userObjectElement.AppendChild($userObjectCCP) | out-null   

            $userObjectPNE = $configXML.CreateElement("PasswordNeverExpires")
            $userObjectPNE.Set_InnerText($user.PasswordNeverExpires)
            $userObjectElement.AppendChild($userObjectPNE) | out-null 
         
            $userObjectCPAL = $configXML.CreateElement("ChangePasswordAtLogon")
            $userObjectCPAL.Set_InnerText($user.PasswordExpired)
            $userObjectElement.AppendChild($userObjectCPAL) | out-null 
                                      
            $configXML.Configuration["Users"].AppendChild($userObjectElement) | out-null

            Write-Log -Msg ("INFORMATION: Backed up user " + $user.name) -category "Info"                  
        }
    }
    $configXML.Save($SettingsFile)
}

Function Backup-Groups($path)
{
    #Open the configuration XML file
    $configXML = [xml](Get-Content ($SettingsFile))
         
    #If a searchbase has been defined, only retrieve the searchbase OU and child OU objects           
    If($searchBase){$OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $searchBase -SearchScope Subtree }     
    #If no searchbase, return all OUs and append the domain root (for domain level policies)
    Else
    {        
        $OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase ($strDomainDN) -SearchScope Subtree                   
    }
    foreach($OU in $OUs)
    {
        $groupObjects = Get-ADGroup -LDAPFilter '(name=*)' -SearchBase ($OU.distinguishedName) -SearchScope OneLevel -Properties Description
        Foreach ($group in $groupObjects)
        {
             $groupObjectElement = $configXML.CreateElement("Group")
             $groupObjectElement.SetAttribute("Name", $group.Name)

             $groupObjectDN = $configXML.CreateElement("distinguishedName")
             #$groupObjectDN.Set_InnerText($group.distinguishedName)
             $DN = $group.distinguishedName -replace((([regex]::matches(($group.distinguishedName),"(?i)DC=[^,]*") | % {$_.value}) -join ","),"")
             $groupObjectDN.Set_InnerText($DN)

             $groupObjectSAM = $configXML.CreateElement("SamAccountName")
             $groupObjectSAM.Set_InnerText($group.SamAccountName)
             $groupObjectElement.AppendChild($groupObjectSAM) | out-null

			 $groupObjectDesc = $configXML.CreateElement("Description")
             $groupObjectDesc.Set_InnerText($group.Description)
             $groupObjectElement.AppendChild($groupObjectDesc) | out-null 

             $groupObjectCategory = $configXML.CreateElement("Category")
             $groupObjectCategory.Set_InnerText($group.GroupCategory)

             $groupObjectScope = $configXML.CreateElement("Scope")
             $groupObjectScope.Set_InnerText($group.GroupScope)

             $groupObjectElement.AppendChild($groupObjectDN) | out-null
             $groupObjectElement.AppendChild($groupObjectCategory) | out-null
             $groupObjectElement.AppendChild($groupObjectScope) | out-null
             $configXML.Configuration["Groups"].AppendChild($groupObjectElement) | out-null
             Write-log -Msg ("INFORMATION: Backed up Group " + $group.name) -category "Info"
        }
    }
    $configXML.Save($SettingsFile)
}

Function Backup-GroupMembership($path)
{
    #Open the configuration XML file
    $configXML = [xml](Get-Content ($SettingsFile))
               
    #If a searchbase has been defined, only retrieve the searchbase OU and child OU objects           
    If($searchBase){$OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $searchBase -SearchScope Subtree }
        
    #If no searchbase, return all OUs and append the domain root (for domain level policies)
    Else
    {       
        $OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase ($strDomainDN) -SearchScope Subtree                   
    }
    foreach($OU in $OUs)
    {
        $groupObjects = Get-ADGroup -LDAPFilter '(name=*)' -SearchBase ($OU.distinguishedName) -SearchScope OneLevel

        Foreach ($group in $groupObjects)
        {
            $groupMembership = Get-ADGroupMember -identity $group.SamAccountName   #Changed from Name - spaces!
            $groupObjectElement = $configXML.CreateElement("Group")
            $groupObjectElement.SetAttribute("SamAccountName", $group.SamAccountName)   
                
            Foreach ($member in $groupMembership)
            {                          
                $memberObjectElement = $configXML.CreateElement("Member")
                $memberObjectElement.SetAttribute("SamAccountName", $member.SamAccountName)
                $memberObjectElement.SetAttribute("Type", $member.objectclass)
                $groupObjectElement.AppendChild($memberObjectElement) | out-null
            }
            $configXML.Configuration["GroupMembership"].AppendChild($groupObjectElement) | out-null
         }
         Write-Log -Msg ("INFORMATION: Backup up Group Membership for Group " + $group.name) -category "Info"           
    }
    $configXML.Save($SettingsFile)   
}

Function Backup-OUs($path)
{        
    #Open the configuration XML file
    $configXML = [xml](Get-Content ($SettingsFile))
              
    #If a searchbase has been defined, only retrieve the searchbase OU and child OU objects           
    If($searchBase){$OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $searchBase -SearchScope Subtree -Properties Description }
        
    #If no searchbase, return all OUs and append the domain root (for domain level policies)
    Else
    {        
        $OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase ($strDomainDN) -SearchScope Subtree -Properties Description
        $OUs += $strDomainDN    
    }
    foreach($OU in $OUs)
    {
        $DN = $ou.distinguishedName -replace((([regex]::matches(($ou.distinguishedName),"(?i)DC=[^,]*") | % {$_.value}) -join ","),"")

       # If((!($configXML.Configuration.OrganizationalUnits.OU | where {$_.distinguishedName -eq $ou.distinguishedName}))-and ($ou.distinguishedName -ne $null))
       If((!($configXML.Configuration.OrganizationalUnits.OU | where {$_.distinguishedName -eq $DN}))-and ($DN-ne $null))
        {                            
            $ouElement = $configXML.CreateElement("OU")
            #$ouElement.SetAttribute("DistinguishedName", $ou.distinguishedName)          
            $ouElement.SetAttribute("DistinguishedName", $DN)

            $blocked = (Get-GPInheritance $ou.distinguishedName).GpoInheritanceBlocked
            $ouElementBlocked = $configXML.CreateElement("GpoInheritanceBlocked")
            $ouElementBlocked.Set_InnerText($blocked)
            $ouElement.AppendChild($ouElementBlocked) | out-null
                                      
            $ouElementDesc = $configXML.CreateElement("Description")
            $ouElementDesc.Set_InnerText($ou.Description)
            $ouElement.AppendChild($ouElementDesc) | out-null
            $ouElementMB = $configXML.CreateElement("ManagedBy")
            $ouElementMB.Set_InnerText($ou.ManagedBy)
            $ouElement.AppendChild($ouElementMB) | out-null

            $configXML.Configuration["OrganizationalUnits"].AppendChild($ouElement) | out-null
        }
        Write-log -Msg ("INFORMATION: Backed up OU " + $ou.distinguishedName) -category "Info"                          
    }
    $configXML.Save($SettingsFile)
}

Function Export-WMIFilter {
Param(
    [Parameter(Mandatory=$true)]
    [String[]]
    $Name,
    [Parameter(Mandatory=$false)]
    [String]
    $SrcServer,
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [String]
    $Path
)
    if (!$SrcServer){$SrcServer=(Get-ADDomainController).HostName}
    # CN=SOM,CN=WMIPolicy,CN=System,DC=wingtiptoys,DC=local
    $WMIPath = "CN=SOM,CN=WMIPolicy,$((Get-ADDomain -Server $SrcServer).SystemsContainer)"

    Get-ADObject -Server $SrcServer -SearchBase $WMIPath -Filter {objectClass -eq 'msWMI-Som'} -Properties msWMI-Author, msWMI-Name, msWMI-Parm1, msWMI-Parm2 |
     Where-Object {$Name -contains $_."msWMI-Name"} |
     Select-Object msWMI-Author, msWMI-Name, msWMI-Parm1, msWMI-Parm2 |
     Export-CSV (Join-Path $Path WMIFilters.csv) -NoTypeInformation
}

Function Restore-WMIFilter {
Param (
    [Parameter(Mandatory=$false)]
    [String]
    $DestServer,
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [String]
    $Path
)
    if (!$DestServer) {$DestServer=(Get-ADDomainController).HostName}
    $WMIExportFile = Join-Path -Path $Path -ChildPath 'WMIFilters.csv'
    If ((Test-Path $WMIExportFile) -eq $false) {
        Write-Warning "No WMI filters to import."
    } Else {
    
        $WMIImport = Import-Csv $WMIExportFile
        $WMIPath = "CN=SOM,CN=WMIPolicy,$((Get-ADDomain -Server $DestServer).SystemsContainer)"

        $ExistingWMIFilters = Get-ADObject -Server $DestServer -SearchBase $WMIPath `
            -Filter {objectClass -eq 'msWMI-Som'} `
            -Properties msWMI-Author, msWMI-Name, msWMI-Parm1, msWMI-Parm2

        ForEach ($WMIFilter in $WMIImport) {

            If ($ExistingWMIFilters | Where-Object {$_.'msWMI-Name' -eq $WMIFilter.'msWMI-Name'}) {
                Write-Host "WMI filter already exists: $($WMIFilter."msWMI-Name")"
            } Else {
                $msWMICreationDate = (Get-Date).ToUniversalTime().ToString("yyyyMMddhhmmss.ffffff-000")
                $WMIGUID = "{$([System.Guid]::NewGuid())}"
    
                $Attr = @{
                    "msWMI-Name" = $WMIFilter."msWMI-Name";
                    "msWMI-Parm2" = $WMIFilter."msWMI-Parm2";
                    "msWMI-Author" = $WMIFilter."msWMI-Author";
                    "msWMI-ID"= $WMIGUID;
                    "instanceType" = 4;
                    "showInAdvancedViewOnly" = "TRUE";
                    "msWMI-ChangeDate" = $msWMICreationDate; 
                    "msWMI-CreationDate" = $msWMICreationDate
                }
    
                # The Description in the GUI (Parm1) may be null. If so, that will botch the New-ADObject.
                If ($WMIFilter."msWMI-Parm1") {
                    $Attr.Add("msWMI-Parm1",$WMIFilter."msWMI-Parm1")
                }

                $ADObject = New-ADObject -Name $WMIGUID -Type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr -Server $DestServer -PassThru
                Write-Host "Created WMI filter: $($WMIFilter."msWMI-Name")"
            }
        }
    } # End If No WMI filters
}

Function Set-GPWMIFilterFromBackup {
Param (
    [Parameter(Mandatory=$false)]
    [String]
    $DestDomain,
    [Parameter(Mandatory=$false)]
    [String]
    $DestServer,
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [String]
    $BackupPath
)
    if (!$DestServer) {$DestServer=(Get-ADDomainController).HostName}
    if (!$DestDomain) {$DestDomain=(Get-ADDomain).DNSRoot}   
    # Get the WMI Filter associated with each GPO backup
    $GPOBackups = Get-ChildItem $BackupPath -Filter "backup.xml" -Recurse

    ForEach ($Backup in $GPOBackups) {

        $GPODisplayName = $WMIFilterName = $null

        [xml]$BackupXML = Get-Content $Backup.FullName
        $GPODisplayName = $BackupXML.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName."#cdata-section"
        $WMIFilterName = $BackupXML.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.WMIFilterName."#cdata-section"

        If ($WMIFilterName) {
            "Linking WMI filter '$WMIFilterName' to GPO '$GPODisplayName'."
            $WMIFilter = Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,$((Get-ADDomain -Server $DestServer).SystemsContainer)" `
                -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=$WMIFilterName))" `
                -Server $DestServer
            If ($WMIFilter) {
                Set-ADObject -Identity (Get-GPO $GPODisplayName).Path `
                    -Replace @{gPCWQLFilter="[$DestDomain;$($WMIFilter.Name);0]"} `
                    -Server $DestServer
            } Else {
                Write-Warning "WMI filter '$WMIFilterName' NOT FOUND.  Manually create and link the WMI filter."
            }
        } #Else {
            #"No WMI Filter for GPO '$GPODisplayName'."
        #}
    }
}

Function Backup-GroupPolicy($path)
{
#       
#      .DESCRIPTION  
#         Backup group policies and configuration
#    
    $path = Join-Path $path -ChildPath "GPO"
    if (!(Test-Path $path)){
        New-Item $path -ItemType Directory | out-null
    }
    #Open the configuration XML file
    $configXML = [xml](Get-Content ($SettingsFile))              
    #If a searchbase has been defined, only retrieve the searchbase OU and child OU objects           
    If(($searchBase) -and ($searchBase -ne ((Get-ADDomain).DistinguishedName))){        
        $OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $searchBase -SearchScope Subtree }       
    #If no searchbase, return all OUs and append the domain root (for domain level policies)
    Else
    {
        $OUs = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $searchBase -SearchScope Subtree 
        $OUs += $searchBase        
    }                             
    Foreach ($ou in $OUs)
    {         
        #If a gpoFilter has been specifed, only return GPOLinks that match the filter
        If($gpofilter -ne "all"){$gpLinks = (Get-GPInheritance -Target $ou).gpoLinks | where {$_.displayName -match $gpofilter}}
        #Otherwise, return all GPOLinks
        Else{$gpLinks = (Get-GPInheritance -Target $ou).gpoLinks}
        Foreach ($link in $gpLinks)
        {              
            #Only process objects that are not the Default Policies
            If($link.displayname -ne "Default Domain Controllers Policy" -and $link.displayname -ne "Default Domain Policy")
            {              
                #Query GPO attributes and permissions
                $gpoAttributes = Get-GPO -Name $link.displayName
                $permissions = Get-GPPermissions -Name $link.displayName -all
               
                #If the GPO has not already been defined in the XML, back it up and add it. 
                If(!($configXML.Configuration.GroupPolicies.Policy | Where {$_.name -eq $link.displayName}))
                {
                    $error.clear()                                               
                    try
                    {
                        Backup-GPO -Name $link.displayName -Path $path | out-null

                        $WMIFilterNames = ((Get-GPO -Name $link.displayName).WmiFilter).Name

                        If ($WMIFilterNames) {
                            Export-WMIFilter -Name $WMIFilterNames -Path $path
                        }

                    }
                    Catch
                    {        
                        Write-Log -Msg ("ERROR: Unable to backup the policy " + ($link.displayName)) -category "Error"
                    }   
                    If(!$Error)
                    {      
                        Write-Log -Msg ("INFORMATION: Backed up the policy " + ($link.displayName)) -category "Info"                   
                        $groupPolicyElement = $configXML.CreateElement("Policy")
                        $groupPolicyElement.SetAttribute("Name", $link.displayName)
                        $groupPolicyElement.SetAttribute("GPOStatus",$gpoAttributes.gpoStatus)
                        $linkElement = $configXML.CreateElement("Link")
                        $ouElement = $configXML.CreateElement("OU")
                        #$ouElement.Set_InnerText(($link.target).replace("dc=","DC="))
                        $DN = $link.target -replace((([regex]::matches(($link.target),"(?i)DC=[^,]*") | % {$_.value}) -join ","),"")
                        $ouElement.Set_InnerText($DN)

                        $linkOrderElement = $configXML.CreateElement("LinkOrder")
                        $linkOrderElement.Set_InnerText($link.order)
                        $enabledElement = $configXML.CreateElement("Enabled")
                        $enabledElement.Set_InnerText($link.Enabled) 
                        $enforcedElement = $configXML.CreateElement("Enforced")
                        $enforcedElement.Set_InnerText($link.Enforced)
                        $linkElement.AppendChild($enforcedElement) | out-null
                        $linkElement.AppendChild($enabledElement)| out-null
                        $linkElement.AppendChild($linkOrderElement)| out-null
                        $linkElement.AppendChild($ouElement)| out-null
                          
                        #Backup the permissions - needs work
                        #Foreach ($acl in $permissions)
                        #{                                                                                                                         
                        #    $pElement = $configXML.CreateElement("Permissions")
                        #    $pElement.Set_InnerText($acl.trustee.name)                   
                        #    $groupPolicyElement.AppendChild($pElement) | Out-Null
                        #}                             
                        $groupPolicyElement.AppendChild($linkElement) | out-null
                        $configXML.Configuration["GroupPolicies"].AppendChild($groupPolicyElement) | out-null
                     }
                 }
                 #The GPO already exists in the XML and has been backed up so just add the link details
                 Else
                 {
                     $groupPolicyElement = $configXML.Configuration.GroupPolicies.Policy | Where {$_.name -eq $link.displayName}
                     $linkElement = $configXML.CreateElement("Link")
                     $ouElement = $configXML.CreateElement("OU")
                     #$ouElement.Set_InnerText(($link.target).replace("dc=","DC="))
                     $DN = $link.target -replace((([regex]::matches(($link.target),"(?i)DC=[^,]*") | % {$_.value}) -join ","),"")
                     $ouElement.Set_InnerText($DN)
                     $linkOrderElement = $configXML.CreateElement("LinkOrder")
                     $linkOrderElement.Set_InnerText($link.order)
                     $enabledElement = $configXML.CreateElement("Enabled")
                     $enabledElement.Set_InnerText($link.Enabled)
                     $enforcedElement = $configXML.CreateElement("Enforced")
                     $enforcedElement.Set_InnerText($link.Enforced)

                     $linkElement.AppendChild($enforcedElement) | out-null
                     $linkElement.AppendChild($enabledElement) | out-null
                     $linkElement.AppendChild($linkOrderElement) | out-null
                     $linkElement.AppendChild($ouElement) | out-null
                     $groupPolicyElement.AppendChild($linkElement) | out-null

                     $DN = $link.target -replace((([regex]::matches(($link.target),"(?i)DC=[^,]*") | % {$_.value}) -join ","),"")

                     #If((!($configXML.Configuration.OrganizationalUnits.OU | where {$_.distinguishedName -eq $link.target})) -and ($ou.distinguishedName -ne $null))
                     If((!($configXML.Configuration.OrganizationalUnits.OU | where {$_.distinguishedName -eq $DN})) -and ($DN -ne $null))
                     {
                        $ouElement = $configXML.CreateElement("OU")
                        #$ouElement.SetAttribute("DistinguishedName", $link.target)
                        
                        $ouElement.SetAttribute("DistinguishedName", $DN)
                        $configXML.Configuration["OrganizationalUnits"].AppendChild($ouElement) | out-null
                     }            
                  }       
               }               
           }
    $configXML.Save($SettingsFile)
    }
}

Function Backup-WMIFilter($strWMIName)
{
    #Open the configuration XML file
    $configXML = [xml](Get-Content ($SettingsFile))

    #Query WMI Filter
    $wmiFilterNAme = Get-GpWmiFilter -Name $strWMIName
               
     #If the WMI filter has not already been defined in the XML, back it up and add it. 
    If(!($configXML.Configuration.WMIFilters.Filter | Where {$_.name -eq $strWMIName}))
    {
    
    }

    $configXML.Save($SettingsFile)
}

Function Restore-Group($strGroupName, $strGroupSamAccountName, $strGroupDisplayName, $strGroupCategory, $strGroupScope, $strGroupPath, $strGroupDescription)
{
    $error.Clear()
        #check if the group already exists...
    $Result = [bool]([adsisearcher]"samaccountname=$strGroupSamAccountName").FindOne()
 
    If($Result)
    {
        Write-Host -ForegroundColor DarkGray ("INFORMATION: Group already exists: " + $strGroupName)
    }
    else
    {
        Write-Host -ForegroundColor Green ("INFORMATION: Creating the group " + $strGroupName)
        try
        {            
            $strGroupPath = $strGroupPath + $strDomainDN
            New-ADGroup -Name $strGroupName -SamAccountName $strGroupSamAccountName -DisplayName $strGroupDisplayName -GroupCategory $strGroupCategory -GroupScope $strGroupScope -Path $strGroupPath -Description $strGroupDescription
        }
        catch
            {               
                 If ($error -match "group already exists")
                 {
                    Write-Host -ForegroundColor Cyan ("INFORMATION: The group" + $strGroupName + " already exists. Skipping")
                 }
                 Else
                 {
                    Write-Host -ForegroundColor Red ("ERROR: Unable to create the group " + $strGroupName)
                    write-host -ForegroundColor Red ("ERROR: The Error captured is: " + $error)
                 }
            }
        
        If(!$error)
        {
            Write-Host -ForegroundColor Green ("INFORMATION: Successfully created the group " + $strGroupName)
        }
    }
}

Function Restore-User($strUserName, $strUserPrincipalName, $strUserSamAccountName, $strUserDisplayName, $strUserPath, $strUserDescription, $strSecurePassword, $strGivenName, $strSurname, $bolPasswordNeverExpires, $bolCannotChangePassword, $bolChangePasswordAtLogon)
{
    #Hash table to convert boolean values to numeric required by New-ADUser
    $convertPasswordNeverExpires = @{"True"=1;"False"=0}
    $convertCannotChangePassword = @{"True"=1;"False"=0}
    $convertChangePasswordAtLogon = @{"True"=1;"False"=0}

    $error.Clear()
    #check if the user already exists...
    $Result = [bool]([adsisearcher]"samaccountname=$strUserSamAccountName").FindOne()
 
    If($Result)
    {
        Write-Host -ForegroundColor DarkGray ("INFORMATION: User already exists: " + $strUserName)
    }
    else
    {
        Write-Host -ForegroundColor Green ("INFORMATION: Creating the user: " + $strUserName)
        try
        {            
           New-ADUser -Name $strUserName -UserPrincipalName $strUserPrincipalName -SamAccountName $strUserSamAccountName -DisplayName $strUserDisplayName -GivenName $strGivenName -Surname $strSurname -Path $strUserPath -Description $strUserDescription -AccountPassword $strSecurePassword -Enabled $true  -ChangePasswordAtLogon ($convertChangePasswordAtLogon[$bolChangePasswordAtLogon]) -CannotChangePassword ($convertCannotChangePassword[$bolCannotChangePassword]) -PasswordNeverExpires ($convertPasswordNeverExpires[$bolPasswordNeverExpires])       
        }
        catch
        {
           If ($error -match "account already exists")
           {
                Write-Host -ForegroundColor Cyan ("INFORMATION: The user" + $strUserName + " already exists. Skipping")
           }
           Else
           {
               Write-Host -ForegroundColor Red ("ERROR: Unable to create the user " + $strUserName + $strUserPrincipalName)
               write-host -ForegroundColor Red ("ERROR: The Error captured is: " + $error)
               write-host -ForegroundColor DarkGray ("INFORMATION: Try using -ForceLocalDomain switch")
           }
        }
        
        If(!$error)
        {
           Write-Host -ForegroundColor Green ("INFORMATION: Successfully created the user " + $strUserName)
        }
    }
}


Function Add-ToGroup($objIdentity, $objMember)
{
$error.clear()
try
        {
            Add-ADGroupMember -identity $objIdentity -members $objMember -erroraction stop
        }
        catch
            {
                If ($error -match "already a member")
                {
                    Write-Host -ForegroundColor Cyan ("INFORMATION: The object " + $objMember + " is already a member of the group " + $objIdentity + ". Skipping")
                }
                Else
                {
                    Write-Host -ForegroundColor Red ("ERROR: Unable to add the object " + $objMember + " to the group " + $objIdentity)
                    Write-Host -ForegroundColor Red ("ERROR: The Error captured is: " + $error)
                }                 
            }
        If(!$error)
        {
            Write-Host -ForegroundColor Green ("INFORMATION: Successfully added the object " + $objMember + " to the group " + $objIdentity)
        }
} 


Function Get-User($strUser)
{
    $error.clear()
    try
    {
        $userObject = Get-ADUser $strUser
    }
    Catch
    {       
        Write-Host -ForegroundColor Red ("ERROR: Unable to locate the user " + $strUser + " in Active Directory.")
        return $false
    }

    If(!$Error)
    {      
        return $userObject
    }
}

Function Get-Group($strGroup)
{
    $error.clear()
    try
    {

        $groupObject = Get-ADGroup $strGroup
    }
    Catch
    {       
        Write-Host -ForegroundColor Red ("ERROR: Unable to locate the group " + $strGroup + " in Active Directory.")
        return $false
    }

    If(!$Error)
    {       
        return $groupObject
    }
}

Function Get-OU($strOU)
{
    $error.clear()
    try
    {
        $OUObject = Get-ADOrganizationalUnit $strOU
    }
    Catch
    {       
        Write-Host -ForegroundColor Red ("ERROR: Unable to locate the OU " + $strOU + "in Active Directory.")
        return $false
    }

    If(!$Error)
    {       
        return $OUObject
    }
}


Function Restore-OU($path)
{
#       
#      .DESCRIPTION  
#         Restore OU configuration
#  
    $configXML = [xml](Get-content ($SettingsFile))
       
    Foreach ($ou in $configXML.Configuration.OrganizationalUnits.OU)
    {
        $Error.Clear()
        
        $targetOU = $ou.DistinguishedName + $strDomainDN 
                           
            #Check the OU exists
            If (!([ADSI]::Exists("LDAP://" + $targetOU))) 
            {            
                Write-Host -ForegroundColor Green ("INFORMATION: Need to create OU " + $targetOU)                
                $newOUName = (($targetOU.Split(","))[0]) -replace("ou=","")
                $newOUPath = ($targetOU.substring($targetOU.indexof(",")+1)) 
                                    
                try
                {               
                    #New-ADOrganizationalUnit -name $newOUName -Path $newOUPath -ProtectedFromAccidentalDeletion $false
					if ($ProtectedFromAccidentalDeletion -eq $null)
					{$ProtectedFromAccidentalDeletion = $true}
					New-ADOrganizationalUnit -name $newOUName -Path $newOUPath -ProtectedFromAccidentalDeletion $ProtectedFromAccidentalDeletion              
                }                  
                    Catch
                    {       
                        Write-Host -ForegroundColor Red ("ERROR: Unable to create the OU " + $targetOU)
                        Write-Host -ForegroundColor Red ("ERROR: The error returned is: " + $Error)                                                      
                    }

                    If(!$Error)
                    {       
                        Write-Host -ForegroundColor Green ("INFORMATION: Successfully created OU " + $targetOU) 
                    }
            }
            Else
            {
                Write-Host -ForegroundColor DarkGray ("The target OU " + $targetOU + " already exists. No need to create")
            }

            #Block Inheritance
            $block = $ou.GpoInheritanceBlocked
            if ($block -eq $True)
            {
               $block = Set-GPInheritance -Target $targetOU -IsBlocked Yes
            } else
            {
               $block = Set-GPInheritance -Target $targetOU -IsBlocked No     
            }
    }
}

Function Restore-GroupPolicy($backupID, $path)
{
#       
#      .DESCRIPTION  
#         Restore group policies
#  
    $error.clear()
    $configXML = [xml](Get-Content ($SettingsFile))           
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $gpoPath = Join-Path $path -ChildPath "GPO"
    $manifestPath = Join-Path $gpoPath -ChildPath "manifest.xml"
	$manifestXML = [xml](Get-Content $manifestPath)  
    Foreach ($gpoName in $configXML.Configuration.GroupPolicies.Policy)
    {   
        $backupGuid = $manifestXML.Backups.BackupInst | where {$_.GPODisplayName."#cdata-section" -eq $gpoName.Name}       
        
		#check backupGuid is valid
		#If the GPO exists and Overwriting is enabled, or the GPO does not exist, import the GPO
        If(((Get-GPO -Name $gpoName.Name -ErrorAction SilentlyContinue) -and ($OverwriteExistingPolicies -eq $True)) -or (!(Get-GPO -name $gpoName.name -ErrorAction SilentlyContinue)))
        {
            $error.clear()   
        
            #Check for migration table, and run appropriate command
            If($migrationTable)
            {       
                try
                {                    
                    $MigTablePath= Join-Path $BackupFolder -ChildPath $MigrationTable
                    $MigFile = [System.IO.Path]::GetFileNameWithoutExtension($MigTablePath)
                    $newmt = $MigFile + "." + $domain + ".migtable"
                    $migTable = Join-Path $BackupFolder -ChildPath $newmt
                    Import-GPO -BackupGpoName ($backupGuid.GPODisplayName."#cdata-section") -TargetName $gpoName.Name -Path $gpoPath -MigrationTable $migTable -CreateIfNeeded | Out-Null
                }
                Catch
                {        
                    Write-Host -ForegroundColor Red ("ERROR: Unable to import the policy " + ($backupGuid.GPODisplayName."#cdata-section"))
                    If($error -match "The data is invalid")
                    {Write-Host -ForegroundColor Red ("ERROR: The data in the migration table is invalid. The policy has been created, but the settings have not been imported.")}               
                }
            }
            Else
            {
                try
                {
                    Import-GPO -BackupGpoName ($backupGuid.GPODisplayName."#cdata-section") -TargetName $gpoName.Name -Path $gpoPath -CreateIfNeeded | Out-Null
                }
                Catch
                {        
                    Write-Host -ForegroundColor Red ("ERROR: Unable to import the policy " + ($backupGuid.GPODisplayName."#cdata-section"))
                }
            }

            If(!$Error)
            {       
                 Write-Host -ForegroundColor Green ("INFORMATION: Restored the policy " + ($backupGuid.GPODisplayName."#cdata-section"))
                 If($gpoName.Permissions)
                 {
                    #Set permissions if defined
                    Foreach($group in $gpoName.Permissions)
                    {
                        If((Get-Group -groupName $group) -eq $True)
                        {
                            Set-GPOApplyPermissions -groupName $group -name $gpoName.Name
                        }
                    }
                 }
                 
            }
        }
        #If the GPO does exist and overwriting is disabled, continue without importing
        ElseIf((Get-GPO -Name $gpoName.Name) -and ($OverwriteExistingPolicies -eq $false))
        {
            Write-Host -ForegroundColor DarkGray ("INFORMATION: The Group Policy " + $gpoName.name + " already exists and the option to overwrite existing policies has not been specified. The policy will not be imported")
        }
		else
		{
			Write-Host -ForegroundColor Red ("ERROR: Unable to import the policy " + $gpoName) 
		}
    }

    #WMIFilter
    Set-GPWMIFilterFromBackup -BackupPath $gpoPath
}

Function Get-GPOLink ($OU, $GPO)
{
    $result = (Get-GPInheritance -Target $OU).GpoLinks.DisplayName

    if ($result -contains $GPO){
        return $true
    }
    else
    {
        return $false
    }    
}

Function Restore-Permissions()
{
#       
#      .DESCRIPTION  
#         Restore Active Directory permissions (ACLs) on OUs
# 

}

Function ConfigureRolePermissions($role, $ou, $group, $objInheritance)
{
#       
#      .DESCRIPTION  
#         Configures Active Directory permissions (ACLs) on OUs
# 
    $definedActivities = $permissionsXML.Configuration.roles.role | where {$_.name -eq $role}

    Foreach ($activity in $definedActivities.activity)
    {
        Write-Host -ForegroundColor Yellow ("INFORMATION: Assigning the group " + $group.name + " the " + $activity + " permission on the following OU: " + $ou)
        If($objInheritance -eq "True")
        {
            $inheritance = "Descendents"
        }
        Else
        {
            $inheritance = "Children"
        }

        $error.clear()
        try{          
            &($activity) -objGroup $group -objOU $ou -inheritanceType $inheritance
        }
        catch
        {
            If($error -match "is not recognized as the name of a cmdlet")
            {
                Write-Host -ForegroundColor Red ("ERROR: The role activity " + $activity + " is not a defined role. Review the role definitions XML file")
            }
            Else
            {
                Write-Host -ForegroundColor Red ("ERROR: An unknown error occurred for the role activity: " + $activity)
            }
        }
    }
}

Function Link-GroupPolicy($path)
{
#       
#      .DESCRIPTION  
#         Restore group policy link configuration
#  
    $configXML = [xml](Get-Content($SettingsFile))
    Foreach ($gpo in $configXML.Configuration.GroupPolicies.Policy)
    {
        #First, create the links
        Foreach ($link in $gpo.link)
        {  
            $error.Clear()

            $targetOU = $link.ou + $strDomainDN

            If($link.Enabled -eq "False") {$linkEnabled = "No"}
            ElseIf($link.Enabled -eq "True") {$linkEnabled = "Yes"}
            
            if (Get-GPOLink $targetOU $gpo.name)
            {
                Write-Host -ForegroundColor DarkGray ("INFORMATION: GPO " + $gpo.name + " is already linked to " + $targetOU)
            }
            else
            {        
                try
                {           
                    New-GPLink -Name $gpo.name -Target $targetOU -LinkEnabled $linkEnabled -ErrorAction Stop| Out-Null
                }

                Catch
                {       
                    Write-Host -ForegroundColor Red ("ERROR: Unable to create a gplink for policy " + $gpo.name + " to the OU " + $targetOU)
                    If($error -match "is already linked")
                    {Write-Host -ForegroundColor Red ("ERROR: The policy " + $gpo.name + " is already linked to the OU " + $targetOU)}
                }
   
                If(!$Error)
                {       
                    Write-Host -ForegroundColor Green ("INFORMATION: GPO " + $gpo.name + " has been linked to " + $targetOU)
                }
            }
        }   
      }
    
        #Configure the link orders
        foreach ($gpo in $configXML.Configuration.GroupPolicies.Policy)
        {
            Foreach ($link in $gpo.link)
            { 
                $error.clear()

                $targetOU = $link.ou + $strDomainDN
            
                try
                {          
                   Set-GPLink -Name $gpo.name -Target  $targetOU -Order $link.LinkOrder | out-null                
                }
                Catch
                {
        
                    Write-Host -ForegroundColor Red ("ERROR: Unable to set the link order for policy " + $gpo.name + " linked to OU " + $targetOU)
                }
   
                If(!$Error)
                {     
                    Write-Host -ForegroundColor Green ("INFORMATION: The link order of " + $link.LinkOrder + " for GPO " + $gpo.name + " that is linked to " + $targetOU + " has been set")
                }       
        }
    }
}

Function Get-Group($groupName)
{
#       
#      .DESCRIPTION  
#         Find a specified Group object in Active Directory
#  
    $error.clear()
    try
    {
        Get-Adgroup -identity $groupName
    }
    catch 
    {
        Write-Host -ForegroundColor Red ("ERROR: Unable to find the group " + $groupName + " in Active Directory")
    }

    If(!$error)
    {
        return $True
    }
    Else
    {
        return $False
    }
}

Function Set-GPOApplyPermissions($name, $groupName)
{
#       
#      .DESCRIPTION  
#         Apply GPO Permissions
# 
    $error.clear()
    #Remove the authenticated users group and then add the target group
    try
    {
        Set-GPPermission -name $name -targetName "Authenticated Users" -TargetType "Group" -PermissionLevel None -ErrorAction SilentlyContinue | Out-Null
        Set-GPPermission -name $name -targetName $groupName -TargetType "Group" -PermissionLevel gpoApply -ErrorAction Stop | Out-Null   
    }
    catch 
    {
        Write-Host -ForegroundColor Red ("ERROR: Unable to set the permissions for " + $groupName + " on the policy GUID " + $name)    
    }
    If(!$error)
    {
        Write-Host -ForegroundColor Green ("SUCCESS: Set the permissions for " + $groupName + " on the policy GUID " + $name)
    }
}

Function Get-OU($strOU)
{
#       
#      .DESCRIPTION  
#         Query OU configuration
#  
    $error.clear()
    try
    {
        $OUObject = Get-ADOrganizationalUnit $strOU
    }
    Catch
    {     
        Write-Host -ForegroundColor Red ("ERROR: Unable to locate the OU " + $strOU + "in Active Directory.")
        return $false
    }

    If(!$Error)
    {      
        return $OUObject
    }
}
     
Function LoadModule([string]$name)
{ 
#       
#      .DESCRIPTION  
#         Load the specified PowerShell module
#  
    If(Get-Module -ListAvailable | Where-Object { $_.name -eq $name }) 
    { 
        Import-Module -Name $name 
        return $true
    } #end if module available then import 
    else 
    { 
        return $false 
    } #module not available
     
} # end if not module 

Function CreateMigTable
{
#       
#      .DESCRIPTION  
#          Create the migration table for the GPOs to be restored
#  
    $domain=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $MigTablePath= Join-Path $BackupFolder -ChildPath $MigrationTable
    $gpm = new-object -comobject gpmGMT.gpm
    $constants = $gpm.getConstants()

    $gpmDomain=$gpm.GetDomain($domain,$null,$constants.useanydc)
    $gpmSearch = $gpm.CreateSearchCriteria()
    $GPOs = $gpmDomain.SearchGpos($gpmSearch)
    $migtable=$gpm.createMigrationTable()

    foreach($gpo in $GPOs)
    {
        $perm=$constants.ProcessSecurity
        $MigTable.Add($perm,$GPO)
        $dn=$gpo.DisplayName
        Write-Host -ForegroundColor Green ("SUCCESS: Updated Migration table for '$dn'")
    }

    $migTable.save($MigTablePath)
    Write-Host -ForegroundColor Green ("SUCCESS: Migration Table Created '$MigTablePath'")
}

Function UpdateMigTable
{
#       
#      .DESCRIPTION  
#          Update the migration table XML by resolving the users and groups
#   
    $MigTablePath= Join-Path $BackupFolder -ChildPath $MigrationTable

    if (Test-Path($MigTablePath) -PathType Leaf -ErrorAction SilentlyContinue)
    {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        #append domain name
        #just get the name, without extension
        $MigFile = [System.IO.Path]::GetFileNameWithoutExtension($MigTablePath)
        $newmt = $MigFile + "." + $domain + ".migtable"
        $newmt = Join-Path $BackupFolder -ChildPath $newmt

        #check if we can write into the folder
        Try { [io.file]::OpenWrite($newmt).close() }
        Catch {
                # if not, we assume we can use the %temp% folder
                $newmt = $MigFile + "." + $domain + ".migtable"
                $newmt = Join-Path $env:TEMP -ChildPath $newmt
              }

        $mt = Get-Content $MigTablePath
        $mt | foreach {$_ -replace "<DestinationSameAsSource />", "<Destination></Destination>"} | Set-Content $newmt

        [xml] $MTData = Get-Content $newmt
        foreach ($data in $MTData.MigrationTable.Mapping)
        {
            if ($data.source -like '*@*')
            {
                $stDomain = "@" + $domain
                $destination = $data.source -replace "\@.*", $stDomain
                $data.destination= $destination
            }
            else
            {
                $data.destination=$data.source
                #TODO: put the "<DestinationSameAsSource />" back
            }       
        }
        $MTData.Save($newmt)
        Write-Host -ForegroundColor Green ("SUCCESS: Migration Table Updated '$newmt'")
    } else
    {
        Write-Host -ForegroundColor DarkGray ("INFORMATION: Migration table does not exist - skipping")
    }
}


######################################################################################################################
# Full Control permissions
Function FullControl($objGroup, $objOU,$inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU

$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"GenericAll","Allow","00000000-0000-0000-0000-000000000000",$inheritanceType,"00000000-0000-0000-0000-000000000000"))
try
{
    Set-Acl -AclObject $objAcl $objOU 
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " Full Control permissions")
  
    
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " Full Control permissions on the OU " + $objOU)
}



}

Function FullControlUsers($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU

$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"GenericAll","Allow","00000000-0000-0000-0000-000000000000",$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU 
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " Full Control permissions over User Objects on the OU " + $objOU)
  
    
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " Full Control permissions over User Objects on the OU " + $objOU)
}



}

Function FullControlGroups($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU

$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"GenericAll","Allow","00000000-0000-0000-0000-000000000000",$inheritanceType,$guidmap["group"]))
try
{
    Set-Acl -AclObject $objAcl $objOU 
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " Full Control permissions over Group Objects on the OU " + $objOU)
  
    
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " Full Control permissions over Group Objects on the OU " + $objOU)
}



}

Function FullControlComputers($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU

$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"GenericAll","Allow","00000000-0000-0000-0000-000000000000",$inheritanceType,$guidmap["computer"]))
try
{
    Set-Acl -AclObject $objAcl $objOU 
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " Full Control permissions over Computer Objects on the OU " + $objOU)
  
    
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " Full Control permissions over Computer Objects on the OU " + $objOU)
}

}

######################################################################################################################
# Full Control permissions
Function CreateUserAccount($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["user"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create User Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create User Accounts on the OU " + $objOU)
}


}

Function DeleteUserAccount($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["user"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete User Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete User Accounts on the OU " + $objOU)
}


}

Function RenameUserAccount($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["distinguishedName"],$inheritanceType,$guidmap["user"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["cn"],$inheritanceType,$guidmap["user"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["name"],$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Rename User Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Rename User Accounts on the OU " + $objOU)
}



}

Function DisableUserAccount($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["userAccountControl"],$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Disable User Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Disable User Accounts on the OU " + $objOU)
}



}

Function UnlockUserAccount($objGroup, $objOU, $inheritanceType)
{


$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["lockoutTime"],$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Unlock User Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Unlock User Accounts on the OU " + $objOU)
}


}

Function EnableDisabledUserAccount($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["userAccountControl"],$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Enable Disabled User Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Enable Disabled User Accounts on the OU " + $objOU)
}


}

Function ResetUserPasswords($objGroup, $objOU, $inheritanceType)
{


$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],$inheritanceType,$guidmap["user"]))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Reset User Passwords on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Reset User Passwords on the OU " + $objOU)
}


}

Function ForcePasswordChangeAtLogon($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["userPassword"],$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Force Password Change at Logon on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Force Password Change at Logon on the OU " + $objOU)
}

}

Function ModifyUserGroupMembership($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["memberOf"],$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify a users group membership on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify a users group membership on the OU " + $objOU)
}

}

Function ModifyUserProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Modify User Properties on " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Modify User Properties on " + $objOU)
}


}

Function DenyModifyLogonScript($objGroup,$objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Deny",$guidmap["scriptPath"],$inheritanceType,$guidmap["user"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " deny permissions to Modify User Logon Script on " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " deny permissions to Modify User Logon Script on " + $objOU)
}


}

Function DenySetUserSPN($objGroup, $objOU, $inheritanceType)
{

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Deny",$guidmap["servicePrincipalName"],$inheritanceType,$guidmap["user"]))


try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " deny permissions to Create User SPNs on OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " deny permissions to Create User SPNs on OU " + $objOU)
}

}

######################################################################################################################
# Computer object permissions
Function CreateComputerAccount($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["computer"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create Computer Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create Computer Accounts on the OU " + $objOU)
}




}

Function DeleteComputerAccount($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["computer"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete Computer Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete Computer Accounts on the OU " + $objOU)
}


}

Function RenameComputerAccount($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["distinguishedName"],$inheritanceType,$guidmap["computer"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["cn"],$inheritanceType,$guidmap["computer"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["name"],$inheritanceType,$guidmap["computer"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Rename Computer Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Rename Computer Accounts on the OU " + $objOU)
}



}

Function DisableComputerAccount($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["userAccountControl"],$inheritanceType,$guidmap["computer"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Disable Computer Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Disable Computer Accounts on the OU " + $objOU)
}



}

Function EnableDisabledComputerAccount($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["userAccountControl"],$inheritanceType,$guidmap["computer"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Enable Disabled Computer Accounts on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Enable Disabled Computer Accounts on the OU " + $objOU)
}


}

Function ModifyComputerProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["computer"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Modify Computer Properties on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Modify Computer Properties on the OU " + $objOU)
}


}

Function ResetComputerAccount($objGroup, $objOU, $inheritanceType)
{

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],$inheritanceType,$guidmap["computer"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Reset Computer Passwords on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Reset Computer Passwords on the OU " + $objOU)
}

}

Function ModifyComputerGroupMembership($objGroup, $objOU, $inheritanceType)
{

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["memberOf"],$inheritanceType,$guidmap["computer"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify the computer group membership on OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify the computer group membership on OU " + $objOU)
}




}

Function SetComputerSPN($objGroup, $objOU, $inheritanceType)
{

$error.Clear()


$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ReadProperty,WriteProperty","Allow",$guidmap["servicePrincipalName"],$inheritanceType,$guidmap["computer"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Set Computer SPN on OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Set Computer SPN on OU " + $objOU)
}

}

Function ReadComputerTPMBitLockerInfo($objGroup, $objOU, $inheritanceType)
{
$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU

$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ReadProperty","Allow",$guidmap["msTPM-OwnerInformation"],$inheritanceType,$guidmap["computer"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ReadProperty","Allow",$guidmap["msFVE-KeyPackage"],$inheritanceType,$guidmap["msFVE-RecoveryInformation"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ReadProperty","Allow",$guidmap["msFVE-RecoveryPassword"],$inheritanceType,$guidmap["msFVE-RecoveryInformation"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to read BitLocker and TPM Information on OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to read BitLocker and TPM Information on OU " + $objOU)
}

}

Function ReadComputerAdmPwd($objGroup, $objOU, $inheritanceType)
{
$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU

# The schema must be extended for LAPS
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ReadProperty","Allow",$guidmap["ms-Mcs-AdmPwd"],$inheritanceType,$guidmap["computer"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to read local administrator password on OU" + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to read local administrator password on OU " + $objOU)
}

}

Function DomainJoinComputers($objGroup, $objOU, $inheritanceType)
{
$error.Clear()

$rootdse = Get-ADRootDSE
$spnguid = [System.Guid](Get-ADObject -Identity ("CN=Service-Principal-Name," + $rootdse.SchemaNamingContext) -Properties schemaIDGUID).schemaIDGUID 

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU   

$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild,DeleteChild","Allow",$guidmap["computer"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$guidmap["Reset Password"],$inheritanceType,$guidmap["computer"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ReadProperty,WriteProperty","Allow",$guidmap["Account Restrictions"],$inheritanceType,$guidmap["computer"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty","Allow",$guidmap["DNS Host Name Attributes"],$inheritanceType,$guidmap["computer"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty","Allow",$spnguid,$inheritanceType,$guidmap["computer"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to join computers to the domain in OU" + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to join computers to the domain in OU " + $objOU)
}

}

####################
#Group Tasks
Function CreateGroup($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["group"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create Groups on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create Groups on the OU " + $objOU)
}



}

Function DeleteGroup($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["group"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete Groups on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete Groups on the OU " + $objOU)
}


}

Function RenameGroup($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["distinguishedName"],$inheritanceType,$guidmap["group"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["cn"],$inheritanceType,$guidmap["group"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["name"],$inheritanceType,$guidmap["group"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Rename Groups on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Rename Groups on the OU " + $objOU)
}


}

Function ModifyGroupProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["group"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Modify Group Properties on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Modify Group Properties on the OU " + $objOU)
}

}

Function ModifyGroupMembership($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["member"],$inheritanceType,$guidmap["group"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify the members of a group on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify the members of a group on the OU " + $objOU)
}


}

Function ModifyGroupGroupMembership($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["memberOf"],$inheritanceType,$guidmap["group"]))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify the members of a group on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify the members of a group on the OU " + $objOU)
}


}

####################
#OU Tasks
Function CreateOU($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["organizationalUnit"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create OUs on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create OUs on the OU " + $objOU)
}


}

Function DeleteOU($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["organizationalUnit"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete OUs on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete OUs on the OU " + $objOU)
}


}

Function RenameOU($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["distinguishedName"],$inheritanceType,$guidmap["organizationalUnit"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["cn"],$inheritanceType,$guidmap["organizationalUnit"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["name"],$inheritanceType,$guidmap["organizationalUnit"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Rename OUs on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Rename OUs on the OU " + $objOU)
}


}

Function ModifyOUProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["organizationalUnit"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Rename OUs on the OU " + $objOU)
}

If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Rename OUs on the OU " + $objOU)
}


}

#######
# Printer Tasks
Function CreatePrintQueue($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["printQueue"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create Printer Queues on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create Printer Queues on the OU " + $objOU)
}



}

Function DeletePrintQueue($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["printQueue"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete Print Queues on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete Print Queues on the OU " + $objOU)
}

}

Function RenamePrintQueue($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["distinguishedName"],$inheritanceType,$guidmap["printQueue"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["cn"],$inheritanceType,$guidmap["printQueue"]))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["name"],$inheritanceType,$guidmap["printQueue"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Rename Print Queues on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Rename Print Queues on the OU " + $objOU)
}




}

Function ModifyPrintQueueProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["printQueue"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify print queue properties on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify print queue properties on the OU " + $objOU)
}


}

######
# GPO Tasks
Function LinkGPO($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["gplink"],$inheritanceType))
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$guidmap["gpoptions"],$inheritanceType))

try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to link group policies on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to link group policies on the OU " + $objOU)
}


}

Function GenerateRsopPlanning($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Generate resultant set of policy (Planning)"],$inheritanceType,"00000000-0000-0000-0000-000000000000"))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " the permission Generate resultant set of policy (Planning) on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " the permission Generate resultant set of policy (Planning) on the OU " + $objOU)
}


}

Function GenerateRsopLogging($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Generate resultant set of policy (Logging)"],$inheritanceType,"00000000-0000-0000-0000-000000000000"))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " the permission Generate resultant set of policy (Logging) on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " the permission Generate resultant set of policy (Logging) on the OU " + $objOU)
}


}

##Site Tasks
Function CreateSiteObjects($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["site"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create Site Objects on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create Site Objects on the OU " + $objOU)
}



}

Function DeleteSiteObjects($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["site"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete Site Objects on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete Site Objects on the OU " + $objOU)
}



}

Function ModifySiteProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["site"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify site properties on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify site properties on the OU " + $objOU)
}


}


##Subnet Tasks
Function CreateSubnetObjects($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["subnet"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create Subnet Objects on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create Subnet Objects on the OU " + $objOU)
}



}

Function DeleteSubnetObjects($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["subnet"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete Subnet Objects on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete Subnet Objects on the OU " + $objOU)
}



}

Function ModifySubnetProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["subnet"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify subnet properties on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify subnet properties on the OU " + $objOU)
}


}

##SiteLink Tasks
Function CreateSiteLinkObjects($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild","Allow",$guidmap["sitelink"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Create SiteLink Objects on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Create SiteLink Objects on the OU " + $objOU)
}



}

Function DeleteSiteLinkObjects($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"DeleteChild","Allow",$guidmap["sitelink"],$inheritanceType))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Delete SiteLink Objects on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Delete SiteLink Objects on the OU " + $objOU)
}



}

Function ModifySiteLinkProperties($objGroup, $objOU, $inheritanceType)
{

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty,ReadProperty","Allow",$inheritanceType,$guidmap["sitelink"]))
try
{
    Set-Acl -AclObject $objAcl $objOU
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to modify SiteLink properties on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to modify SiteLink properties on the OU " + $objOU)
}


}

##Replication Tasks
Function ManageReplicationTopology($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],$inheritanceType,"00000000-0000-0000-0000-000000000000"))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Manage Replication Topology on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Manage Replication Topology on the OU " + $objOU)
}


}

Function ReplicatingDirectoryChanges($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],$inheritanceType,"00000000-0000-0000-0000-000000000000"))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Replicate Directory Changes on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Replicate Directory Changes on the OU " + $objOU)
}


}

Function ReplicatingDirectoryChangesAll($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],$inheritanceType,"00000000-0000-0000-0000-000000000000"))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Replicate Directory Changes (All) on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Replicate Directory Changes (All) on the OU " + $objOU)
}


}

Function ReplicatingDirectoryChangesInFilteredSet($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes In Filtered Set"],$inheritanceType,"00000000-0000-0000-0000-000000000000"))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " permissions to Replicate Directory Changes (In Filtered Set) on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " permissions to Replicate Directory Changes (In Filtered Set) on the OU " + $objOU)
}


}

Function ReplicationSynchronization($objGroup, $objOU, $inheritanceType)
{

If($inheritanceType -eq "Descendents") { $inheritanceType="All"}
ElseIf($inheritanceType -eq "Children") { $inheritanceType="None"}

$error.Clear()

$groupSID = New-Object System.Security.Principal.SecurityIdentifier $objGroup.SID
$objAcl = get-acl $objOU
$objacl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],$inheritanceType,"00000000-0000-0000-0000-000000000000"))

try
{
    Set-Acl -AclObject $objAcl $objOU -ErrorAction Stop
}
catch
{
    Write-Host -ForegroundColor Red ("ERROR: Unable to grant the group " + $objGroup.Name + " the permission Replication Synchronization on the OU " + $objOU)
}
If(!$error)
{
    Write-Host -ForegroundColor Green ("INFORMATION: Granted the group " + $objGroup.Name + " the permission Replication Synchronization on the OU " + $objOU)
}

}
# End Role Functions
###############

Function Main
{
#       
#      .DESCRIPTION  
#          Main processing function
#  
    #Load Active Directory Module
    If ((LoadModule -name ActiveDirectory) -eq $True)
    {
        Write-Host -ForegroundColor Green "Loaded Active Directory Module"
    }
    Else 
    {
        Write-Host -ForegroundColor Red "Failed to load Active Directory Module"   
    }

    #Load Group Policy Module
    IF ((LoadModule -name GroupPolicy) -eq $True)
    {
        Write-Host -ForegroundColor Green "Loaded Group Policy Module"
    }
    Else 
    {
        Write-Host -ForegroundColor Red "Failed to load Group Policy Module"
    }
   
    If ($Backup)
    { 
        If(!(Test-Path $BackupFolder -ErrorAction SilentlyContinue))
        {  
            $result = New-Item $BackupFolder -ItemType Directory -Force
        }
        $gpoFolder = $BackupFolder      
        #Create the XML file to where the OU and GPO configuration will be exported
        Set-Content ($SettingsFile) "<?xml version='1.0' encoding='Unicode'?>" -Encoding Unicode
        Add-Content ($SettingsFile) "<Configuration>" -Encoding Unicode
        Add-Content ($SettingsFile) "<OrganizationalUnits>" -Encoding Unicode
        Add-Content ($SettingsFile) "</OrganizationalUnits>" -Encoding Unicode
        Add-Content ($SettingsFile) "<Users>" -Encoding Unicode
        Add-Content ($SettingsFile) "</Users>" -Encoding Unicode
        Add-Content ($SettingsFile) "<Groups>" -Encoding Unicode
        Add-Content ($SettingsFile) "</Groups>" -Encoding Unicode
        Add-Content ($SettingsFile) "<GroupMembership>" -Encoding Unicode
        Add-Content ($SettingsFile) "</GroupMembership>" -Encoding Unicode
        Add-Content ($SettingsFile) "<GroupPolicies>" -Encoding Unicode
        Add-Content ($SettingsFile) "</GroupPolicies>" -Encoding Unicode
        Add-Content ($SettingsFile) "</Configuration>" -Encoding Unicode

        #Backup the OU structure and GPOs

        if ($BackupOUs){
            Write-Host -ForegroundColor DarkGray "INFORMATION: Backing up Organisational Units..."
            Backup-OUs -path $gpoFolder
        }
        if ($BackupUsers){
            Write-Host -ForegroundColor DarkGray "INFORMATION: Backing up Users..."
            Backup-Users -path $gpoFolder
        }
        if ($BackupGroups){
            Write-Host -ForegroundColor DarkGray "INFORMATION: Backing up Groups..."
            Backup-Groups -path $gpoFolder
        }
        if ($BackupMemberships){
            Write-Host -ForegroundColor DarkGray "INFORMATION: Backing up Group Memberships..."
            Backup-GroupMembership -path $gpoFolder
        }
        if ($BackupPolicies){
            Write-Host -ForegroundColor DarkGray "INFORMATION: Backing up Group Policies..."
            Backup-GroupPolicy -path $gpoFolder
            #Create Migration Table
            CreateMigTable
        }
   }   
   ElseIf($Restore)
   {    
        $gpoFolder = $BackupFolder  
        $configXML = [xml](Get-content ($SettingsFile))  
                
        If($restoreOUs -eq $True)
        {
            #Restore Ous
            Write-Host -ForegroundColor DarkGray "INFORMATION: Restoring Organisational Units..."
            Restore-OU -path $gpoFolder
        }
      
        #Restore Users      
        If($restoreUsers -eq $true)
        {
            $dnsRoot = (Get-ADDomain).DNSRoot
            Write-Host -ForegroundColor DarkGray "INFORMATION: Restoring Users..."
            $userPassword=(ConvertTo-SecureString "P@ssw0rd" -AsPlainText -force)
            Foreach ($user in $configXML.Configuration.Users.User)
            {
                If (($user.Password -ne "") -and ($user.Password -ne $null)) 
                {
                    $userPassword = (ConvertTo-SecureString $user.Password -AsPlainText -force)
                }

                if (!$user.UserPrincipalName){
                    $upn = $user.SamAccountName + "@" + $dnsRoot
                } else
                {
                    $upn = $user.UserPrincipalName + "@" + $dnsRoot
                }
                $strUserPath = $user.distinguishedName.substring($user.distinguishedName.indexof(",")+1)
                $strUserPath = $strUserPath + $strDomainDN
                Restore-User -strUserName $user.name -strUserPrincipalName $upn -strUserSamAccountName $user.SamAccountName -strUserPath $strUserPath -strUserDisplayName $user.name -strGivenName $user.GivenName -strSurname $user.Surname -strUserDescription $user.Description -strSecurePassword $userPassword -bolPasswordNeverExpires $user.PasswordNeverExpires -bolCannotChangePassword $user.CannotChangePassword -bolChangePasswordAtLogon $user.ChangePasswordAtLogon
            }
        }

        If($restoreGroups -eq $true)
        {
            Write-Host -ForegroundColor DarkGray "INFORMATION: Restoring Groups..."
            Foreach ($group in $configXML.Configuration.Groups.Group)
            {
                Restore-Group -strGroupName $group.name -strGroupSamAccountName $group.SamAccountName -strGroupDisplayName $group.name -strGroupCategory $group.category -strGroupScope $group.scope -strGroupPath  ($group.distinguishedName.substring($group.distinguishedName.indexof(",")+1)) -strGroupDescription $group.Description
            }
        }

        If($restoreMemberships -eq $true)
        {
        Write-Host -ForegroundColor DarkGray "INFORMATION: Restoring Group Memberships..."
        foreach ($group in $configXML.Configuration.GroupMembership.Group)
        {
            foreach ($member in $group.Member)
            {
                Add-ToGroup -objIdentity $group.SamAccountName -objMember $member.SamAccountName
            }
         }
       }

       #Import the Group Policies from the XML file       
       If($restorePolicies -eq $true)
       {      
           Write-Host -ForegroundColor DarkGray "INFORMATION: Restoring Group Policies..."
           #Update Migration Table.
           UpdateMigTable
           Restore-WMIFilter -Path (Join-Path $gpoFolder "GPO")
           Restore-GroupPolicy -path $gpoFolder

           #Configure the Group Policy links and ordering
           if ($LinkGPOs)
           {
               Write-Host -ForegroundColor DarkGray "INFORMATION: Linking Group Policies to Organisational Units..."     
               Link-GroupPolicy -path $gpoFolder
           }
           else{
               Write-Host -ForegroundColor DarkGray "INFORMATION: Group Policies NOT linked to Organisational Units..."            
           }
       }    
       
       if ($RestorePermissions -eq $true)
       {
            Write-Host -ForegroundColor DarkGray ("INFORMATION: Restoring Permissions...")
            $permissionsXML = [xml](Get-content ($PermissionsFile)) 
            Set-Location ad:

            #Get a reference to the RootDSE of the current domain
            $rootdse = Get-ADRootDSE
            #Get a reference to the current domain
            $guidmap = @{}
            Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID | % {$guidmap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}

            #Create a hashtable to store the GUID value of each extended right in the forest
            $extendedrightsmap = @{}
            Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))"  -Properties displayName,rightsGuid | % {$extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid}

            #permissions defined in role $PermissionsFile!
            Foreach ($permission in $permissionsXML.Configuration.SetPermissions.Permission)
            {
                $groupIdentity = Get-Group ($permission.Group)
            
                If($permission.OU -eq "")
                {
                    $targetOU = $strDomainDN
                }
                Else
                {
                    $targetOU = (($permission.OU) + "," + $strDomainDN)
                }
                ConfigureRolePermissions -role $permission.roledefinition -ou $targetOU -group $groupIdentity -objInheritance $permission.propagate           
            }      
       }                        
   }   
}

#Test the presence of valid Configuration
Function CheckConfig
{
    If ($SearchBase -ne "")
    {
        $Searchbase = $SearchBase
        #test existance of the base?
    }
    Else
    {      
        $domain=(Get-ADDomain).DistinguishedName
        Write-Host -ForegroundColor DarkGray "INFORMATION: SearchBase set to '$domain'"
        $SearchBase = $domain
    }

	if ($BackupAll)
	{
		$Backup = $true
		$BackupOUs =$true
		$BackupUsers = $true
		$BackupGroups = $true
		$BackupMemberships = $true
		$BackupPolicies = $true
	} elseif ($RestoreAll)
	{
		$Restore = $true
		$RestoreOUs = $true
		$RestoreUsers = $true
		$RestoreGroups = $true
		$RestoreMemberships = $true
		$RestorePolicies = $true
		$RestorePermissions = $true
	}

    if ($BackupOUs -or $BackupUsers -or $BackupGroups -or $BackupMemberships -or $BackupPolicies)
    {
        $Backup = $true
    }

    if ($RestoreOUs -or $RestoreUsers -or $RestoreGroups -or $RestoreMemberships -or $RestorePolicies -or $RestorePermissions)
    {
        $Restore = $true
    }

    if ($Backup -and $Restore)
    {
        Write-Host -ForegroundColor Red "ERROR: You cannot backup and restore at the same time. Exiting..."
        Exit
    }

    if ($Backup)
    {
        If ($BackupFolder -ne "")
        {  
            $gpoFolder = $BackupFolder           
        }
        Else
        {
            Write-Host -ForegroundColor Red "ERROR: The backup folder path was not specified"
            Exit
        }

        If ($SettingsFile -ne "")
        {  
            $SettingsFile = Join-Path $BackupFolder -ChildPath $SettingsFile          
        }
        Else
        {
            Write-Host -ForegroundColor Red "ERROR: The file name for the settings XML file was not specified"
            Exit
        }

        If((!$MigrationTable -eq $null))
        {
            If(!(Test-Path $MigrationTable -PathType Leaf -ErrorAction SilentlyContinue)) {Write-Host -ForegroundColor Red "ERROR: The path to the migration table specified is invalid";Exit}
        } else
        {
            $MigrationTable = "MigrationTable.migtable"
        }

    } elseif ($Restore)
    {
        If(!(Test-Path $BackupFolder -ErrorAction SilentlyContinue))
        {   
            Write-Host -ForegroundColor Red "ERROR: The backup folder path specified is invalid. The path cannot be found or has not been specified"
            Exit
        }
        Else
        {
            $gpoFolder = $BackupFolder
        }

        If(!(Test-Path $SettingsFile -ErrorAction SilentlyContinue))
        {   
            $SettingsFile = Join-Path $BackupFolder -ChildPath $SettingsFile

            If(!(Test-Path $SettingsFile -ErrorAction SilentlyContinue))
            { 
                Write-Host -ForegroundColor Red "ERROR: The setting file path specified is invalid. The path cannot be found or has not been specified"
                Exit
            }
            else {$SettingsFile = $SettingsFile}
        } else {$SettingsFile = $SettingsFile}
   
        If (!($RestoreOUs -eq $true -or $RestoreOUs -eq $false))
        { 
            Write-Host -ForegroundColor Red "ERROR: The RestoreOUs configuration contains an invalid value"
            Exit
        }
        Else
        {
            If($RestoreOUs) { $restoreOUs = $true }
            Else{$restoreOUs = $false}
        }

        If (!($restoreUsers -eq $true -or $RestoreUsers -eq $false))
        { 
            Write-Host -ForegroundColor Red "ERROR: The RestoreUsers configuration contains an invalid value"
            Exit
        }
        Else
        {
            If($RestoreUsers) { $restoreUsers = $true }
            Else{$restoreUsers = $false}
        }

        If (!($RestoreGroups -eq $true -or $RestoreGroups -eq $false) )
        { 
            Write-Host -ForegroundColor Red "ERROR: The RestoreGroups configuration contains an invalid value"
            Exit
        }
        Else
        {
            If($RestoreGroups) { $restoreGroups = $true }
            Else{$restoreGroups = $false}
        }
        If (!($RestoreMemberships -eq $true -or $RestoreMemberships -eq $false)) 
        { 
            Write-Host -ForegroundColor Red "ERROR: The RestoreMemberships configuration contains an invalid value"
            Exit
        }
        Else
        {
            If($RestoreMemberships) { $restoreMemberships = $true }
            Else{$restoreMemberships = $false}
        }
        If (!($RestorePolicies -eq $true -or $RestorePolicies -eq $false))
        { 
            Write-Host -ForegroundColor Red "ERROR: The RestorePolicies configuration contains an invalid value"
            Exit
        }
        Else
        {
            If($RestorePolicies) { $restorePolicies = $true }
            Else{$restorePolicies = $false}
        }
        If (!($OverwriteExistingPolicies -eq $true -or $OverwriteExistingPolicies -eq $false) )
        { 
            Write-Host -ForegroundColor Red "ERROR: The OverwriteExistingPolicies configuration contains an invalid value"
            Exit
        } 
        Else
        {
            If($OverwriteExistingPolicies) { $overwriteExisting = $true }
            Else{$overwriteExisting = $false}
        }
        If((!$MigrationTable -eq $null))
        {
            If(!(Test-Path $MigrationTable -ErrorAction SilentlyContinue)) {Write-Host -ForegroundColor Red "ERROR: The path to the migration table specified is invalid";Exit}
        } else
        {
            $MigrationTable = "MigrationTable.migtable"
        }

        If($RestorePermissions -eq $true)
        {
           if (!$PermissionsFile){        
                $PermissionsFile = Join-Path $BackupFolder -ChildPath "RoleDefinitions.xml"
            }

            If(!(Test-Path $PermissionsFile -ErrorAction SilentlyContinue)) {Write-Host -ForegroundColor Red "ERROR: The path to the permissions file '$PermissionsFile' is invalid";Exit}      
        } 

        #If a target domain is specified use that, otherwise use the current
        If ($TargetDomain -ne "")
        {
            $domain = Get-ADDomain -Identity $targetDomain
            $Script:strDomainDN = $domain.DistinguishedName
        }
        Else
        {
            $domain = Get-ADDomain 
            $Script:strDomainDN = $domain.DistinguishedName
        }   
    }
    Write-Host -ForegroundColor Cyan "INFORMATION: Configuration Validation:"
    Write-Host -ForegroundColor Cyan ("SearchBase: " + $SearchBase)
    Write-Host -ForegroundColor Cyan ("Settings File Path: " + $SettingsFile)
    Write-Host -ForegroundColor Cyan ("Backup Folder Path: " + $BackupFolder)
    Write-Host -ForegroundColor Cyan ("Migration Table: " + $MigrationTable)
    
    if ($Restore){
        Write-Host -ForegroundColor Cyan ("Restore OUs: " + $RestoreOUs)
        Write-Host -ForegroundColor Cyan ("Restore Users: " + $RestoreUsers)
        Write-Host -ForegroundColor Cyan ("Restore Groups: " + $RestoreGroups)
        Write-Host -ForegroundColor Cyan ("Restore Memberships: " + $RestoreMemberships)
        Write-Host -ForegroundColor Cyan ("Restore Policies: " + $RestorePolicies)
        Write-Host -ForegroundColor Cyan ("Overwrite Existing Policies: " + $OverwriteExistingPolicies)
        Write-Host -ForegroundColor Cyan ("Restore GPO Links: " + $LinkGPOs)
        Write-Host -ForegroundColor Cyan ("Restore Permissions: " + $RestorePermissions)
        Write-Host -ForegroundColor Cyan ("Migration Table File Path: " + $MigrationTable)
        Write-Host -ForegroundColor Cyan ("Target Domain: " + $strDomainDN)
        #Write-Host -ForegroundColor Cyan ("Group Policy Filter: " + $GroupPolicyFilter)
    } elseif ($Backup)
    {
        Write-Host -ForegroundColor Cyan ("Backup OUs: " + $BackupOUs)
        Write-Host -ForegroundColor Cyan ("Backup Users: " + $BackupUsers)
        Write-Host -ForegroundColor Cyan ("Backup Groups: " + $BackupGroups)
        Write-Host -ForegroundColor Cyan ("Backup Memberships: " + $BackupMemberships)
        Write-Host -ForegroundColor Cyan ("Backup Policies: " + $BackupPolicies)
    }

	$currentDir = (Get-Item -Path ".\" -Verbose).FullName
    if ($Force)
    {
        Main
    }
    else{
        $prompt = Read-Host "Do you want to continue with the above settings? [Y/N]"

        if ($prompt.ToLower() -eq "y"){
            Main
        }
        else
        {
            Write-Host -ForegroundColor Cyan ("Exiting")
        }
    }
	Set-location $currentDir
}
####################################################################
# End Functions  
####################################################################
$currentdir = Split-path -parent $MyInvocation.MyCommand.Definition
CheckConfig