#OU to be secured
$strOUToBeSecured = "OU=Admin,DC=corp,DC=contoso,DC=com"

#Get AD Domain, domain NetBIOSName, and forest NetBIOS name
$domCurrent = Get-ADDomain
$strDomainSID = $domCurrent.DomainSID
$strDomain = $domCurrent.NetBIOSName
$strForestDomainSID = (Get-ADDomain $domCurrent.Forest).DomainSID

#Get relevant schema GUIDs from AD
$dseRoot = Get-ADRootDSE
$cchObjectClasses = @{} #Blank cache for object type results
$cchObjectClasses.Add("All-Objects", "00000000-0000-0000-0000-000000000000") #all objects GUID

#Get all class and attribute objects in AD schema
Get-ADObject -SearchBase $dseRoot.SchemaNamingContext -LDAPFilter "(|(objectClass=classSchema)(objectClass=attributeSchema))" -Properties Name, schemaIDGUID -SearchScope OneLevel | %{
    $cchObjectClasses.add($_.Name, ([system.guid]$_.schemaIDGUID).guid)
}

#Get all extended rights in forest
Get-ADObject -SearchBase "CN=Extended-Rights,$($dseRoot.ConfigurationNamingContext)" -LDAPFilter "(objectClass=controlAccessRight)" -Properties name, rightsGUID -SearchScope OneLevel | %{
    $cchObjectClasses.add($_.Name, $_.rightsGUID)
}

#Create access masks
$acmFull = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll.value__
$acmReadWrite = ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead -bxor [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
$acmRead = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead.value__
$acmWrite = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite.value__
$acmLcLoRapRp = ([System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bxor [System.DirectoryServices.ActiveDirectoryRights]::ListObject -bxor [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bxor [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)
$acmReadProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty.value__
$acmWriteProperty = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty.value__
$acmReadPropertyWriteProperty = ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bxor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
$acmReadPropertyWritePropertyExtendedRight = ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bxor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bxor [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
$acmLcLoRapR = ([System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bxor [System.DirectoryServices.ActiveDirectoryRights]::ListObject -bxor [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bxor [System.DirectoryServices.ActiveDirectoryRights]::GenericRead)

#Create inheritance flag values
$inhObject = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::ObjectInherit.value__
$inhThis = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None.value__
$inhDescendants = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents.value__
$inhAll = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All.value__

#Create propagation flag values
$prpNone = [System.Security.AccessControl.PropagationFlags]::None.value__

#Create access control type values
$actAllow = [System.Security.AccessControl.AccessControlType]::Allow.value__

#Create identity references
$idrSystem = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-5-18"
$idrEnterpriseAdmins = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "$strForestDomainSID-519"
$idrDomainAdmins = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "$strDomainSID-512"
$idrAdministrators = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-5-32-544"
$idrSelf = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-5-10"
$idrEnterpriseDomainControllers = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-5-9"
$idrAuthenticatedUsers = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-5-11"

#Create an array of ACEs for the object
$arrACEs = @()
#Add the ACEs to the ACL
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrSystem, $acmFull, $actAllow, $inhAll) 
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrEnterpriseAdmins, $acmFull, $actAllow, $inhAll)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrDomainAdmins, $acmFull, $actAllow, $inhAll)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrAdministrators, $acmFull, $actAllow, $inhAll)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrSelf, $acmReadPropertyWriteProperty, $actAllow, $cchObjectClasses.'ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity', $inhAll)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrSelf, $acmReadPropertyWritePropertyExtendedRight, $actAllow, $cchObjectClasses.'Private-Information', $inhAll)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrSelf, $acmReadPropertyWriteProperty, $actAllow, $cchObjectClasses.'ms-Mcs-AdmPwdExpirationTime',$inhDescendants, $cchObjectClasses.Computer)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrSelf, $acmWriteProperty, $actAllow, $cchObjectClasses.'ms-Mcs-AdmPwd',$inhDescendants, $cchObjectClasses.Computer)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrSelf, $acmWriteProperty, $actAllow, $cchObjectClasses.'ms-TPM-Tpm-Information-For-Computer',$inhDescendants, $cchObjectClasses.Computer)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrEnterpriseDomainControllers, $acmRead, $actAllow, $inhAll)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrEnterpriseDomainControllers, $acmReadProperty, $actAllow, $inhDescendants, $cchObjectClasses.User)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrEnterpriseDomainControllers, $acmReadProperty, $actAllow, $inhDescendants, $cchObjectClasses.Computer)
$arrACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($idrAuthenticatedUsers, $acmRead, $actAllow, $inhAll) 

#Get the ACL for the current 
$aclCurrent = (Get-ADObject $strOUToBeSecured -properties nTSecurityDescriptor).NTSecurityDescriptor

#Update ACE
$aclCurrent.Access | %{
    $aclCurrent.RemoveAccessRuleSpecific($_)
}

#Remove self ACE (not sure where this comes from)
$aclCurrent.PurgeAccessRules($idrSelf)

#Add each ACE in $arrACEs
$arrACEs | %{
    #Determine if the ACE already exists
    if ($aclCurrent.access -notcontains $_) {
        #ACE does not exist.  Add it.
        $aclCurrent.AddAccessRule($_)
    }
}

#Block inheritance
$aclCurrent.SetAccessRuleProtection($True, $False)

#Commit the changes
Set-ACL "AD:\$strOUToBeSecured" -AclObject $aclCurrent

#Remove explicit access from any OUs below the designated OU and enable inheritance
Get-Childitem "AD:\$strOUToBeSecured" | ?{$_.objectClass -eq "organizationalUnit"} | %{
    $aclCurrent = (Get-ADOrganizationalUnit $_.DistinguishedName -Properties nTSecurityDescriptor).NTSecurityDescriptor
    $aclCurrent.access | ?{$_.IsInherited -eq $False} | %{
        $aclCurrent.RemoveAccessRuleSpecific($_)
    }

    $aclCurrent.SetAccessRuleProtection($False,$True)

    Set-ACL "AD:\$($_.distinguishedname)" -AclObject $aclCurrent
} 
