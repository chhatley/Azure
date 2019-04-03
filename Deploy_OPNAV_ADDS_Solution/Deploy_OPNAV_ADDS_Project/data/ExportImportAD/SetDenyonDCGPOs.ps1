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
        V1.1 28 April 2018 - Updated for GPO Rename 
        V1.0 02 February 2017
        

#>

####### Start Functions ##########

Function ApplyPermissions($Guid)
{
$adgpo = [ADSI]"LDAP://CN=`{$($Guid)`},CN=Policies,CN=System,$DomainDN"

$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        [System.Security.Principal.NTAccount]"$domainNB\Tier 0 Build Domain Controller using MDT",
		"ExtendedRight",
		"Deny",
		[Guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939"
	)

$acl = $adgpo.ObjectSecurity
$acl.AddAccessRule($rule)
$adgpo.CommitChanges()
}

####### END Functions ############

####### MAIN ########

$DomainDN = get-ADDomain |select -ExpandProperty DistinguishedName
$domainNB = get-ADDomain |select -ExpandProperty NetBIOSName
$DC2016 = get-GPO -Name "*- Tier 0 DCs SCM Windows Server 2016 - Domain Controller Baseline" |select -ExpandProperty id
$DC2016Guid = $DC2016.Guid
$DC2012R2 = get-GPO -Name "*- Tier 0 DCs MSFT Windows Server 2012 R2 Domain Controller Baseline" |select -ExpandProperty id
$DC2012R2Guid = $DC2012R2.Guid
ApplyPermissions $DC2016Guid
ApplyPermissions $DC2012R2Guid

##### END ###########
