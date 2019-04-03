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
        v1.5 1 July 2018 - Updated for removing EMET.
        v1.4 28 June 2018 - Updated for a Typo in DCs Defender policy.
        v1.3 28 April 2018 - Updated for GPO Rename 
        V1.2 12 September 2017 - Updated for 1703 Baselines
        V1.1 02 February 2017 - #'d out Cred Guard policy and renamed policies
        V1.0 16 August 2016
        

#>

$DomainDN = get-ADDomain |select -ExpandProperty DistinguishedName

Set-GPLink -Name "*- Tier 0 DCs SCM Windows Server 2016 - Domain Controller Baseline" -Target "ou=Domain Controllers,$DomainDN" -LinkEnabled Yes
Set-GPLink -Name "*- Tier 0 DCs MSFT Windows 10 and Server 2016 Defender" -Target "ou=Domain Controllers,$DomainDN" -LinkEnabled Yes
#Set-GPLink -Name "*- SCM Windows 10 and Server 2016 - Credential Guard" -Target "ou=Domain Controllers,$DomainDN" -LinkEnabled Yes
Set-GPLink -Name "*- Tier 0 DCs MSFT Internet Explorer 11 - Computer" -Target "ou=Domain Controllers,$DomainDN" -LinkEnabled Yes
#Set-GPLink -Name "*- Tier 0 DCs EMET Baseline" -Target "ou=Domain Controllers,$DomainDN" -LinkEnabled Yes
Remove-GPO -Name "*- Tier 0 DCs MSFT Windows Server 2012 R2 Domain Controller Baseline"
Remove-GPO -Name "*- WMI Filter Placeholder GPO - Not in Use"