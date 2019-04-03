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
        V1.2 12 September 2017 - Updated for 1703 baselines
        V1.1 02 February 2017 - renamed policies
        V1.0 16 August 2016
        

#>

$DomainDN = get-ADDomain |select -ExpandProperty DistinguishedName

Set-GPLink -Name "*- Additional Domain Security Settings" -Target $DomainDN -LinkEnabled Yes
Set-GPLink -Name "*- MSFT Windows 10 and Server 2016 - Domain Security" -Target $DomainDN -LinkEnabled Yes

