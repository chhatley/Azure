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
        
        V1.0 03 July 2018
        

#>

### Functions

### Unlink GPOs from Devices

Function UnlinkPolicyDevices
{
Param([string]$DisplayName = $(throw"$DisplayName required."))
write-host "Unlinking $Displayname" -ForegroundColor Cyan
Remove-GPLink -Name $DisplayName -Target "OU=Devices,$DomainDN" -ErrorAction SilentlyContinue -ErrorVariable ProcessError;
If ($ProcessError) {
    Write-Host "Error: Could not unlink $DisplayName policy.  Policy may have already been removed or was not present" -ForegroundColor Yellow
}

}

### Unlink GPOs from User Accounts

Function UnlinkPolicyUsers
{
Param([string]$DisplayName = $(throw"$DisplayName required."))
write-host "Unlinking $Displayname" -ForegroundColor Cyan
Remove-GPLink -Name $DisplayName -Target "OU=User Accounts,$DomainDN" -ErrorAction SilentlyContinue -ErrorVariable ProcessError;
If ($ProcessError) {
    Write-Host "Error: Could not unlink $DisplayName policy.  Policy may have already been removed or was not present" -ForegroundColor Yellow
}

}

### Main

$DomainDN = get-ADDomain |Select-Object -ExpandProperty DistinguishedName

Write-host "Unlinking Tier 2 RS3 policies" -ForegroundColor Green

UnlinkPolicyDevices -DisplayName "*- Tier 2 MSFT Windows 10 RS3 - Bitlocker"
UnlinkPolicyDevices -DisplayName "*- Tier 2 MSFT Windows 10 RS3 - Computer"
UnlinkPolicyDevices -DisplayName "*- Tier 2 MSFT WIndows 10 and Server 2016 Defender Antivirus - Windows 10 RS3"
UnlinkPolicyUsers -DisplayName "*- Tier 2 MSFT Windows 10 RS3 - User"

