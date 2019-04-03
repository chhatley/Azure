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

### Unlink GPOs from T2-Devices

Function UnlinkPolicyDevices
{
Param([string]$DisplayName = $(throw"$DisplayName required."))
write-host "Unlinking $Displayname" -ForegroundColor Cyan
Remove-GPLink -Name $DisplayName -Target "OU=T2-Devices,OU=Tier 2,OU=Admin,$DomainDN" -ErrorAction SilentlyContinue -ErrorVariable ProcessError;
If ($ProcessError) {
    Write-Host "Error: Could not unlink $DisplayName policy.  Policy may have already been removed or was not present" -ForegroundColor Yellow
}

}

### Unlink GPOs from T2-Accounts

Function UnlinkPolicyUsers
{
Param([string]$DisplayName = $(throw"$DisplayName required."))
write-host "Unlinking $Displayname" -ForegroundColor Cyan
Remove-GPLink -Name $DisplayName -Target "OU=T2-Accounts,OU=Tier 2,OU=Admin,$DomainDN" -ErrorAction SilentlyContinue -ErrorVariable ProcessError;
If ($ProcessError) {
    Write-Host "Error: Could not unlink $DisplayName policy.  Policy may have already been removed or was not present" -ForegroundColor Yellow
}

}

### Main

$DomainDN = get-ADDomain |Select-Object -ExpandProperty DistinguishedName

Write-host "Unlinking T2 PAW RS2 policies" -ForegroundColor Green

UnlinkPolicyDevices -DisplayName "*- Tier 2 PAWs MSFT Windows 10 RS2 - Bitlocker"
UnlinkPolicyDevices -DisplayName "*- Tier 2 PAWs MSFT Windows 10 RS2 - Computer"
UnlinkPolicyDevices -DisplayName "*- Tier 2 PAWs MSFT Windows 10 and Server 2016 Defender - Windows 10 RS2"
UnlinkPolicyUsers -DisplayName "*- Tier 2 PAWs MSFT Windows 10 RS2 - User"

