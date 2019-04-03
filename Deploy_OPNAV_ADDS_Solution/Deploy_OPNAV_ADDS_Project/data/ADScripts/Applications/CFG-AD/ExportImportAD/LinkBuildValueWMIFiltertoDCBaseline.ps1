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
        V1.1 28 April 2018 - Updated for GPO rename 
        V1.0 02 February 2017 - #'d out Cred Guard policy and renamed policies

#>

### Import Modules we need ###

Import-Module ActiveDirectory
Import-Module GroupPolicy
# for *-GpWmiFilter cmdlets; From: http://gallery.technet.microsoft.com/scriptcenter/Group-Policy-WMI-filter-38a188f3

$DomainName = get-ADDomain |select -ExpandProperty Name

#### Select Build Value WMI Query #######

$WMIFilterADObject = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties "msWMI-Name","msWMI-Parm1","msWMI-Parm2" | 
                Where {$_."msWMI-Name" -eq "Build Value"}

#### Link Filters to Group Policy Objects ####

$GPODC2016 = get-gpo -name "*- Tier 0 DCs SCM Windows Server 2016 - Domain Controller Baseline" -ErrorAction SilentlyContinue
$GPODC2012R2 = get-gpo -name "*- Tier 0 DCs MSFT Windows Server 2012 R2 Domain Controller Baseline" -ErrorAction SilentlyContinue

#Perform Operations on WMI Filter

#$FilterObject =  Get-WMIFilterInADObject -Name $WMIFilterADObject.'msWMI-Name'

$gpDomain = New-Object -Type Microsoft.GroupPolicy.GPDomain
$path = 'MSFT_SomFilter.Domain="' + $gpDomain.DomainName + '",ID="' + $WMIFilterADobject.Name + '"'
$filter = $gpDomain.GetWmiFilter($path)
[Guid]$Guid = $WMIFilterADobject.Name.Substring(1, $WMIFilterADobject.Name.Length - 2)
$filter | Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru | Add-Member -MemberType NoteProperty -Name Content -Value $WMIFilterADobject."msWMI-Parm2" -PassThru | Write-Output

###Link Filter to GPOs ####

$GPODC2016.WmiFilter = $filter
$GPODC2012R2.WmiFilter = $filter



