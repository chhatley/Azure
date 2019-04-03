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
        V1.0 11 April 2018 - first version
        

#>
Import-Module Admpwd.ps
set-AdmPwdComputerSelfPermission T0-Devices
set-AdmPwdComputerSelfPermission T1-Devices
set-AdmPwdComputerSelfPermission T2-Devices
set-AdmPwdComputerSelfPermission Devices
set-AdmPwdComputerSelfPermission "Tier 1 Servers"
set-AdmPwdComputerSelfPermission T0-Servers
