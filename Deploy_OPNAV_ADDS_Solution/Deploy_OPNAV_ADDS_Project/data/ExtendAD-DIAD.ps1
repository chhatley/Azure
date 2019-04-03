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
        #>

# Extract Scripts

Expand-Archive .\ExportImportAD.zip $diadscripts -Force
 

# Import DIAD OUs/GPOs

cd $diadscripts

powershell -ExecutionPolicy Unrestricted -File "$diadscripts\ExportImport-AD.ps1" -RestoreAll -restorepolicies -LinkGPOs -Link2016 -LinkDomainPolicies -RedirectComputersContainers -BackupFolder "$diadscripts\" -SettingsFile "$diadscripts\settings.xml" -force


# Wait 30 seconds

Start-Sleep -Seconds 30

# copy the ADMXs to the domain controller

powershell -ExecutionPolicy Unrestricted -File "$diadscripts\ImportADMXs.ps1" -backupfolder "$diadscripts\"