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
        V1.0 29 July 2016
        v1.1 27 April 2018 - Added UserProxySettings ADMX

#>

param(

    [Parameter(Mandatory=$true)]
    [string] $BackupFolder
    
)

# Copy ADMX and ADML to DC policy storage

Copy-Item "$BackupFolder\ADMXs\EMET.admx" "C:\Windows\PolicyDefinitions"
Copy-Item "$BackupFolder\ADMXs\EMET.adml" "C:\Windows\PolicyDefinitions\en-us"
Copy-Item "$BackupFolder\ADMXs\FEP2010.admx" "C:\Windows\PolicyDefinitions"
Copy-Item "$BackupFolder\ADMXs\FEP2010.adml" "C:\Windows\PolicyDefinitions\en-us"
Copy-Item "$BackupFolder\ADMXs\admpwd.admx" "C:\Windows\PolicyDefinitions"
Copy-Item "$BackupFolder\ADMXs\admpwd.adml" "C:\Windows\PolicyDefinitions\en-us"
Copy-Item "$BackupFolder\ADMXs\MSS-legacy.admx" "C:\Windows\PolicyDefinitions"
Copy-Item "$BackupFolder\ADMXs\MSS-legacy.adml" "C:\Windows\PolicyDefinitions\en-us"
Copy-Item "$BackupFolder\ADMXs\SecGuide.admx" "C:\Windows\PolicyDefinitions"
Copy-Item "$BackupFolder\ADMXs\SecGuide.adml" "C:\Windows\PolicyDefinitions\en-us"
Copy-Item "$BackupFolder\ADMXs\UserProxySettings.admx" "C:\Windows\PolicyDefinitions"
Copy-Item "$BackupFolder\ADMXs\UserProxySettings.adml" "C:\Windows\PolicyDefinitions\en-us"



### END ###