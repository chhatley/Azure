#region Includes
Import-Module .\modules\copy-files.psm1 -verbose
Import-Module .\modules\add-log.psm1 -verbose

#Include PS Environment
. .\PSEnvironment.ps1

#Set the trap
trap{
    try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
    $Global:ErrorCode = 3 #0=Success, 1=Success with Information, 2=Error, 3=Error with Information
    $Global:ErrorMessage = "Exception: $($_.Exception.GetType().FullName) $($_.Exception.Message)"
    try{Exit-Script}catch{write-host "ERROR exiting script"}
}


#endregion---------------------------------------------------------------------------------------------------------------------------------------------

$sSourcePath = $Global:sLocalDir+"\Modules"
$sDestinationPath = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Hydration"

Copy-Files -Source "$sSourcePath" -Destination $sDestinationPath
If($Global:ErrorCode -gt 1){Exit-Script}          

Remove-Module copy-files -Verbose
Remove-Module add-log -Verbose

Exit-Script



