#region Includes
#Include PS Environment
. ..\..\Scripts\Custom\PSEnvironment.ps1
#Exit the script if previous one in a Task Sequence failed
try{If ($Global:TSEnv.Value("ContinueOnError") -eq "NO" -and $Global:TSEnv.Value("LastActionStatus") -eq "ERROR"){
        $Global:ErrorCode = -9999;$Global:ErrorMessage = "The last action failed.  Terminating this script.";Exit-Script}}catch{}

#Set the trap
trap{try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
    $Global:ErrorCode = 3;$Global:ErrorMessage = "Exception: $($_.Exception.GetType().FullName) $($_.Exception.Message)";Exit-Script}
#endregion---------------------------------------------------------------------------------------------------------------------------------------------

#region Includes
#Include PS Environment
. ..\..\Scripts\Custom\PSEnvironment.ps1
#Exit the script if previous one in a Task Sequence failed
try{If ($Global:TSEnv.Value("ContinueOnError") -eq "NO" -and $Global:TSEnv.Value("LastActionStatus") -eq "ERROR"){
        $Global:ErrorCode = -9999;$Global:ErrorMessage = "The last action failed.  Terminating this script.";Exit-Script}}catch{}

#Set the trap
trap{try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
    $Global:ErrorCode = 3;$Global:ErrorMessage = "Exception: $($_.Exception.GetType().FullName) $($_.Exception.Message)";Exit-Script}
#endregion---------------------------------------------------------------------------------------------------------------------------------------------


#Copy ExportImport files from MDT ISO

$DVDDrive = Get-WmiObject -Class Win32_CDROMDrive
$DVDDriveLetter = $DVDDrive.Drive

foreach ($DL in $DVDDriveLetter)
{
    $ExportImportSource = "" + $DL +"\Deploy\Applications\CFG-AD\ExportImportAD"
# if exists, copy
if (Test-Path($ExportImportSource))
    {
        $ExportImportDest = "C:\ExportImportAD"
        Add-Log -LogEntry ("Copying ExportImport Scripts locally")
        Copy-Files -Source $ExportImportSource -Destination $ExportImportDest
     }
    
}

If($Global:ErrorCode -gt 1){Exit-Script}

Exit-Script