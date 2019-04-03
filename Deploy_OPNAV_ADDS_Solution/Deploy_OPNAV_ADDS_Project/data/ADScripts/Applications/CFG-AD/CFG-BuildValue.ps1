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


#Adding Registry Value for Build Value
$value = "Complete"
$keys = "HKLM:\SOFTWARE\Microsoft\Deployment 4"
$name = "Build Value"
Set-ItemProperty -path $keys -name $name -value $value
#Adding Registry Value for Build Value
Add-Log -LogEntry("Modifying Registry Entries: $Value, $Keys, $name")


Exit-Script