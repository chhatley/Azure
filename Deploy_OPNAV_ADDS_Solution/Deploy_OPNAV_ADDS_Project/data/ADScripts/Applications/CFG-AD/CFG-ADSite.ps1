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


If($Global:bTSEnv -eq $true){
    $NewSiteName = $DomainAdmin =  $Global:TSEnv.Value("SiteName") 
}
Else{
    $NewSiteName = "TEST"
}


$DSE = (Get-ADRootDSE).defaultNamingContext
$SiteName = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration," + $($DSE)
Rename-ADObject -Identity $SiteName -NewName $NewSiteName
If($? -eq $false){
    Add-Log -LogEntry "Unable to rename the AD Site Name"
}

Exit-Script