Function Log-ExitCode{
    If($Global:ErrorCode -eq 0){
        $sLogType = "Informational"
        #[Environment]::SetEnvironmentVariable("LastActionStatus", "SUCCESS", "machine")
        try{$Global:TSEnv.Value("LastActionStatus") = "SUCCESS"}catch{}
        #$env:lastactionstatus = "SUCCESS"
    }
    Elseif($Global:ErrorCode -eq 1){
        $sLogType = "Warning"
        #[Environment]::SetEnvironmentVariable("LastActionStatus", "WARNING", "machine")
        try{$Global:TSEnv.Value("LastActionStatus") = "WARNING"}catch{}
        #$env:lastactionstatus = "WARNING"
    }
    Else{
        $sLogType = "Error"      
        #[Environment]::SetEnvironmentVariable("LastActionStatus", "FAILURE", "machine")
        try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
        #$env:lastactionstatus = "FAILURE"
    }
    Add-Log -LogEntry "Exit code: $($Global:ErrorCode) Exit message: $($Global:ErrorMessage)" -LogType $sLogType
}

Function Exit-Script{       
    Log-ExitCode
    try {Stop-Transcript | Out-Null} catch{}
    $Error.Clear()    
    exit $Global:ErrorCode
}

try{
    #if (([Environment]::GetEnvironmentVariable("LastActionStatus","machine")) -eq "FAILURE"){
    If ($Global:TSEnv.Value("ContinueOnError") -eq "NO" -and $Global:TSEnv.Value("LastActionStatus") -eq "ERROR"){
        $Global:ErrorCode = 3 
        $Global:ErrorMessage = "The last action failed.  Terminating this script."
        Exit-Script
    }
}
catch{}


