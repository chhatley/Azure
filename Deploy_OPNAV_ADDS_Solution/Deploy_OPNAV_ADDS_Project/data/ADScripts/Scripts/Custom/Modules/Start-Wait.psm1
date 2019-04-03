$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
$StopWatch.Stop()
$StopWatch.Start()
Function Wait-Process($oProcess, $a){
    $ElapsedTime = [String]::Format("{0:00}:{1:00}:{2:00}", $StopWatch.Elapsed.Hours, $StopWatch.Elapsed.Minutes, $StopWatch.Elapsed.Seconds);  
    If ($oProcess.HasExited -eq $false){
        Write-Progress -Activity "Title: $RunTitle - The process $($oProcess.Name) with PID $($oProcess.Id) started at $($oProcess.StartTime)" -Status "Time Elapsed:" -CurrentOperation $($ElapsedTime)
        Start-Sleep -Seconds 1    
        $a = $a + 1
        Wait-Process $oProcess $a
    }  
    Else{     
        Return $oProcess.GetType().GetField("exitCode", "NonPublic,Instance").GetValue($oProcess)
    }
    <#
    else{           
        $exitcode = $oProcess.GetType().GetField("exitCode", "NonPublic,Instance").GetValue($oProcess)  
        If ($exitcode -eq 0 -or $exitcode -eq 1 -or $exitcode -eq 3010 -or $exitcode -eq -2068709375){
            Add-Log -LogEntry $("Process $($oProcess.Name) returned with exit code $exitcode.  Elapsed Time: $ElapsedTime")
        }
        Else
        {
            Add-Log -LogEntry $("Process $($oProcess.Name) returned with exit code $exitcode.  Elapsed Time: $ElapsedTime") -LogType "ERROR"
        }         
        Return $exitcode
    }  
    #>  
}

Function Start-Wait ()
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("File")] 
        [string]$sFile      
        ,

        [Parameter(Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Args")]
        [string]$sArgs
        ,

        [Parameter(Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Source")]
        [string]$sSourceDir,

        [Parameter(Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Title")]
        [string]$RunTitle 
        ,

        [Parameter(Mandatory=$false, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Acc")]
        [System.Management.Automation.PSCredential]$Account
    )

    Begin
    {
    }
    Process
    {   
        $Error.Clear()
        If($Account -eq $null){
            try {   
                $StopWatch.Start()      
                $env:SEE_MASK_NOZONECHECKS = 1
                $oProcess = Start-Process -FilePath "$sSourceDir\$sFile" -ArgumentList $sArgs -WorkingDirectory $sSourceDir -PassThru -ErrorAction Stop   
                Remove-Item env:SEE_MASK_NOZONECHECKS                          
            } 
            catch {
                #Write-Host "ERROR: " $_ -ForegroundColor Red -BackgroundColor Black
                Add-Log -LogEntry $("ERROR: $_") -LogType "ERROR"
                Return 2
            }            
        }
        Else{
            
            try { 
                 #Write-Host -fore Cyan "Running with alternate credentials" 
                 Add-Log -LogEntry "Running with alternate credentials"                 
                 $env:SEE_MASK_NOZONECHECKS = 1
                 $oProcess = Start-Process -FilePath "$sSourceDir\$sFile" -ArgumentList $sArgs -WorkingDirectory $sSourceDir -Credential $Account -PassThru -ErrorAction Stop
                 Remove-Item env:SEE_MASK_NOZONECHECKS 
            } 
            catch {
                #Write-Host "ERROR: " $_ -ForegroundColor Red -BackgroundColor Black
                Add-Log -LogEntry $("ERROR: $_") -LogType "ERROR"
                Return 2
                
            }              
        }
        
        #Write-Host -fore Cyan "The process" $oProcess.Name "PID" $oProcess.Id "started at" $oProcess.StartTime
        Add-Log -LogEntry $("The process $($oProcess.Name) PID $($oProcess.Id) started at $($oProcess.StartTime)")
        $RetVal = Wait-Process $oProcess $a         
        $StopWatch.Reset()         
        Return $RetVal
    }
}
Export-ModuleMember -Function Start-Wait