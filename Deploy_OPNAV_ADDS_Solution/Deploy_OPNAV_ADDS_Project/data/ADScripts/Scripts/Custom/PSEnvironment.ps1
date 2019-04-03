
#Custom Error handling values
$Global:ErrorCode = 0 #0=Success, 1=Success with Information, 2=Error, 3=Error with Information
$Global:ErrorMessage =""

#Stop the transcript if it is running
try {Stop-Transcript | Out-Null} catch{}
$Error.Clear()

[reflection.assembly]::LoadWithPartialName("System.IO") | Out-Null
$Global:ScriptName = [System.IO.Path]::GetFileName($MyInvocation.ScriptName)
$Global:sLocalDir = $MyInvocation.PSScriptRoot
Set-Location $Global:sLocalDir
$Global:sLogDir = "C:\MININT\SMSOSD\OSDLOGS"
$sTranscriptFile = ("$Global:sLogDir\TRANSCRIPT-"+ $($Global:ScriptName -replace ".ps1", ".log"))


try{
    $Global:TSEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment    
    $Global:bTSEnv = $true
    }
catch{}
$Error.Clear()


if((Test-Path variable:global:TSEnv) -eq $true){
    #$Global:sLogDir = $Global:TSEnv.Value("_SMSTSLogPath")
    Add-Log -LogEntry "The TS Environment has been initialized"
}
else{    
    $Error.Clear()
    $Global:bTSEnv = $false
    #$Global:sLogDir = "C:\MININT\SMSOSD\OSDLOGS"
    #Add-Log -LogEntry "The TS Environment has not been initialized" -LogType "Warning"
}    

Start-Transcript -path $sTranscriptFile | Out-Null

If ((Test-Path "C:\pause.txt") -eq $true){
    Add-Log -LogEntry("Found C:\pause.txt")
    pause
}

Function Log-ExitCode{
    If($Global:ErrorCode -eq 0 -or $Global:ErrorCode -eq 3010){
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























<#
Function Get-NTDomain(){
	$NTDomain = Get-WmiObject Win32_NTDomain | Where-Object {$_.DomainName -ne $null} | Select-Object -ExpandProperty DomainName
    return $NTDomain
}
#>

Function Run-Command(){
    [CmdletBinding()]
    [OutputType([Int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        [Alias("CMD")] 
        $sCMD       
    )
    Begin
    {
        #Get the error count
        $ErrNum = $error.count
    }
    Process
    {
        try{       
            Invoke-Command -Command $sCMD -ErrorVariable RetVal | Out-Null
            #Check if an error occured
            If ($ErrNum -lt $error.count){        
                $Global:ErrorCode = 3
                $Global:ErrorMessage = $RetVal                                 
                return $Global:ErrorCode                     
            }
        }
        catch{
            $Global:ErrorCode = 3
            $Global:ErrorMessage = $_                            
            return $Global:ErrorCode
        }         
        return $Global:ErrorCode           
    }
}

