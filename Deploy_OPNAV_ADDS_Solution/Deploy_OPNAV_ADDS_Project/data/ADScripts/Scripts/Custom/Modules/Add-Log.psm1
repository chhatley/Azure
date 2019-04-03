<#
.Synopsis
   
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
Function Add-Log()
{
[CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("LogEntry")] 
        [string]$sLogEntry,
        
        [Parameter(Mandatory=$false, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("LogType")] 
        [string]$sLogType             
    )

    Begin
    {
    }
    Process
    {  

        $sForeColor = "Cyan"
        $sBackColor = "Black"

        If($sLogType.ToLower() -eq "error"){
            $sForeColor = "Red"
        }
        Elseif($sLogType.ToLower() -eq "warning"){
            $sForeColor = "Yellow"
        }

        If ($Global:sLogDir -eq $null){
            $sLogFile = "C:\Windows\Temp\PSConsole.log"
        }
        else{

            #$env:RunningScript = $MyInvocation.ScriptName -replace ".ps1", ""
            $ScriptName = ($Global:ScriptName -replace ".ps1", ".log")
            If ((Test-Path $Global:sLogDir) -eq $False){
                New-Item $Global:sLogDir -type directory
            }  
        
            #Define the Log File
            $sLogFile = ("$Global:sLogDir\$ScriptName")
        }

        
            

        #"Logfile = $sLogFile"
        #If the file exists then append to it.  If not then creat it
        If ((Test-Path $sLogFile) -eq $False){
            Write-Debug "Log file not found.  Creating $sLogFile"
            New-Item $sLogFile -type file | Out-Null        
        }
    
        $sLogTime = ((get-date).Hour.ToString() + ":" + (get-date).Minute.ToString() + ":" + (get-date).Second.ToString() + "." + "000+000")
        $sLogDate = ((get-date).Month.ToString() + "-" + (get-date).Day.ToString() + "-" + (get-date).Year.ToString())    
        $sCMLogEntry = ("<![LOG[$sLogEntry]LOG]!><time=" + [char]34 + $sLogTime + [char]34 + " date=" + [char]34 + $sLogDate + [char]34 + " component=" + [char]34 + $ScriptName + [char]34 + " context=" + [char]34 + [char]34 + " type="+ [char]34 + "1" + [char]34 + " thread=" + [char]34 + [char]34 + " file=" + [char]34 + $ScriptName + [char]34)
    
        Try{
            Write-Host -Fore $sForeColor (get-Date).ToShortDateString() (get-date).ToShortTimeString() $sLogEntry -BackgroundColor $sBackColor
            Add-Content $sLogFile $sCMLogEntry            
        }
        Catch{
            Write-Debug "Unable to create log entry in $sLogFile."
            Write-Debug $sCMLogEntry
        }  
    }  
}

Export-ModuleMember -Function Add-Log