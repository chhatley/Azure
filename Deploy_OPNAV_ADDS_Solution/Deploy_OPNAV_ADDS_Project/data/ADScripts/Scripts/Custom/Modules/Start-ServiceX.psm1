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

function Start-ServiceX
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   #Position=0,
                   ParameterSetName='P1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        [Alias("SN")] 
        $ServiceName        
        ,
        # Param2 help description
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   #Position=2,
                   ParameterSetName='P1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [int]
        [Alias("A")] 
        $Amount
    )

    Begin
    {
        $Amount = 0
    }
    Process
    {   #Check if service exists
        Add-Log -LogEntry "Checking if $($ServiceName) exists"
        If((gwmi Win32_Service -Filter "Name='$($ServiceName)'") -eq $null) {
            Add-Log -LogEntry $("The service $ServiceName doesn't exists")
            return 0 | Out-Null  
        }

        Add-Log -LogEntry "Getting the status of $($ServiceName)"
        $Service = Get-Service | Where-Object {$_.Name -eq $ServiceName}
        #Start the SRS service if it is not running.  Only try 10 times
        If ($Service.Status -eq "Running")
        {                                        
            Add-Log -LogEntry $("Service $ServiceName is running.")
            return 0 | Out-Null  
        } 
        
        #Start the service if it is not running.  Only try 10 times
        If ($Service.Status -ne "Running" -and $Amount -le 10)
        {                                        
            Add-Log -LogEntry $("Attempting to start the $ServiceName service")
            Start-Service $ServiceName
        } 
        else{
            Add-Log -LogEntry "Unable to start service"
            return 3 | Out-Null  
        }
 
        #Check if the service is running.  If not try again for until 10 times
        $Service = Get-Service | Where-Object {$_.Name -eq $ServiceName}
        If ($Service.Status -ne "Running" -and $Amount -le 10)
        {       
            Add-Log -LogEntry $("The service didn't start.  Attempting to start service $Amount of 10 times.")
            Start-ServiceX -SN $ServiceName -A ($Amount + 1)
        }
        Else
        {
            Add-Log -LogEntry $("Service $ServiceName is running.")            
        }
        return 0 | Out-Null         
    }
}

Export-ModuleMember -Function Start-ServiceX