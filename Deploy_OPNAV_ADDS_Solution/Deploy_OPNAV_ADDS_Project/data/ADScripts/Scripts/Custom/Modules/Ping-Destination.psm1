Function Ping-Destination{
    [CmdletBinding()]
    [OutputType([boolean])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        [Alias("D")]$Destination
        ,
        # Param2 help description
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [int]
        [Alias("A")] 
        $Amount       
    )
    Begin
    {
    }
    Process
    {
        try{
            If($Amount -lt 10 -and $Amount -gt 0){
                $Ping = New-Object System.Net.NetworkInformation.Ping
                Add-Log -LogEntry "Pinging $Destination : $Amount of 10"
                $PingStatus = $ping.Send($Destination, 3000).Status                
                If ($PingStatus -eq "Success")
                    {Add-Log -LogEntry "Status: $PingStatus"; Return 0}
                Else{
                    Add-Log -LogEntry "Status: $PingStatus" -LogType "Warning"
                    $Amount++
                    Ping-Destination -Destination $Destination -A $Amount                               
                    }
            }
        }
        catch{
            Add-Log -LogEntry "Unable to resolve $Destination" -LogType "Error"
            Return 1
        }           
    }
}
Export-ModuleMember -Function Ping-Destination