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

function Copy-Files
{
    [CmdletBinding()]
    [OutputType([int])]
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
        [Alias("Source")] 
        $sSourcePath        
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
        [string]
        [Alias("Destination")] 
        $sDestinationPath
    )

    Begin
    {
        $Global:ErrorCode = 0
        $Global:ErrorMessage =""
    }
    Process
    {   
        $counter = 1
        #Check if the source path exists.  If not then exit script
        If((Test-Path $sSourcePath) -eq $false){
            $Global:ErrorCode = 3
            $Global:ErrorMessage ="The source directory doesn't exist."
            Add-Log -LogEntry "Exit code: $($Global:ErrorCode) Exit message: $($Global:ErrorMessage)" -LogType "Error"
            return $ErrorCode
        }
    
        #Check if the destination path exists.  If not then create it
        If((Test-Path $sDestinationPath) -eq $false){
            Add-Log -LogEntry "The destination path doesn't exist.  Attempting to create it"            
            New-Item -Path $sDestinationPath -ItemType Directory | Out-Null
        }

        #If the destination path wasn't created exit the script
        If((Test-Path $sDestinationPath) -eq $false){
            $Global:ErrorCode = 3
            $Global:ErrorMessage ="The destination path couldn't be created."
            Add-Log -LogEntry "Exit code: $($Global:ErrorCode) Exit message: $($Global:ErrorMessage)" -LogType "Error"
            return $ErrorCode
        }
    
        Add-Log -LogEntry "Copying PowerShell modules from $sSourcePath to $sDestinationPath"        
               
        $oFiles = Get-ChildItem $sSourcePath -Recurse        
       
        Foreach ($sFilePath in $oFiles){
            Write-Progress -Activity "Copying $counter of $($oFiles.count) Files" -PercentComplete ($counter / $oFiles.count*100) -CurrentOperation "Copying file: $($sFilePath.Name)"
            $counter++    
            $sFileName = ($sFilePath.FullName -replace [regex]::Escape($sSourcePath), $sDestinationPath)            
            Copy-Item -Path $sFilePath.FullName -Destination $sFileName -Force -Verbose
        }
        Write-Progress -Complete -Activity "Close"
        
        <#
        #Verify the destination has the same amount of modules as the source
        If($oFiles.Count -ne (Get-ChildItem $sDestinationPath).Count){
            $Global:ErrorCode = 3
            $Global:ErrorMessage = "The number of modules in the destination isn't the same as the source."            
            return $ErrorCode        
        }      
        #>            
    }
}

Export-ModuleMember -Function Copy-Files