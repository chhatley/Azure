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
function Add-ToLocalGroup
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
        [Alias("SO")] 
        $SourceObject        
        ,
        # Param2 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   #Position=2,
                   ParameterSetName='P1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        [Alias("DO")] 
        $DestinationObject

    )

    Begin
    {
    }
    Process
    {
        <#if ($pscmdlet.ShouldProcess("Target", "Operation"))
        {

        }
        #>
            try{
                #Write-Host "Source:" $SourceObject
                $oSourceObject = [ADSI]("WinNT://"+$SourceObject)
                #$oSourceObject
            }
            catch{            
                                   
                return 3
            }

            try{
                #Write-Host "Dest:" $DestinationObject
                $oDestinationObject=[ADSI]("WinNT://./"+$DestinationObject)
                #$oDestinationObject
            }
            catch{
                return 2
            }

            try{
                $oDestinationObject.Add(($oSourceObject).Path)
                }
            catch{
                Return 2 
            }
            return 0
    }
    End
    {
    }
}