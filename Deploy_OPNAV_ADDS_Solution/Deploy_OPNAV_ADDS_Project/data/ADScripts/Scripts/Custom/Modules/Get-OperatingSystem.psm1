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
function Get-OperatingSystem
{

    Begin
    {        
    }
    Process
    {
        $OS = (Get-WmiObject WIN32_OperatingSystem).Caption
        Return $OS
        
    }
    End
    {
    }
}
Export-ModuleMember -Function Get-OperatingSystem