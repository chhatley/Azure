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
function Get-NTDomain
{

    Begin
    {        
    }
    Process
    {
        $NTDomain = Get-WmiObject Win32_NTDomain | Where-Object {$_.DomainName -ne $null} | Select-Object -ExpandProperty DomainName
        return $NTDomain        
    }
    End
    {
    }
}
Export-ModuleMember -Function Get-NTDomain