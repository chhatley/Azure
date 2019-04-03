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
function Get-FQDN
{

    Begin
    {        
    }
    Process
    {
	    $FQDN = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain
        return $FQDN.Trim()
        
    }
    End
    {
    }
}
Export-ModuleMember -Function Get-FQDN