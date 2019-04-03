#region Includes
#Include PS Environment
. ..\..\Scripts\Custom\PSEnvironment.ps1
. ..\..\Scripts\Custom\ADEnvironment.ps1
#Exit the script if previous one in a Task Sequence failed
try{If ($Global:TSEnv.Value("ContinueOnError") -eq "NO" -and $Global:TSEnv.Value("LastActionStatus") -eq "ERROR"){
        $Global:ErrorCode = -9999;$Global:ErrorMessage = "The last action failed.  Terminating this script.";Exit-Script}}catch{}

#Set the trap
trap{try{$Global:TSEnv.Value("LastActionStatus") = "ERROR"}catch{}
    $Global:ErrorCode = 3;$Global:ErrorMessage = "Exception: $($_.Exception.GetType().FullName) $($_.Exception.Message)";Exit-Script}
#endregion---------------------------------------------------------------------------------------------------------------------------------------------

<#########################################################################
This script does the following:
- Creates a new svc-domainjoin user account that is used to join machines to the domain
- Creates a new Domain Join Users group
- Adds the user to the group
- Delegates the necessary permissions on the Staging Server, Staging and Admin Desktop OUs
     to the group to allow members to join machines to the domain
- Sets the ms-ds-MachineAccountQuota to 0 to prevent other users from joining machines to the domain


##########################################################################
Version History:
V1.2 - 14 July 2014 Andrej Budja (abudja)
     - integrated original script into MDT Task Sequence
V1.1 - 23 Mar 2015 Andrej Budja (abudja)
     - Fixed the permission error
V1.0 - 11 Mar 2015 Andrej Budja (abudja)

#########################################################################>


#####################################
# Initialize current environment variables
#####################################
$username = "svc-domainjoin"
$groupname = "domainjoinusers"

$rootdse = Get-ADRootDSE
$extendedrightsmap = @{} 
Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | % {$extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid}
$spnguid = [System.Guid](Get-ADObject -Identity ("CN=Service-Principal-Name," + $rootdse.SchemaNamingContext) -Properties schemaIDGUID).schemaIDGUID
$computerguid = [System.Guid](Get-ADObject -Identity ("CN=Computer," + $rootdse.SchemaNamingContext) -Properties schemaIDGUID).schemaIDGUID
$domain = Get-ADDomain
$domainName = $domain.DNSRoot

$groups = (Get-ADObject -LDAPFilter "(&(objectclass=organizationalUnit)(name=Groups))").DistinguishedName
$serviceAccounts = (Get-ADObject -LDAPFilter "(&(objectclass=organizationalUnit)(name=Service Accounts))").DistinguishedName

#####################################
# Function definitions
#####################################
#http://support.microsoft.com/kb/932455
# Create Computer Accounts
# Delete Computer Accounts
# Reset Password
# Read and write Account Restrictions
# Validated write to DNS host name 
# Validated write to service principal name

function Set-DomainJoinPermissions($groupsid, $ou)
{
    #Write-Host "Setting Domain Join Permissions on: " $ou -Fore Cyan
    Add-Log -LogEntry ("Setting Domain Join Permissions on:" + $ou)

    Try {
        $Error.Clear()
        $ace1 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"CreateChild,DeleteChild","Allow",$computerguid
        $ace2 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],"Descendents",$computerguid
        $ace3 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"readproperty,writeproperty","Allow",$extendedrightsmap["Account Restrictions"],"Descendents",$computerguid
        $ace4 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"writeproperty","Allow",$extendedrightsmap["DNS Host Name Attributes"],"Descendents",$computerguid
        $ace5 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"writeproperty","Allow",$spnguid,"Descendents",$computerguid

        $acl = Get-ACL -Path ("AD:\"+$ou)
        $acl.AddAccessRule($ace1)
        $acl.AddAccessRule($ace2)
        $acl.AddAccessRule($ace3)
        $acl.AddAccessRule($ace4)
        $acl.AddAccessRule($ace5)
        Set-ACL -ACLObject $acl -Path ("AD:\"+$ou)
        
        } 
        Catch {
            write-host "Caught an exception:" -ForegroundColor Red
            write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
        }        
}

#####################################
# Prevent normal users from adding machines to the domain by setting ms-DS-MachineAccountQuota to 0
#####################################

Add-Log -LogEntry ("Setting the ms-ds-MachineAccountQuota to 0")
Set-ADDomain $domainName -Replace @{"ms-ds-MachineAccountQuota"="0"}

#####################################
# Create Group
#####################################
Try {
        $Error.Clear()
        If($group=Get-ADGroup $groupname) {
            #write-host "The Group already exists" -Fore Yellow
            Add-Log -LogEntry ("The group already exists: " + $groupname)
        }
    } #already exists
    Catch 
    {
        If($Error[0].FullyQualifiedErrorID -eq "ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.GetADGroup")
        {
            If ($group=New-ADGroup -Name "Domain Join Users" -SamAccountName $groupname -GroupCategory Security -GroupScope DomainLocal -DisplayName "Domain-join Users" -Path $groups -Description "Members of this group can join computers to the domain" ) 
            {
                #write-host "The Group successfully created"-ForegroundColor Green
                Add-Log -LogEntry ("The group created: " + $groupname)
            }
         }
    }     

#####################################
# Create Service Account
#####################################
Try {
        $Error.Clear()
        If($user=Get-ADUser $username) {
            #write-host "The user already exists" -Fore Yellow
            Add-Log -LogEntry ("The user already exists: " + $username)
            }
    } #already exists
    Catch 
    {
        If($Error[0].FullyQualifiedErrorID -eq "ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.GetADUser")
        {
            If ($user=New-ADUser -SamAccountName "svc-domainjoin" -Name $username -Path $serviceAccounts -AccountPassword (Read-Host -AsSecureString "AccountPassword") -CannotChangePassword $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -Enabled $true -Description "Service Accounts with delegated permissions to join computers to the domain") 
            {
                #write-host "The User successfully created"-ForegroundColor Green
                Add-Log -LogEntry ("The account created: " + $username)
            }
         }
    }   

#####################################
# Add the User to the Group
#####################################
$group =Get-ADGroup $groupname
$user=Get-ADUser $username
Add-ADGroupMember $group -Members $user

#####################################
# Set Permissions on the OUs
#####################################
$groupsid = new-object System.Security.Principal.SecurityIdentifier $group.SID
#$ou = (Get-ADObject -LDAPFilter "(&(objectclass=organizationalUnit)(name=Server Staging))").DistinguishedName
#Set-DomainJoinPermissions $groupsid $ou
$ou = (Get-ADObject -LDAPFilter "(&(objectclass=organizationalUnit)(name=Admin Desktops))").DistinguishedName
Set-DomainJoinPermissions $groupsid $ou
$ou = (Get-ADObject -LDAPFilter "(&(objectclass=organizationalUnit)(name=Staging))").DistinguishedName
Set-DomainJoinPermissions $groupsid $ou