using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management


Get-Module ActiveDirectory | Remove-Module
#Requires -Modules ActiveDirectory
Function Get-LrtADUserInfo {
    <#
    .SYNOPSIS 
        Retrieves information about and Active Directory user object.
    .DESCRIPTION
        The Get-LrtADUserInfo cmdlet retrieves information about an Active Directory 
        user object, and calculates or looks up information that is commonly desired,
        such as determining if an account is a Service Account, and the number of days
        since the last password change.
    .PARAMETER Identity
        Specifies an Active Directory user in the form of a valid SamAccountName.
    .INPUTS
        None - does not support pipeline.
    .OUTPUTS
        An object with the following fields is returned:
        - Name:             [string]    Common Name (CN)
        - SamAccountName:   [string]    Account Logon (7Letter)
        - EmailAddress:     [string]    SMTP AddressGet
        - Exists:           [boolean]   User Exists
        - Enabled:          [boolean]   User is Enabled
        - LockedOut:        [boolean]   Account is Locked
        - PasswordExpired:  [boolean]   Password is Expired
        - PasswordAge:      [integer]   Days since Password Changed
        - HasManager:       [boolean]   Manager is Assigned
        - ManagerName:      [boolean]   Manager Common Name
        - ManagerEmail:     [string]    Manager SMTP Address
        - IsSvcAccount:     [boolean]   Name like Svc* or in ServiceAccount OU
        - IsAdminAccount:   [boolean]   In "Administrators" OU, such as "SD,PA,DA" accounts.
        - OrgUnits:         [List]      OU Hierarchy
        - ADUser:           [ADUser]    Full ADUser Object
    .EXAMPLE
        $UserInfo = Get-LrtADUserInfo -Identity bjones
    .EXAMPLE
        PS C:\> if((Get-LrtADUserInfo bjones).HasManager) { "Has a manager." }
        ---
        Determine if a the account has a manager.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [ADUser] $Identity,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Server = $LrtConfig.ActiveDirectory.Server,


        [Parameter(Mandatory = $false, Position = 2)]
        [pscredential] $Credential = $LrtConfig.ActiveDirectory.Credential
    )


    Begin {
        # Import Module ActiveDirectory
        Import-LrtADModule
    }



    Process {
        # strip off domain if present - e.g. abc\userbob
        $DomainCheck = $Identity -split "\\"
        if ($DomainCheck.Count -gt 1) {
            $Identity = $DomainCheck[1]
        }

        # Setup a result object
        $OrgUnits = [List[string]]::new()

        # Result Object
        $Result = [PSCustomObject]@{
            Name = $Identity
            SamAccountName = ""
            Title = ""
            Team = ""
            EmailAddress = $EmailAddress
            Exists = $false
            Message = ""
            Enabled = $false
            LockedOut = $false
            PasswordExpired = $false
            PasswordAge = 9999
            Manager = ""
            OrgUnits = $OrgUnits
            ADUser = $null
            Owner = $null
        }

        # If user doesn't exist, return the default non-existing account object
        try {
            $User = Get-ADUser -Identity $Identity -Properties * -ErrorAction Stop
        } catch {
            $Result.Message = $PSItem.Exception.Message
        }

        # Include the ADUser object in the result
        $Result.ADUser = $User

        # Basic Properties
        $Result.Name = $User.Name
        $Result.SamAccountName = $User.SamAccountName
        $Result.Title = $User.Title
        $Result.Team = $User.extensionAttribute8
        $Result.EmailAddress = $User.EmailAddress
        $Result.Exists = $true
        $Result.Enabled = $User.Enabled
        $Result.LockedOut = $User.LockedOut
        $Result.PasswordExpired = $User.PasswordExpired

        # Password Age - sometimes PasswordLastSet is null
        if ($User.PasswordLastSet -is [datetime]) {
            $Result.PasswordAge = (New-TimeSpan -Start $User.PasswordLastSet -End (Get-Date)).Days    
        } else {
            $Result.PasswordAge = $User.PasswordLastSet
        }

        # Manager
        if ($User.Manager) {
            $Result.Manager = Get-LrtADUserInfo -Identity $User.Manager
        }
        
        # Org Units
        $DN = ($User.DistinguishedName) -split ','
        foreach ($value in $DN) {
            if ($value -match $OUPattern) {
                $Result.OrgUnits.Add(($value -split '=')[1])
            }
        }
        return $Result
    }



    End { }

}