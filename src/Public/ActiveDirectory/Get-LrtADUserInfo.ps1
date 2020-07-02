using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

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
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
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


        # User Result Object
        $Result = [PSCustomObject]@{
            Name            = $Identity
            SamAccountName  = ""
            Title           = ""
            EmailAddress    = $EmailAddress
            Exists          = $false
            Message         = ""
            Enabled         = $false
            LockedOut       = $false
            PasswordExpired = $false
            PasswordAge     = 9999
            Manager         = ""
            OrgUnits        = [List[string]]::new()
            ADUser          = $null
            Owner           = $null
            Groups          = [List[string]]::new()
        }


        # Try to get [ADUser] from Get-LrtADUser cmdlet, which will use Server/Credential as needed
        try {
            $User = Get-LrtADUser -Identity $Identity -Server $Server -Credential $Credential
            $Result.ADUser = $User
        } catch {
            $Result.Message = $PSItem.Exception.Message
            return $Result
        }


        # Basic Properties
        $Result.Name = $User.Name
        $Result.SamAccountName = $User.SamAccountName
        $Result.Title = $User.Title
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
            try {
                $Result.Manager = Get-LrtADUserInfo -Identity $User.Manager -Server $Server -Credential $Credential
            }
            catch {
                # if something goes wrong we will just plug in the default manager field
                # into the result instead of the manager's name.
                $err = $PSItem.Exception.Message
                Write-Warning "Manager lookup for [$($Result.Name)]: $err"
                $Result.Manager = $User.Manager
            }
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