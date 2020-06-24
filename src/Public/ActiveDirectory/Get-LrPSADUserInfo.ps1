using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Get-Module ActiveDirectory | Remove-Module
#Requires -Modules ActiveDirectory
Function Get-LrPSADUserInfo {
    <#
    .SYNOPSIS 
        Retrieves information about and Active Directory user object.
    .DESCRIPTION
        The Get-LrPSADUserInfo cmdlet retrieves information about an Active Directory 
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
        $UserInfo = Get-LrPSADUserInfo -Identity bjones
    .EXAMPLE
        PS C:\> if((Get-LrPSADUserInfo bjones).HasManager) { "Has a manager." }
        ---
        Determine if a the account has a manager.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string] $Identity
    )


    Begin {
        $ThisFunction = $MyInvocation.MyCommand
        $Verbose = $false
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            $Verbose = $true
        }
    }



    Process {
        # strip off domain if present - e.g. abc\userbob
        $DomainCheck = $Identity -split "\\"
        if ($DomainCheck.Count -gt 1) {
            $Identity = $DomainCheck[1]
        }

        $SvcPattern = "[sS][vV][cC].*?"
        $OUPattern = "[oO][uU]=.*?"
        $AdminPattern = "^.*?([aA][dD][mM][iI][nN]).*?$"
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
            Enabled = $false
            LockedOut = $false
            PasswordExpired = $false
            PasswordAge = 9999
            HasManager = $false
            ManagerName = ""
            ManagerEmail = ""
            IsSvcAccount = $false
            IsAdminAccount = $false
            OrgUnits = $OrgUnits
            ADUser = $null
            Owner = $null
        }

        # If user doesn't exist, return the default non-existing account object
        try {
            $User = Get-ADUser -Identity $Identity -Properties * -ErrorAction Stop
        }
        catch [ADIdentityNotFoundException] {
            Write-Verbose "[$ThisFunction]: $Identity not found in Active Directory."
            return $Result
        }
        catch {
            Write-Verbose "[$ThisFunction]: Encountered unexpected error while running Get-ADUser."
            return $Result
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
            Write-Verbose "Manager: $($User.Manager)"
            $Result.HasManager = $true

            $Manager = Get-ADUser -Identity $User.Manager -Properties *
            $Result.ManagerName = $Manager.Name
            $Result.ManagerEmail = $Manager.EmailAddress
        }
        
        # Org Units
        $DN = ($User.DistinguishedName) -split ','
        foreach ($value in $DN) {
            if ($value -match $OUPattern) {
                $Result.OrgUnits.Add(($value -split '=')[1])
            }
        }

        # IsSvcAccount - if in a Service Account OU or matches "Svc" pattern
        if ($Result.OrgUnits.Contains("Service Accounts")) {
            $Result.IsSvcAccount = $true
        } else {
            $Result.IsSvcAccount = $User.SamAccountName -match $SvcPattern
        }

        # IsAdminAccount - if in one of the groups below
        if ($Result.OrgUnits.Contains("Administrators")) {
            $Result.IsAdminAccount = $true
            if ($Result.SamAccountName -match $AdminPattern) {
                $LookFor = ($Result.SamAccountName).Substring(0, $Result.SamAccountName.Length-2)
                try {
                    $Result.Owner = Get-ADUser -Identity $LookFor -Properties * -ErrorAction Stop
                }
                catch {
                    Write-Verbose "[$ThisFunction]: $($Result.SamAccountName) is in the Administrators OU."
                    Write-Verbose "[$ThisFunction]: Failed to find a non-privileged account (tried $LookFor)."
                }
            }
        }

        return $Result
    }



    End { }

}