using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Function Get-LrtADUserInfo {
    <#
    .SYNOPSIS 
        Retrieves information about an Active Directory user object.
    .DESCRIPTION
        The Get-LrtADUserInfo cmdlet retrieves information about an Active Directory 
        user object, and calculates or looks up information that is commonly desired,
        such as determining if an account is a Service Account, and the number of days
        since the last password change.
    .PARAMETER Identity
        Specifies an Active Directory user in the form of a valid SamAccountName or ADUser.
    .INPUTS
        None - does not support pipeline.
    .OUTPUTS
        An object with the following fields is returned:
        - Name:             [string]    Common Name (CN)
        - SamAccountName:   [string]    Account Logon (7Letter)
        - Title             [string]    User Title
        - EmailAddress:     [string]    SMTP AddressGet
        - Exists:           [boolean]   User Exists
        - Enabled:          [boolean]   User is Enabled
        - LockedOut:        [boolean]   Account is Locked
        - PasswordExpired:  [boolean]   Password is Expired
        - PasswordAge:      [integer]   Days since Password Changed
        - Manager:          [ADUser]    User's manager
        - OrgUnits:         [List]      OU Hierarchy
        - ADUser:           [ADUser]    Full ADUser Object
        - Groups:           [List]      ADGroups this user belongs to
        - Exceptions:       [List]      List of System.Exceptions raised during the
                                        execution of this command.
    .EXAMPLE
        $UserInfo = Get-LrtADUserInfo -Identity bjones
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
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
        [ADUser] $Identity
    )


    Begin {
        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
        }

        $Me = $MyInvocation.MyCommand.Name


        # Determine which parameters to pass to AD cmdlets - Server, Credential, both, or neither.
        $Options = ""
        if ($LrtConfig.ActiveDirectory.Credential) {
            if ($LrtConfig.ActiveDirectory.Server) {
                $Options = "Server+Credential"
            } else {
                $Options = "Credential"
            }
        } else {
            if ($LrtConfig.ActiveDirectory.Server) {
                $Options = "Server"
            }
        }
        Write-Verbose "AD Options: $Options"
    }



    Process {
        # strip off domain if present - e.g. abc\userbob
        $DomainCheck = $Identity -split "\\"
        if ($DomainCheck.Count -gt 1) {
            $Identity = $DomainCheck[1]
        }


        #region: User Object Structure                                                             
        # User Result Object
        $UserInfo = [PSCustomObject]@{
            Name            = $Identity
            SamAccountName  = ""
            Title           = ""
            EmailAddress    = ""
            Exists          = $false
            Enabled         = $false
            LockedOut       = $false
            PasswordExpired = $false
            PasswordAge     = 0
            Manager         = $null
            OrgUnits        = [List[string]]::new()
            ADUser          = $null
            Groups          = $null
            Exceptions      = [List[Exception]]::new()
        }
        #endregion



        #region: Lookup User Info                                                                         
        switch ($Options) {
            "Server+Credential" {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties * `
                        -Server $LrtConfig.ActiveDirectory.Server `
                        -Credential $LrtConfig.ActiveDirectory.Credential `
                        -ErrorAction Stop
                } catch {
                    Write-Warning "[$Me] User Lookup: $($PSItem.Exception.Message)"
                    $UserInfo.Exceptions.Add($PSItem.Exception)
                }
            }

            "Credential" {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties * `
                        -Credential $LrtConfig.ActiveDirectory.Credential `
                        -ErrorAction Stop    
                } catch {
                    Write-Warning "[$Me] User Lookup: $($PSItem.Exception.Message)"
                    $UserInfo.Exceptions.Add($PSItem.Exception)
                }
                
            }

            "Server" {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties * `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -ErrorAction Stop    
                }
                catch {
                    Write-Warning "[$Me] User Lookup: $($PSItem.Exception.Message)"
                    $UserInfo.Exceptions.Add($PSItem.Exception)
                }
                
            }

            Default {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties * -ErrorAction Stop    
                }
                catch {
                    Write-Warning "[$Me] User Lookup: $($PSItem.Exception.Message)"
                    $UserInfo.Exceptions.Add($PSItem.Exception)
                }
                
            }
        }
        #endregion


        #region: Set Basic User Info                                                               
        if ($ADUser) {
            # Basic Properties
            $UserInfo.Name = $ADUser.Name
            $UserInfo.SamAccountName = $ADUser.SamAccountName
            $UserInfo.Title = $ADUser.Title
            $UserInfo.EmailAddress = $ADUser.EmailAddress
            $UserInfo.Exists = $true
            $UserInfo.Enabled = $ADUser.Enabled
            $UserInfo.LockedOut = $ADUser.LockedOut
            $UserInfo.PasswordExpired = $ADUser.PasswordExpired
            $UserInfo.ADUser = $ADUser
    
            # Password Age - sometimes PasswordLastSet is null
            if ($ADUser.PasswordLastSet -is [datetime]) {
                $UserInfo.PasswordAge = (New-TimeSpan -Start $ADUser.PasswordLastSet -End (Get-Date)).Days    
            } else {
                $UserInfo.PasswordAge = $ADUser.PasswordLastSet
            }
        }
        #endregion



        #region: Lookup Manager Info                                                                      
        if ($ADUser.Manager) {
            try {
                switch ($Options) {
                    "Server+Credential" {
                        $UserInfo.Manager = Get-ADUser -Identity $ADUser.Manager `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential `
                            -ErrorAction Stop
                    }
                    "Credential" {
                        $UserInfo.Manager = Get-ADUser -Identity $ADUser.Manager `
                            -Credential $LrtConfig.ActiveDirectory.Credential `
                            -ErrorAction Stop
                    }
                    "Server" {
                        $UserInfo.Manager = Get-ADUser -Identity $ADUser.Manager `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -ErrorAction Stop
                    }
                    Default {
                        $UserInfo.Manager = Get-ADUser -Identity $ADUser.Manager -ErrorAction Stop
                    }
                }
            }
            catch {
                Write-Warning "[$Me] Manager Lookup: $($PSItem.Exception.Message)"
                $UserInfo.Exceptions.Add($PSItem.Exception)
                # if something goes wrong we will just plug in the default manager field into the result
                # instead of the manager's name.
                $UserInfo.Manager = $ADUser.Manager
            }
        }     
        #endregion


        
        #region: Lookup Groups                                                                            
        # Run the appropriate version of Get-ADGroup
        if ($ADUser.MemberOf) {
            try {
                switch ($Options) {
                    "Server+Credential" {
                        $UserInfo.Groups = $ADUser.MemberOf | Get-ADGroup `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential `
                            -ErrorAction Stop
                    }
                    "Credential" {
                        $UserInfo.Groups = $ADUser.MemberOf | Get-ADGroup `
                            -Credential $LrtConfig.ActiveDirectory.Credential `
                            -ErrorAction Stop
                    }
                    "Server" {
                        $UserInfo.Groups = $ADUser.MemberOf | Get-ADGroup `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -ErrorAction Stop
                    }
                    Default {
                        $UserInfo.Groups = $ADUser.MemberOf | Get-ADGroup -ErrorAction Stop
                    }
                }
            }
            catch {
                Write-Warning "[$Me] Group Lookup: $($PSItem.Exception.Message)"
                $UserInfo.Exceptions.Add($PSItem.Exception)
            }
        }
        #endregion



        #region: Org Unit Info                                                                     
        $DN = ($ADUser.DistinguishedName) -split ','
        foreach ($value in $DN) {
            if ($value -match $OUPattern) {
                $UserInfo.OrgUnits.Add(($value -split '=')[1])
            }
        }
        #endregion


        return $UserInfo
    }



    End { }

}