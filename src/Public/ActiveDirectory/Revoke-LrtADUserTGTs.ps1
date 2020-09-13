using namespace System
using namespace System.Management.Automation
using namespace Microsoft.ActiveDirectory.Management

Function Revoke-LrtADUserTGTs {
    <#
    .SYNOPSIS
        Change a user account password twice in a row in order to expire all existing 
        ticket-granting tickets in the domain (as determined by the value of 
        $LrtConfig.ActiveDirectory.Server).  This process is recommended if an ActiveDirectory
        user account is suspected of being compromised.
    .DESCRIPTION
        The Revoke-LrtADUserTGTs cmdlet changes the account password of the specified AD User
        twice in order to invalidate the current user credential stolen credentials as well as to
        invalidate any existing TGTs based on the n-1 password.
    
        WARNING: Be cautious when running this command against any critical service principals.

        There is a small wait time of six seconds between password changes to be
        conservative and give the first change time to be processed by a DC, but the command
        will not wait for full replication to complete before the second password change.
        
        Using the Revoke-LrtADUserTGTs cmdlet on a service principal responsible for running a
        critical service may cause service disriptions until both changes fully replicate across
        the domain.

        For users this may cause multiple re-authentication prompts until changes fully replicate
        across a domain.
    .PARAMETER Identity
        Specifies an Active Directory user in the form of a valid SamAccountName or ADUser.
    .PARAMETER PassThru
        Returns the new or modified object. By default (i.e. if -PassThru is not specified), this cmdlet
        does not generate any output.
    .INPUTS
        [ADUser] => Identity
    .OUTPUTS
        If PassThru option is specified, an [ADUser] object for the impacted Identity is returned.
    .EXAMPLE
        PS C:\> DSet-LrtADUserRandomPassword -Identity "bobjones"
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
        [ADUser] $Identity,


        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $PassThru
    )



    Begin {
        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
        }
    }


    Process {
        # Get username for Identity
        if (! $Identity.SamAccountName) {
            $AccountName = $Identity
        } else {
            $AccountName = $Identity.SamAccountName
        }


        # Create two random passwords to use for the password changes.
        $_pass1 =  ConvertTo-SecureString -AsPlainText -Force `
            -String ([Web.Security.Membership]::GeneratePassword(20,1))
        $_pass2 =  ConvertTo-SecureString -AsPlainText -Force `
            -String ([Web.Security.Membership]::GeneratePassword(20,1))


        
        # Run version of command based on ActiveDirectory options
        switch ($LrtConfig.ActiveDirectory.Options) {

            "Server+Credential" {
                Write-Verbose "First password change for $AccountName (Server+Credential)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass1 `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -Credential $LrtConfig.ActiveDirectory.Credential `
                    -Reset -PassThru -ErrorAction Stop | 
                        Set-ADuser -ChangePasswordAtLogon $true `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential
                
                # Small wait between changes
                Write-Verbose "Sleep: 6 seconds (Server+Credential)"
                Start-Sleep -Seconds 6

                # DoubleTap - Server+Credential
                Write-Verbose "Second password change for $AccountName (Server+Credential)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass2 `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -Credential $LrtConfig.ActiveDirectory.Credential `
                    -Reset -PassThru -ErrorAction Stop | 
                        Set-ADuser -ChangePasswordAtLogon $true `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential
            }

            "Credential" {
                Write-Verbose "First password change for $AccountName (Credential)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass1 `
                    -Credential $LrtConfig.ActiveDirectory.Credential `
                    -Reset -PassThru -ErrorAction Stop | 
                        Set-ADuser -ChangePasswordAtLogon $true `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential
                            
                # Small wait between changes
                Write-Verbose "Sleep: 6 seconds (Credential)"
                Start-Sleep -Seconds 6

                # DoubleTap - Credential
                Write-Verbose "Second password change for $AccountName (Credential)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass2 `
                    -Credential $LrtConfig.ActiveDirectory.Credential `
                    -Reset -PassThru -ErrorAction Stop | 
                        Set-ADuser -ChangePasswordAtLogon $true `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential
            }

            "Server" {
                Write-Verbose "First password change for $AccountName (Server)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass1 `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -Reset -PassThru -ErrorAction Stop | 
                        Set-ADuser -ChangePasswordAtLogon $true `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential
                
                # Small wait between changes
                Write-Verbose "Sleep: 6 seconds (Server)"
                Start-Sleep -Seconds 6

                # DoubleTap - Server
                Write-Verbose "Second password change for $AccountName (Server)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass2 `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -Reset -PassThru -ErrorAction Stop | 
                        Set-ADuser -ChangePasswordAtLogon $true `
                            -Server $LrtConfig.ActiveDirectory.Server `
                            -Credential $LrtConfig.ActiveDirectory.Credential
            }

            Default {
                Write-Verbose "First password change for $AccountName (Default)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass1 -Reset -PassThru -ErrorAction Stop | 
                    Set-ADuser -ChangePasswordAtLogon $true
                
                # Small wait between changes
                Write-Verbose "Sleep: 6 seconds (Default)"
                Start-Sleep -Seconds 6

                # DoubleTap - Default
                Write-Verbose "Second password change for $AccountName (Default)"
                Set-ADAccountPassword -Identity $Identity -NewPassword $_pass2 -Reset -PassThru -ErrorAction Stop | 
                    Set-ADuser -ChangePasswordAtLogon $true
            }
        }


        # Implement PassThru
        # We could passthru at the Set-ADUser above, but that would require another set of checks to see if its desired...
        if ($PassThru) {
            return Get-LrtADUser -Identity $Identity
        }
    }

    End {

    }


}