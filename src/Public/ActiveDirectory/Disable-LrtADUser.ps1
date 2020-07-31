using namespace System
using namespace System.Management.Automation
using namespace Microsoft.ActiveDirectory.Management

Function Disable-LrtADUser {
    <#
    .SYNOPSIS
        Disable an Active Directory user account.
    .PARAMETER Identity
        AD User Account to disable
    .PARAMETER Credential
        [pscredential] Credentials to use for local auth.
        Default: Current User
    .EXAMPLE
        Disable-LrtADUser -Identity testuser -Credential (Get-Credential)
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
        $Me = $MyInvocation.MyCommand.Name

        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
        }


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
    }


    Process {

        # Validate user account
        $UserInfo = Get-LrtADUserInfo -Identity $Identity
        if (! $UserInfo.Exists) {
            Write-Verbose "Could not find user [$Identity]."
            throw [ADIdentityNotFoundException] "[$Me]: Cannot find an object with identity '$($UserInfo.Name)'"
        }

        # If already disabled, return true
        if (! $UserInfo.Enabled) {
            Write-Verbose "[$Me]: $($UserInfo.Name) is already disabled."
            return $true
        }

        
        # Disable Account
        try {
            switch ($Options) {
                "Server+Credential" {
                    Write-Verbose "Get-ADUser Options: +Credential +Server"
                    $UserInfo.ADUser | Disable-ADAccount `
                        -Server $LrtConfig.ActiveDirectory.Server `
                        -Credential $LrtConfig.ActiveDirectory.Credential
                        
                }
                "Credential" {
                    Write-Verbose "Get-ADUser Options: +Credential"
                    $UserInfo.ADUser | Disable-ADAccount `
                        -Credential $LrtConfig.ActiveDirectory.Credential
                }
                "Server" {
                    Write-Verbose "Get-ADUser Options: +Server"
                    $UserInfo.ADUser | Disable-ADAccount `
                        -Server $LrtConfig.ActiveDirectory.Server
                }
                Default {
                    Write-Verbose "Get-ADUser Options: None"
                    $UserInfo.ADUser | Disable-ADAccount
                }
            }            
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }


        # Check account to ensure it is disabled
        $UserInfo = Get-LrtADUserInfo -Identity $Identity
        if (! $UserInfo.Enabled) {
            Write-Verbose "[$Me]: Successfully disabled '$($UserInfo.Name)'"
            return $true
        } else {
            Write-Verbose "[$Me]: Failed to disable object '$($UserInfo.Name)'"
            return $false
        }
    }

    End {

    }


}