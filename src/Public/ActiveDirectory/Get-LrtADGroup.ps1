using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Function Get-LrtADGroup {
    <#
    .SYNOPSIS 
        Invokes the ActiveDirectory module command Get-ADGroup for LrtAD cmdlets.
    .DESCRIPTION
        The purpose of the Get-LrtADUser command is to serve as a simple wrapper for the 
        ActiveDirectory module's Get-ADGroup command. The purpose of this is to
        enable the use of $LrtConfig to determine which domain to query and which
        credential to use, without needing to be joined to the domain.
    .PARAMETER Identity
        Specifies an Active Directory user in the form of a valid SamAccountName or ADUser.
    .INPUTS
        [ADUser] => Identity
    .OUTPUTS
        The [ADUser] object returned from Get-ADGroup
    .EXAMPLE
        PS C:\> Get-LrtADUser -Identity "bobjones"
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
        [ADGroup[]] $Identity
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

        try {
            switch ($Options) {
                "Server+Credential" {
                    $Group = $Identity | Get-ADGroup `
                        -Server $LrtConfig.ActiveDirectory.Server `
                        -Credential $LrtConfig.ActiveDirectory.Credential `
                        -ErrorAction Stop
                }
                "Credential" {
                    $Group = $Identity | Get-ADGroup `
                        -Credential $LrtConfig.ActiveDirectory.Credential `
                        -ErrorAction Stop
                }
                "Server" {
                    $Group = $Identity | Get-ADGroup `
                        -Server $LrtConfig.ActiveDirectory.Server `
                        -ErrorAction Stop
                }
                Default {
                    $Group = $Identity | Get-ADGroup -ErrorAction Stop
                }
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }

        return $Group
    }



    End { }

}