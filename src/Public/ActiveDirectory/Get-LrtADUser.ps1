using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Function Get-LrtADUser {
    <#
    .SYNOPSIS 
        Invokes the ActiveDirectory module command Get-ADUser for LrtAD cmdlets.
    .DESCRIPTION
        The purpose of the Get-LrtADUser command is to serve as a simple wrapper to manage
        handling the Server and Credential parameters required by ActiveDirectory module commands.
        
        If the local computer is joined to a domain and the caller of this command can be 
        authenticated, AD commands will be executed without special parameters.
        
        To point Lrt to a different domain or use an alternative credential (such as for privileged actions), 
        provide values for the $LrtConfig.ActiveDirectory.Server and Credential properties.
        This can also easily configured by running the Lrt Setup.ps1 script again.
    .PARAMETER Identity
        Specifies an Active Directory user in the form of a valid SamAccountName or ADUser.
    .INPUTS
        [ADUser] => Identity
    .OUTPUTS
        The [ADUser] object returned from Get-ADUser
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
        [ADUser] $Identity,


        [Parameter(Mandatory = $false, Position = 1)]
        [string[]] $Properties
    )


    Begin {
        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
        }

        $Me = $MyInvocation.MyCommand.Name


        # If no Properties are set, build out the default properties.
        # We do this to avoid needing to run two versions of the command
        # for each of the below scenarios (one with a Properties parameter and one without)
        if (! $Properties) {
            $Properties = @('DistinguishedName','Enabled','GivenName','Name','ObjectClass',
                'ObjectGUID','SamAccountName','SID','Surname','UserPrincipalName')
        }
    }



    Process {
        # strip off domain if present - e.g. abc\userbob
        $DomainCheck = $Identity -split "\\"
        if ($DomainCheck.Count -gt 1) {
            $Identity = $DomainCheck[1]
        }


        #region: Lookup User Info                                                                         
        switch ($LrtConfig.ActiveDirectory.Options) {
            "Server+Credential" {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties $Properties `
                        -Server $LrtConfig.ActiveDirectory.Server `
                        -Credential $LrtConfig.ActiveDirectory.Credential `
                        -ErrorAction Stop
                } catch {
                    $PSCmdlet.ThrowTerminatingError($PSItem)
                }
            }

            "Credential" {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties $Properties `
                        -Credential $LrtConfig.ActiveDirectory.Credential `
                        -ErrorAction Stop    
                } catch {
                    $PSCmdlet.ThrowTerminatingError($PSItem)
                }
                
            }

            "Server" {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties $Properties `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -ErrorAction Stop    
                }
                catch {
                    $PSCmdlet.ThrowTerminatingError($PSItem)
                }
                
            }

            Default {
                try {
                    $ADUser = Get-ADUser -Identity $Identity -Properties $Properties -ErrorAction Stop
                }
                catch {
                    $PSCmdlet.ThrowTerminatingError($PSItem)
                }
                
            }
        }
        #endregion


        return $ADUser
    }



    End { }

}