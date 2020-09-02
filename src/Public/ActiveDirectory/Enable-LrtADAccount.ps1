using namespace System
using namespace System.Management.Automation
using namespace Microsoft.ActiveDirectory.Management

Function Enable-LrtADAccount {
    <#
    .SYNOPSIS
        Invokes the ActiveDirectory module command Enable-ADAccount for LrtAD cmdlets.
    .DESCRIPTION
        The purpose of the Enable-LrtADAccount command is to serve as a simple wrapper to manage
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
        If PassThru option is specified, an [ADUser] object for the impacted Identity is returned.
    .EXAMPLE
        PS C:\> Enable-LrtADAccount -Identity "bobjones"
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
        $Me = $MyInvocation.MyCommand.Name

        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
        }
    }


    Process {
        # Disable Account
        switch ($LrtConfig.ActiveDirectory.Options) {
            "Server+Credential" {
                Enable-ADAccount -Identity $Identity `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -Credential $LrtConfig.ActiveDirectory.Credential `
                    -ErrorAction Stop
            }
            "Credential" {
                Enable-ADAccount -Identity $Identity `
                    -Credential $LrtConfig.ActiveDirectory.Credential `
                    -ErrorAction Stop
            }
            "Server" {
                Enable-ADAccount -Identity $Identity `
                    -Server $LrtConfig.ActiveDirectory.Server `
                    -ErrorAction Stop
            }
            Default {
                Enable-ADAccount -Identity $Identity -ErrorAction Stop
            }
        }            


        # Implement PassThru
        if ($PassThru) {
            return Get-LrtADUser -Identity $Identity
        }
    }

    End {

    }


}