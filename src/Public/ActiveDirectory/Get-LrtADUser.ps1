using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Function Get-LrtADUser {
    <#
    .SYNOPSIS
        Encapsulation of Get-ADUser that will use the settings found in LogRhythm.Tools configuration
        for populating the <Server> and <Credential> parameters of that cmdlet.
    .DESCRIPTION
        The purpose of this cmdlet is to serve as an interface to the ActiveDirectory module version,
        Get-ADUser, which will enables the configuration stored in LogRhythm.Tools to provide the
        <sever> and <credential> parameters to the actual Get-ADUser cmdlet.
    .PARAMETER Identity
        
    .PARAMETER Server
        
    .PARAMETER Credential

    .INPUTS
        xxxx
    .OUTPUTS
        xxxx
    .EXAMPLE
        xxxx
    .EXAMPLE
        xxxx
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
        [string] $Server = $LrtConfig.ActiveDirectory.Server,


        [Parameter(Mandatory = $false, Position = 2)]
        [pscredential] $Credential = $LrtConfig.ActiveDirectory.Credential
    )


    Begin {
        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] ""
        }
    }


    Process {
        # strip off domain if present - e.g. abc\userbob
        $DomainCheck = $Identity -split "\\"
        if ($DomainCheck.Count -gt 1) {
            $Identity = $DomainCheck[1]
        }


        # Run the appropriate variation of Get-ADUser
        try {
            if ($Server) {
                if ($Credential) {
                    Write-Verbose "Get-ADUser <Server> <Credential>"
                    $User = Get-ADUser -Identity $Identity -Properties * -Server $Server -Credential $Credential
                    $type = $User.GetType()
                    Write-Host "Type: $type"
                } else {
                    Write-Verbose "Get-ADUser <Server>"
                    $User = Get-ADUser -Identity $Identity -Properties * -Server $Server
                }
            } else {
                if ($Credential) {
                    Write-Verbose "Get-ADUser <Credential>"
                    $User = Get-ADUser -Identity $Identity -Properties * -Credential $Credential
                } else {
                    Write-Verbose "Get-ADUser without extra options"
                    $User = Get-ADUser -Identity $Identity -Properties *
                }
            }
        } catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
        
        return $User
    }


    End { }
}