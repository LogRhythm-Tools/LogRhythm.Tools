using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Function Get-LrtADUser {
    <#
    .SYNOPSIS
        Encapsulation of Get-ADUser that will use the settings found in LogRhythm.Tools configuration
        for populating the <Server> and <Credential> parameters of that cmdlet.

        For more information, run:
        > Get-Help Get-ADUser
    .DESCRIPTION
        The purpose of this cmdlet is to serve as a SIMPLE interface to the standard ActiveDirectory module
        command Get-ADUser, and is not intended to replace it or any other ActiveDirectory module commands.

        This cmdlet merely runs Get-ADUser and automatically supplies the values for <Credential> and <Server>
        with the corresponding values found in LrtConfig.
    .PARAMETER Identity
        Specifies an Active Directory user object by providing one of the following values. The
        identifier in parentheses is the LDAP display name for the attribute.
            Distinguished Name
            GUID
            Security Identifier (objectSid)
            Security Accounts Manager (SAM) Account Name (sAMAccountName)        
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
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
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
                    Write-Verbose "Get-ADUser Options: +Credential +Server"
                    $User = Get-ADUser -Identity $Identity -Properties * -Server $Server -Credential $Credential
                } else {
                    Write-Verbose "Get-ADUser Options: +Server"
                    $User = Get-ADUser -Identity $Identity -Properties * -Server $Server
                }
            } else {
                if ($Credential) {
                    Write-Verbose "Get-ADUser Options: +Credential"
                    $User = Get-ADUser -Identity $Identity -Properties * -Credential $Credential
                } else {
                    Write-Verbose "Get-ADUser Options: None"
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