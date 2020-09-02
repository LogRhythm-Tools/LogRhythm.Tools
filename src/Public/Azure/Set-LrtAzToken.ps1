using namespace System

Function Set-LrtAzToken {
    <#
    .SYNOPSIS
        Sets an Azure Access Token for the current PowerShell scope.
    .DESCRIPTION
        The Set-LrtAzToken cmdlet will update the environment variable 
        $LrtConfig.[ResourceName].Token with a new access token if one
        is not already set. Resource name refers to one of DefenderATP
        or AzureAD.

        Tokens are not written to disk, and are only cached in memory
        for the current PowerShell application context.

        Users will not typically need to call this cmdlet, as each of
        LogRhythm.Tools Azure commands call it to ensure there
        is an active token available for requests.

        Set-LrtAzToken will not return an Azure token, so if you would
        like a new token to use for purposes outside of LogRhythm.Tools,
        e.g. curl, Ivoke-RestMethod, Postman - use [Get-LrtAzToken] instead.

        Azure OAuth2 Token Structure

        Property         Value (Example)
        -------------    -------------
        token_type       : Bearer
        expires_in       : 3599
        ext_expires_in   : 3599
        expires_on       : 1598894283
        not_before       : 1598890383
        resource         : https://graph.windows.net
        access_token     : <Token>
    .PARAMETER ResourceName
        The name of the resource for which to obtain a token. This can either
        be "AzureAD" or "DefenderATP", which are the two supported Azure
        resources in LogRhythm.Tools
    .INPUTS
        The Set-LrtAzToken cmdlet accepts the following values via Pipeline:
        [System.String]  -> ResourceName (by value)
    .OUTPUTS
        None
    .EXAMPLE
        PS C:\> Set-LrtAzToken -ResourceName DefenderATP

        Description
        -----------
        If successful, the environment variable $LrtConfig.DefenderATP.Token
        will be set with an access token.
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [ValidateSet('AzureAD','DefenderATP')]
        [string] $ResourceName
    )


    Begin {
        # For error/info reporting
        $Me = $MyInvocation.MyCommand.Name
    }


    Process {
        # Set our reference
        $CurrentToken = $LrtConfig.$ResourceName.Token


        # Check remaining token time if one is set
        if ($CurrentToken) {
            # Get Token time remaining and now, in UTC
            $Expires = (ConvertFrom-UnixEpoch -UnixTime $CurrentToken.expires_on)
            $Now = ([datetime]::Now).ToUniversalTime()
            $TimeRemaining = $Expires - $Now

            if ($TimeRemaining.Minutes -gt 5) {
                # enough time left on token, return
                Write-Verbose "[$Me]: $ResourceName token is still active, minutes remaining: $($TimeRemaining.Minutes)"
                return $null
            }
            Write-Verbose "[$Me]: $ResourceName token expired $($TimeRemaining.Minutes) minutes ago."
        }


        # Get / save token
        try {
            Write-Verbose "[$Me]: Getting new token for $ResourceName."
            $LrtConfig.$ResourceName.Token = Get-LrtAzToken -ResourceName $ResourceName
            Write-Verbose "Token set for $ResourceName."
        } catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }

    End { }
}