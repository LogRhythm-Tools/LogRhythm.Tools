using namespace System

Function Set-LrtExaToken {
    <#
    .SYNOPSIS
        Sets an Exabeam Access Token for the current PowerShell scope.
    .DESCRIPTION
        The Set-LrtAzToken cmdlet will update the environment variable 
        $LrtConfig.[ResourceName].Token with a new access token if one
        is not already set. 

        Tokens are not written to disk, and are only cached in memory
        for the current PowerShell application context.
    .OUTPUTS
        None
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
    )


    Begin {
        # For error/info reporting
        $Me = $MyInvocation.MyCommand.Name
        # Set our reference
        $CurrentToken = $LrtConfig.Exabeam.Token
    }


    Process {
        # Check remaining token time if one is set
        if ($CurrentToken) {
            # Get Token time remaining and now, in UTC
            if ($(Get-Date) -lt $LrtConfig.Exabeam.Token.expires_on) {
                Write-Verbose "[$Me]: New token not required."
                return
            }
        }

        # Get / save token
        try {
            Write-Verbose "[$Me]: Getting new token for Exabeam."
            $LrtConfig.Exabeam.Token = Get-LrtExaToken
        } catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }

    End { }
}