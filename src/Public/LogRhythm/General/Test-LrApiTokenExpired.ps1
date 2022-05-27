using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrApiTokenExpired {
    <#
    .SYNOPSIS
        Test the LR API Token for validity
    .DESCRIPTION
        The LogRhythm API Token is a JWT consisting of several parts.

        By default this function will test whether the token is within it's expiry time.

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER WarningInterval
        Number of days before expiry at which to generate a warning.

        Default: 30 days
    .PARAMETER XXXX
        xxxxxx
    .INPUTS
        Type -> Parameter
    .OUTPUTS
        PSCustomObject representing the (new|modified) LogRhythm object.
    .EXAMPLE
        PS C:\>
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(
            Mandatory = $false
        )]
        [int] $WarningInterval = 30
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        Write-Verbose "Invoking $($Me)"

        $TokenInfo = Get-LrApiTokenInfo -Credential $Credential
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $_
        }

        $OutObject = [PSCustomObject]@{
            IsExpired = $false
            IsWarning = $false
            Expires = $TokenInfo.Expires
        }

        # Test Expiry Date of Token
        try {
            if ($TokenInfo.Expiry -le (Get-Date).Date){
                # Token is expired
                Write-Error "Token is expired: $($TokenInfo.Expires)"
                $OutObject.IsExpired = $true
                $OutObject.IsWarning = $true
            }
            elseif ($TokenInfo.Expiry -le (Get-Date).AddDays($WarningInterval).Date) {
                # Token Expiry is within WarningInterval Days
                Write-Warning "Token expires in less than $($WarningInterval) Days. Token Expiry: $($TokenInfo.Expires)"
                $OutObject.IsWarning = $true
            }
        }
        catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "Exception"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Raw = $_
            $ErrorObject.Error = $true
            return $ErrorObject
        }

        return $OutObject
    }


    End { }
}