using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrApiTokenInfo {
    <#
    .SYNOPSIS
        Returns Information about the LR API Token
    .DESCRIPTION
        The LogRhythm API Token is a JWT consisting of several parts. The first two parts are Base64 encoded values that provide information about the token.
        
        The first part describes the type of token. The second part contains various information fields:

        - uid - [int] UserID to which the token was issued
        - jti - [uuid] JSON Token Identifier
        - cid - [uuid] App Connection ID
        - iss - [string] Issuing Service, should be lr-auth
        - rid - [string] Role ID, one of globalAdmin, globalAnalyst, restrictedAdmin, restrictedAnalyst
        - pid - [int] PersonID to which the token was issued
        - sub - [string] Subject (User ID) to which the token was issued
        - exp - [int64] Token Expiry in Unix Epoch
        - deid - [int] Default Entity ID
        - eids - [array][int] Visible Entity IDs
        - iat - [int64] Token Issued At in Unix Epoch

        The third and last part contains the token signature.

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        PSCustomObject -> Credential
    .OUTPUTS
        PSCustomObject representing the API Token Information.
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
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        Write-Verbose "Invoking $($Me)"
    
        $Token = $Credential.GetNetworkCredential().Password
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

        # REQUEST
        try {
            # Part [1] contains the token information, but needs padding for Base64 Decode to work
            $LrTokenInfoPart = $Token.Split('.')[1]
            $PaddedLrTokenInfoPart = $LrTokenInfoPart.PadRight(([math]::ceiling($LrTokenInfoPart.length / 4) * 4), '=')

            # Convert from Base64 and turn into a PSCustomObject/Hash
            $LrTokenInfo = ConvertFrom-Base64 -Encoding UTF8 -String $PaddedLrTokenInfoPart | ConvertFrom-Json

            # Get the bits we actually care about
            $OutObject = [PSCustomObject]@{
                UserId = $LrTokenInfo.uid
                PersonId = $LrTokenInfo.pid
                DefaultEntityId = $LrTokenInfo.deid
                RoleId = $LrTokenInfo.rid
                Subject = $LrTokenInfo.sub
                Entity = $LrTokenInfo.eids
                TokenId = $LrTokenInfo.jti
                AppConnectionId = $LrTokenInfo.cid
                Issued = ($LrTokenInfo.iat | ConvertFrom-UnixEpoch)
                Expires = ($LrTokenInfo.exp | ConvertFrom-UnixEpoch)
            }
        }
        catch {
            $ErrorObject.Type = "Exception"
            $ErrorObject.Note = "Unable to convert JWT to API User Info."
            $ErrorObject.Raw = $_
            $ErrorObject.Error = $true
            return $ErrorObject
        }

        return $OutObject
    }


    End { }
}