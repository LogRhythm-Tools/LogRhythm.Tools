using namespace System
using namespace System.Net
using namespace System.Collections.Generic
using namespace System.Web

Function Get-LrtExaToken {
    <#
    .SYNOPSIS
        Get an access token to access Exabeam API resources.
        
    .DESCRIPTION
        Retrieves an access token from Exabeam by authenticating with provided client ID and secret. 
        The token is essential for making authenticated requests to Exabeam's APIs. This function uses the OAuth 2.0
        client credentials grant type to authenticate and fetch the token. The function constructs the request URI
        using configuration settings from $LrtConfig.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .OUTPUTS
        [System.Object] representing an Exabeam resource access token.

        Object Properties
        -----------------
        token_type      = Type of token (e.g., "Bearer").
        expires_in      = Expiry time span in seconds.
        ext_expires_in  = Extended expiry time span in seconds.
        expires_on      = Expiry timestamp as UTC datetime.
        not_before      = Creation timestamp as UTC datetime.
        resource        = Resource URL for which the token is generated.
        access_token    = The actual bearer token string.
    .NOTES
        Exabeam-API   
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential
    )

    Begin { 
        $Me = $MyInvocation.MyCommand.Name

        # Credentials
        $ClientId = $LrtConfig.Exabeam.ApiKey.Username
        $ClientSecret = $LrtConfig.Exabeam.ApiKey.GetNetworkCredential().Password

        $ResourceUri = $LrtConfig.Exabeam.BaseUrl + 'auth/v1/token'
    }


    Process {
        $BodyContents = [PSCustomObject]@{
            "grant_type" = 'client_credentials'
            client_id = $ClientId 
            client_secret = $ClientSecret
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json 
        Write-Verbose $Body

        # Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("accept",'application/json')
        $Headers.Add("content-type",'application/json')


        # Request
        try {
            $Token = Invoke-RestMethod -Uri $ResourceUri -Headers $Headers -Method $HttpMethod.Post -Body $Body
        }
        catch [WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.error)]: $($Err.error_description)`n"
        }

        $Token | Add-Member -MemberType NoteProperty -Name expires_on -Value $((get-date).AddSeconds($Token.expires_in))

        return $Token
    }


    End { }
}