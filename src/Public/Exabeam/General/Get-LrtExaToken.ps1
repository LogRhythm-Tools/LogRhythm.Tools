using namespace System
using namespace System.Net
using namespace System.Collections.Generic
using namespace System.Web

Function Get-LrtExaToken {
    <#
    .SYNOPSIS
        Get an access token to access Exabeam API resources.
    .DESCRIPTION
    .PARAMETER Credential
 
    .INPUTS
        [System.String] => $ResourceName
    .OUTPUTS
        [System.Object] representing an Exabeam resource access token.

        Object Properties
        -----------------
        token_type      = "Bearer"
        expires_in      = Expiry timespan
        ext_expires_in  = Expiry timespan
        expires_on      = Expiry timestamp
        not_before      = Creation timestamp
        resource        = Resource URL
        access_token    = Bearer Token String
    .EXAMPLE
        PS C:\> $AccessToken = Get-LrtExaToken

    .EXAMPLE

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


        # Write Info
        Write-Verbose "ResourceUri: $ResourceUri"
        Write-Verbose "Client ID: $ClientId"
        Write-Verbose "Client Secret: $ClientSecret"

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