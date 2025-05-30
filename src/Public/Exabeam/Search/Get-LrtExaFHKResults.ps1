using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrtExaFHKResults {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        The Name parameter can be provided via the PowerShell pipeline.
    .OUTPUTS

    .EXAMPLE

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $RouteId,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)]
        [ValidateNotNull()]
        [int] $Days = 1,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Exabeam.ApiKey
    )
                                                                    
    Begin {
        $Me = $MyInvocation.MyCommand.Name
        Set-LrtExaToken
        # Request Setup
        $BaseUrl = $LrtConfig.Exabeam.BaseUrl
        $Token = $LrtConfig.Exabeam.Token.access_token


        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("content-type", "application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "search/v2/events"

        # Temporary variables
        $yesterday = (Get-Date).ToUniversalTime().Date.AddDays(-$Days)
        $startTime = $yesterday.ToString("yyyy-MM-ddT00:00:00.000Z")
        $endTime = $yesterday.AddDays($Days).ToString("yyyy-MM-ddT00:00:00.000Z")

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        $body = [PSCustomObject]@{
            limit     = 1000000
            distinct  = $false
            filter    = "msg_type: `"microsoft-iis-str-http-session-dq-gov-custom`" AND c_route_id: `"$($RouteId)`" AND NOT http_response_code: 400"
            startTime = $startTime
            endTime   = $endTime
            fields    = @(
                "approxLogTime",
                "host",
                "user",
                "object",
                "uri_path",
                "uri_query",
                "url",
                "method",
                "c_route_id"
            )
        } | ConvertTo-Json -Compress

 
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me -Body $body
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider

        if ($Response.rows) {
            ForEach($Row in $Response.rows) {
                $timestamp = $(ConvertFrom-UnixEpoch -UnixTime $($row.approxLogTime / 1000000))
                $Row | Add-Member -MemberType NoteProperty -Name 'timestamp' -Value $timestamp.ToString("M/d/yyyy h:mm:ss tt")
                $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($Row.approxLogTime)$($Row.host)$($Row.user)$($Row.uri_path)"))
                $Row | Add-Member -MemberType NoteProperty -Name 'sha1' -Value $([BitConverter]::ToString($hashBytes) -replace '-', '')
            }
        }


        return $Response
    }

    End { }
}