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
        [int] $Days = 1,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [int] $StartHour = 0,
        
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [int] $EndHour = 23,

        [Parameter(Mandatory = $false, Position = 3)]
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
        $CurrentDate = (Get-Date).ToUniversalTime()
        # Temporary variables
        $PastDate = $CurrentDate.Date.AddDays(-$Days)
        
        # Validate hour parameters (between 0-23)
        $ValidatedStartHour = [Math]::Max(0, [Math]::Min(23, $StartHour))
        $ValidatedEndHour = [Math]::Max(0, [Math]::Min(23, $EndHour))
        
        # Ensure EndHour isn't less than StartHour
        if ($ValidatedEndHour -lt $ValidatedStartHour) {
            $ValidatedEndHour = $ValidatedStartHour
        }
        
        Write-Verbose "[$Me]: Using time range: $ValidatedStartHour:00 to $ValidatedEndHour:59"
        
        # Create precise time range for this query with guaranteed non-overlapping time windows
        $startTime = $PastDate.AddHours($ValidatedStartHour).ToString("yyyy-MM-ddTHH:00:00.000Z")
        
        # If we're querying the same day, use the end hour with precise formatting
        # If we're querying multiple days, handle differently
        if ($Days -le 1) {
            # Create an exclusive end time that doesn't overlap with the next time block
            # End time is the last second of the specified end hour (HH:59:59)
            $endTime = $PastDate.AddHours($ValidatedEndHour).AddMinutes(59).AddSeconds(59).ToString("yyyy-MM-ddTHH:mm:ss.000Z")
            Write-Verbose "[$Me]: Time window: $startTime to $endTime"
        } else {
            # For multi-day queries, keep the existing behavior
            $endTime = $PastDate.AddDays($Days).ToString("yyyy-MM-ddT23:59:59.000Z")
            Write-Verbose "[$Me]: Multi-day time window: $startTime to $endTime"
        }


        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        $body = [PSCustomObject]@{
            limit     = 1000000
            distinct  = $false
            filter    = 'NOT user IN "FHK Approved Users"."Primary User Name" AND NOT user: null AND uri_path:WLDi("*aspx*") AND url:WLDi("*?*") AND NOT http_response_code: 401 AND c_route_id="Gov" AND m_origin_hostname IN "WIndWard Prod Hosts"."Hostname"'
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

        Write-Verbose $Body
 
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me -Body $body
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider

        if ($Response.rows) {
            $AddRows = [list[object]]::new()
            ForEach($Row in $Response.rows) {
                $timestamp = $(ConvertFrom-UnixEpoch -UnixTime $($row.approxLogTime / 1000000))
                $Row | Add-Member -MemberType NoteProperty -Name 'timestamp' -Value $timestamp.ToString("M/d/yyyy h:mm:ss tt")
                $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($Row.approxLogTime)$($Row.host)$($Row.user)$($Row.uri_path)"))
                $Row | Add-Member -MemberType NoteProperty -Name 'sha1' -Value $([BitConverter]::ToString($hashBytes) -replace '-', '')
                if ($AddRows.sha1 -notcontains $Row.sha1) {
                    $AddRows.add($Row)
                }
            }
            $Response.rows = @($AddRows)
        }


        return $Response
    }

    End { }
}