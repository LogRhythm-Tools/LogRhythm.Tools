using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaSearch {
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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [int] $StartHour = 0,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [int] $EndHour = 23,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [DateTime] $SearchDate = (Get-Date), 
        
        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateNotNull()]
        [string] $Filter, 

        [Parameter(Mandatory = $true, Position = 4)]
        [ValidateNotNull()]
        [string[]] $Fields, 

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [string[]] $ShaFields, 

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [bool] $Distinct = $false, 

        [Parameter(Mandatory = $false, Position = 7)]
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
        
        # Use SearchDate parameter (defaults to today if not provided)
        $QueryDate = $SearchDate.Date
        Write-Verbose "[$Me]: Using search date: $QueryDate"
        
        # Validate hour parameters (between 0-23)
        $ValidatedStartHour = [Math]::Max(0, [Math]::Min(23, $StartHour))
        $ValidatedEndHour = [Math]::Max(0, [Math]::Min(23, $EndHour))
        
        # Ensure EndHour isn't less than StartHour
        if ($ValidatedEndHour -lt $ValidatedStartHour) {
            $ValidatedEndHour = $ValidatedStartHour
        }
        
        # Create precise time range for this query with guaranteed non-overlapping time windows
        $startTime = $QueryDate.AddHours($ValidatedStartHour).ToString("yyyy-MM-ddTHH:00:00.000Z")
        
        # Create precise end time for the time block (last second of the end hour)
        # End time is the last second of the specified end hour (HH:59:59)
        $endTime = $QueryDate.AddHours($ValidatedEndHour).AddMinutes(59).AddSeconds(59).ToString("yyyy-MM-ddTHH:mm:ss.000Z")
        Write-Verbose "[$Me]: Precise time window: $startTime to $endTime"


        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        if ($Fields -notcontains 'approxLogTime') {
            $Fields += 'approxLogTime'
        }

        $body = [PSCustomObject]@{
            limit     = 1000000
            distinct  = $Distinct
            filter    = $Filter
            startTime = $startTime
            endTime   = $endTime
            fields    = $Fields
        } | ConvertTo-Json -Compress

        Write-Verbose $Body
 
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me -Body $body
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        if ($ShaFields -and $ShaFields.Count -gt 0) {
            $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider

            if ($Response.rows) {
                $AddRows = [list[object]]::new()
                ForEach($Row in $Response.rows) {
                    $timestamp = $(ConvertFrom-UnixEpoch -UnixTime $($row.approxLogTime / 1000000))
                    $Row | Add-Member -MemberType NoteProperty -Name 'timestamp' -Value $timestamp.ToString("M/d/yyyy h:mm:ss tt")
                    $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($Row.approxLogTime)$($Row.$($ShaFields[0]))$($Row.$($ShaFields[1]))"))
                    $Row | Add-Member -MemberType NoteProperty -Name 'sha1' -Value $([BitConverter]::ToString($hashBytes) -replace '-', '')
                    if ($AddRows.sha1 -notcontains $Row.sha1) {
                        $AddRows.add($Row)
                    }
                }
                $Response.rows = @($AddRows)
            }
        }

        




        return $Response
    }

    End { }
}