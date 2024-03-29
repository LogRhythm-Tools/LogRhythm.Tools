using namespace System
using namespace System.Collections.Generic

Function Get-RfAlertSearch {
    <#
    .SYNOPSIS
        Get Search results RecordedFuture Alert Rule(s).
    .DESCRIPTION
        Get RecordedFuture Alert Rules cmdlet retrieves the available Alert Rule title and id values.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Freetext
        Name of the RecordedFuture Alert Rules
    .PARAMETER Limit
        Default set to 100.
    .INPUTS
    .NOTES
        RecordedFuture-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [datetime] $Triggered,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Assignee,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Status,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $AlertRule,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNullOrEmpty()]
        [string] $FreeText,


        [Parameter(Mandatory = $false, Position = 5)]
        [int] $Limit,


        [Parameter(Mandatory = $false, Position = 6)]
        [int] $From,


        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullOrEmpty()]
        [string] $OrderBy,


        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNullOrEmpty()]
        [string] $Direction,


        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.RecordedFuture.ApiKey
    )

    Begin {
        $BaseUrl = $LrtConfig.RecordedFuture.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("X-RFToken", $Token)

        Write-Verbose "$($Headers | Out-String)"

        # Request Setup
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Verify Status
        $ValidStatus = @("unassigned", "assigned", "actionable", "no-action", "tuning")
        if ($Status) {
            if ($Status -like $ValidStatus) {
                $Status = $ValidStatus
            } else {
                return "Please provide valid status: unassigned, assigned, actionable, no-action, tuning"
            }
        }

        # Verify Direction
        $ValidDirection = @("desc", "asc")
        if ($Direction) {
            if ($Direction -like $ValidDirection) {
                $Direction = $ValidDirection
            } else {
                return "Please provide valid status: desc, asc"
            }
        }
    }

    Process {
        # Establish Query Parameters object
        $QueryParams = [Dictionary[string,string]]::new()

        # Triggered
        if ($Triggered) { $QueryParams.Add("triggered", $Triggered) }

        # Assignee
        if ($Assignee) { $QueryParams.Add("assignee", $Assignee) }

        # Status
        if ($Status) { $QueryParams.Add("status", $Status) }

        # AlertRule
        if ($AlertRule) { $QueryParams.Add("alertRule", $AlertRule) }

        # Freetext
        if ($FreeText) { $QueryParams.Add("freetext", $FreeText) }

        # Limit
        if ($Limit) { $QueryParams.Add("limit", $Limit) }

        # From
        if ($From) { $QueryParams.Add("from", $From) }

        # OrderBy
        if ($OrderBy) { $QueryParams.Add("orderby", $OrderBy) }

        # Direction
        if ($Direction) { $QueryParams.Add("direction", $Direction) }

        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }



        # Define Search URL
        $RequestUrl = $BaseUrl + "alert/search" + $QueryString
        Write-Verbose "[$Me]: Request URL: $RequestUrl"


        Try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers
        }
        catch {
            If ($_.Exception.Response.StatusCode.value__) {
                $HTTPCode = ($_.Exception.Response.StatusCode.value__ ).ToString().Trim()
                Write-Verbose "HTTP Code: $HTTPCode"
            }
            If  ($_.Exception.Message) {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $ExceptionMessage
            }
        }

        
        # Return Values only as an array or all results as object
        Return $Results.data.results
    }

    End { }
}