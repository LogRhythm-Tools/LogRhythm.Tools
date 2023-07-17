using namespace System
using namespace System.Collections.Generic

Function Get-RfAlerts {
    <#
    .SYNOPSIS
        Get RecordedFuture Alerts detail.
    .DESCRIPTION
        Get RecordedFuture Alerts allows for searching for triggered alerts.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        Id value for Recorded Future Alert retrieval.
    .INPUTS

    .NOTES
        RecordedFuture-API v3
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $AlertRuleId,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('New','Resolved', 'Pending', 'Flag for Tuning', ignorecase=$true)]
        [string] $Status,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Triggered,


        [Parameter(Mandatory = $false, Position = 2)]
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
    }

    Process {
        # Establish Query Parameters object
        $QueryParams = [Dictionary[string,string]]::new()

        if ($AlertRuleId) {
            $QueryParams.Add("alertRule", $AlertRuleId)
        }

        if ($Status) {
            $QueryParams.Add("statusInPortal", $Status)
        }

        
        if ($Triggered) {
            $QueryParams.Add("triggered", "["+$Triggered+",]")
        }

        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Define Search URL
        $RequestUrl = $BaseUrl + "/v3/alerts/" + $QueryString
        Write-Verbose "[$Me]: Request URL: $RequestUrl"


        Try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers
        } catch {
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
        Return $Results.data
    }

    End { }
}