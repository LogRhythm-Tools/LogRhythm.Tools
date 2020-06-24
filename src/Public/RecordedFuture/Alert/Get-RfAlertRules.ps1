using namespace System
using namespace System.Collections.Generic

Function Get-RfAlertRules {
    <#
    .SYNOPSIS
        Get RecordedFuture Alert Rules.
    .DESCRIPTION
        Get RecordedFuture Alert Rules cmdlet retrieves the available Alert Rule title and id values.  
    .PARAMETER Token
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
        [pscredential] $Credential = $LrtConfig.RecordedFuture.ApiKey,

        [string] $Freetext,
        [int] $Limit = 100
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

        # Format
        $QueryParams.Add("freetext", $Freetext)

        # Compression
        $QueryParams.Add("limit", $Limit)

        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }



        # Define Search URL
        $RequestUrl = $BaseUrl + "alert/rule" + $QueryString
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        Try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers
        }
        catch [System.Net.WebException] {
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