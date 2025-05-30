using namespace System
using namespace System.Collections.Generic

Function Get-RfAlert {
    <#
    .SYNOPSIS
        Get RecordedFuture Alert detail for a specified alert.
    .DESCRIPTION
        Get RecordedFuture Alert allows for retrieving the details for a specific alert.  
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
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $AlertId,


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

        # Define Search URL
        $RequestUrl = $BaseUrl + "v3/alerts/" + $AlertId
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