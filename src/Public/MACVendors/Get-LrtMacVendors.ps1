using namespace System
using namespace System.Collections.Generic

Function Get-LrtMacVendors {
    <#
    .SYNOPSIS
        Retrieve Vendor details for a given MAC Address.
    .DESCRIPTION
        Retrieve Vendor details for a given MAC Address.
    .PARAMETER Mac
        MAC Address value for vendor lookup.
    .INPUTS

    .NOTES
        MacVendors-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Mac
    )

    Begin {
        # Request URL
        $BaseUrl = "https://api.macvendors.com/"

        # Request Setup
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {

        # Define lookup URL
        $RequestUrl = $BaseUrl + $Mac
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        $Results = Invoke-WebRequest $RequestUrl -Method $Method -Headers $Headers -ErrorAction SilentlyContinue


        if ($results.ErrorDetails) {
            return $($($Results.ErrorDetails.Message) | ConvertFrom-Json | Select-Object -ExpandProperty Errors)
        }
        
        # Return Values only as an array or all results as object
        Return $Results.Content
    }

    End { }
}