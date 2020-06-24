using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-SrfAzRiskDetections {
    <#
    .SYNOPSIS
        XXXXXXXX
    .DESCRIPTION
        XXXXXXXX
    .PARAMETER Token
        An access token issued by the Microsoft identity platform with a valid claim to Microsoft
        Graph. The registered application will require the IdentityRiskyUser.Read.All role.
    .INPUTS
        [Type] -> Parameter
    .OUTPUTS
        A collection of 
        https://docs.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-beta#properties
    .EXAMPLE
        PS C:\> 
    .NOTES
        Azure-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [object] $Token = $LrtConfig.Resources.Graph.Token
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $AccessToken = $Token.access_token
        
        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }


    Process {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $AccessToken")
        $Method = $HttpMethod.Get

        # Request URI
        $RequestUri = "https://graph.microsoft.com/beta/riskDetections?`$top=200"


        # Build Request URI Filters
        if ($After) {
            $_after = $After | ConvertTo-Rfc3339
            Write-Verbose "+ Filter Activity After (RFC-3339): $_after"
            $RequestUri += "& AND createdDateTime ge $_after"
        }

        if ($Before) {
            $_before = $Before | ConvertTo-Rfc3339
            Write-Verbose "+ Filter Activity After (RFC-3339): $_before"
            $RequestUri += "& AND createdDateTime le $_before"
        }

        
        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method `
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.error.code)]: $($Err.error.message)`n"
        }

        return $Response.value

    }


    End { }
}