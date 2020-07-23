using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCaseMetrics {
    <#
    .SYNOPSIS
        Return metrics for a specified case.
    .DESCRIPTION
        The Get-LrCaseMetrics cmdlet will return metrics for a specified case,
        and also provide timespans for the 4 different metric categories:
        (created, completed, incident, mitigated, resolved, earliestEvidence)
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .INPUTS
        System.Object -> Id
    .OUTPUTS
        PSCustomObject representing a LogRhythm Case's metrics.
    .EXAMPLE
        PS C:\> Get-LrCaseMetrics -Id 2095 -Verbose
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 1
        )]
        [object] $Id
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }


    Process {
        #region: Main                                                                    
        # Validate Case ID (Guid || Int)
        $IdInfo = Test-LrCaseIdFormat $Id
        if (! $IdInfo.IsValid) {
            throw [ArgumentException] "Parameter [Id] should be an RFC 4122 formatted string or an integer."
        }
        
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Request URI
        $Method = $HttpMethod.Get
        $RequestUri = $BaseUrl + "/cases/$Id/metrics"


        # Send Request
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }        
        #endregion



        #region: Convert values to DateTime                                              
        # category: created, completed, incident, mitigated, resolved, earliestEvidence
        # property: date, originalDate, customDate, note
        
        if ($Response) {
            # Placeholders
            $d = [datetime]::MinValue
            
            # Step One: For each category of date, and convert any dates into datetime objects
            foreach ($category in $Response.PSObject.Properties) {
                foreach ($property in $category.Value.PSObject.Properties) {
                    if ($property.Value) {
                        if ([datetime]::TryParse($property.Value, [ref]$d)) {
                            $property.Value = $d
                        }
                    }
                }
            }
            # Step Two: TTD/TTR/TTE/TTC
            $TTD = "N/A"
            $TTR = "N/A"
            $TTE = "N/A"
            $TTC = "N/A"
            # Add to Response
            $Response | Add-Member -MemberType NoteProperty -Name "TTD" -Value $TTD
            $Response | Add-Member -MemberType NoteProperty -Name "TTR" -Value $TTR
            $Response | Add-Member -MemberType NoteProperty -Name "TTE" -Value $TTE
            $Response | Add-Member -MemberType NoteProperty -Name "TTC" -Value $TTC
            # TTD: Time to Detect
            if ($Response.Created.Date -and $Response.EarliestEvidence.Date) {
                $Response.TTD = $Response.Created.Date - $Response.earliestEvidence.Date
            }
            # TTR: Time to Respond
            if ($Response.Created.Date -and $Response.Mitigated.Date) {
                $Response.TTR = $Response.Mitigated.Date - $Response.Created.Date
            }
            # TTE: Time to Elevate
            if ($Response.Incident.Date -and $Response.Created.Date) {
                $Response.TTE = $Response.Incident.Date - $Response.Created.Date
            }
            # TTC: Time to Close (Incidents)
            if ($Response.Created.Date -and $Response.Resolved.Date) {
                $Response.TTC = $Response.Resolved.Date - $Response.Created.Date
            }
            # TTC: Time to Close (Non-Incidents)
            if ($Response.Created.Date -and $Response.Completed.Date) {
                $Response.TTC = $Response.Completed.Date - $Response.Created.Date
            }
        }
        #endregion



        # End
        return $Response
    }


    End { }
}