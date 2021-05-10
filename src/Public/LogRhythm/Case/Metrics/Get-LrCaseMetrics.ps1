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
        PS C:\> Get-LrCaseMetrics -Id 2095
        --- 

        created          : @{date=6/6/2020 9:46:49 AM; originalDate=6/6/2020 9:46:49 AM; customDate=; note=}
        completed        : @{date=; originalDate=; customDate=; note=}
        incident         : @{date=; originalDate=; customDate=; note=}
        mitigated        : @{date=; originalDate=; customDate=; note=}
        resolved         : @{date=; originalDate=; customDate=; note=}
        earliestEvidence : @{date=6/5/2020 1:46:47 PM; originalDate=; customDate=6/5/2020 1:46:47 PM; note=LogRhythm Tools: Update EarliestEvidence Timestamp}
        TTD              : 20:00:02.4964154
        TTR              : N/A
        TTE              : N/A
        TTC              : N/A
    .EXAMPLE
        PS C:\> Get-LrCaseMetrics -Id "case 2"
        ---

        created          : @{date=6/6/2020 9:46:49 AM; originalDate=6/6/2020 9:46:49 AM; customDate=; note=}
        completed        : @{date=; originalDate=; customDate=; note=}
        incident         : @{date=7/16/2020 10:30:38 PM; originalDate=7/16/2020 10:30:38 PM; customDate=; note=}
        mitigated        : @{date=7/16/2020 10:37:21 PM; originalDate=7/16/2020 10:37:21 PM; customDate=; note=}
        resolved         : @{date=7/16/2020 10:37:38 PM; originalDate=7/16/2020 10:37:38 PM; customDate=; note=}
        earliestEvidence : @{date=6/5/2020 1:46:47 PM; originalDate=; customDate=6/5/2020 1:46:47 PM; note=LogRhythm Tools: Update EarliestEvidence Timestamp}
        TTD              : 20:00:02.4964154
        TTR              : 40.12:50:32.3369253
        TTE              : 40.12:43:49.0602425
        TTC              : 40.12:50:49.0538522
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [object] $Id,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # HTTP Method
        $Method = $HttpMethod.Get

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        $_COUNT = 0
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Case                  =   $Id
            Raw                   =   $null
        } 

        $_COUNT++
        $RunAgain = $false

        # Test CaseID Format
        $Case = Test-LrCaseIdFormat $Id
        if ($Case.IsValid) {
            $CaseNumber = $Case.CaseNumber
        } else {
            return $Case
        }
     
        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/metrics"


        #region: Send Request - First Attempt                                                      
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
             # Rate limit error
             if ($Err.statusCode -eq "429") {
                Write-Verbose "Rate limit exceeded at case $CaseNumber, throttling requests."
                $RunAgain = $true
                Start-Sleep -Milliseconds 100
            } else {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.Error = $true
                $ErrorObject.Raw = $_
                return $ErrorObject
            }
        }      
        #endregion



        #region: Send Request - Second Attempt                                                     
        if ($RunAgain) {
            Write-Verbose "Running Second Attempt at $CaseNumber"
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
            } catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.Error = $true
                $ErrorObject.Raw = $_
                return $ErrorObject
            }
        }
        #endregion



        #region: Convert values to DateTime                                              
        # category: created, completed, incident, mitigated, resolved, earliestEvidence
        # property: date, originalDate, customDate, note
        
        if ($Response) {
            # Placeholders
            $d = [datetime]::MinValue
            
            # Step One: For each category of date, convert any dates into datetime objects
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

        Start-Sleep -Milliseconds 50

        # End
        return $Response
    }


    End {
        Write-Verbose "Processed $_COUNT cases."
    }
}