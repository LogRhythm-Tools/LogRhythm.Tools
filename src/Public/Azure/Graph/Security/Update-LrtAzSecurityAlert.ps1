using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrtAzSecurityAlert {
    <#
    .SYNOPSIS
        Update a specific Azure Security Alert via Graph API.
    .DESCRIPTION
        The Update-LrtAzSecurityAlert cmdlet enables updating an existing alert in Azure. 
    .PARAMETER AlertId
        The Id of the Alarm Update request.
    .PARAMETER AssignedTo
        Name of the analyst the alert is assigned to for triage, investigation, or remediation.
    .PARAMETER ClosedDate
        Time at which the alert was closed. The Timestamp type represents date and time 
        information using ISO 8601 format and is always in UTC time. 
    
        For example, midnight UTC on Jan 1, 2014 would look like this: 
        '2014-01-01T00:00:00Z'.
    .PARAMETER Comments
        Analyst comments on the alert (for customer alert management). 
        
        This method can update the comments field with the following values only:
         Closed in IPC, Closed in MCAS.
    .PARAMETER Feedback
        Analyst feedback on the alert. 
        
        Possible values are: unknown, truePositive, falsePositive, benignPositive.
    .PARAMETER Provider
    .PARAMETER Status
        Alert life cycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved.
    .PARAMETER Tags
        User-definable labels that can be applied to an alert and can serve as filter conditions.
        Examples: "HVA", "SAW"
    .PARAMETER Vendor
    .PARAMETER Token
        An access token issued by the Microsoft identity platform with a valid claim to Microsoft
        Graph. The registered application will require the IdentityRiskyUser.Read.All role.
    .INPUTS
        None
    .OUTPUTS
        A collection of signIn objects designed as being "At Risk" by the Identity platform.
        https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta#properties
    .EXAMPLE
        PS C:\> 
    .NOTES
        Azure-API
    .LINK
        https://github.com/GeneCupstid/SRF-Private
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [string] $AlertID,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $AssignedTo,


        [Parameter(Mandatory = $false, Position = 2)]
        [DateTime] $ClosedDate,


        [Parameter(Mandatory = $false, Position = 3)]
        [string[]] $Comments,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('unknown','truePositive','falsePositive', 'benignPositive', ignorecase=$true)]
        [string] $Feedback,


        [Parameter(Mandatory = $false, Position = 5)]
        #[ValidateSet('Office 365 Security and Compliance', 'IPC', ignorecase=$true)]
        [string] $Provider,


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet('unknown','newAlert','inProgress', 'resolved', ignorecase=$true)]
        [string] $Status,


        [Parameter(Mandatory = $false, Position = 7)]
        [string[]] $Tags,


        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateSet('microsoft', ignorecase=$true)]
        [string] $Vendor
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $AccessToken = Get-LrtAzToken -ResourceName AzureAd | Select-Object -ExpandProperty access_token
        
        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }


    Process {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $AccessToken")
        $Headers.Add("Content-type", "application/json")

        # Request URI
        # https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=http
        $Method = $HttpMethod.Patch
        $RequestUri = "https://graph.microsoft.com/v1.0/security/alerts/$AlertID"

        Switch ($Provider) {
            "Office 365 Security and Compliance" { $_provider = 'Office 365 Security and Compliance' }
            "IPC" { $_provider = 'IPC' }
            default { $_provider = $Provider }
        }

        Switch ($Vendor) {
            "Microsoft" { $_vendor = 'Microsoft' }
            "truePositive" { $_vendor = 'truePositive' }
            "falsePositive" { $_vendor = 'falsePositive' }
            "benignPositive" { $_vendor = 'benignPositive' }
            default { $_vendor = 'Microsoft' }
        }

        if ($Feedback) {
            Switch ($Feedback) {
                "unknown" { $_feedback = 'unknown' }
                "truePositive" { $_feedback = 'truePositive' }
                "falsePositive" { $_feedback = 'falsePositive' }
                "benignPositive" { $_feedback = 'benignPositive' }
            }
        }

        if ($Status) {
            Switch ($Status) {
                "unknown" { $_status = 'unknown' }
                "newAlert" { $_status = 'newAlert' }
                "inProgress" { $_status = 'inProgress' }
                "resolved" { $_status = 'resolved' }
            }
        }

        if ($ClosedDate) {
            $_closedDate = $ClosedDate.GetDateTimeFormats("u")
        }


        # Build PatchBody
        $_body = [PSCustomObject]@{
            vendorInformation = [PSCustomObject]@{
                provider = $_provider
                vendor = $_vendor
            }
        }

        if ($_status) {
            $_body | Add-Member -NotePropertyName status -NotePropertyValue $_status
        }


        if ($_closedDate) {
            $_body | Add-Member -NotePropertyName closedDateTime -NotePropertyValue $_closedDate
        }

        if ($AssignedTo) {
            $_body | Add-Member -NotePropertyName assignedTo -NotePropertyValue $AssignedTo
        }

        $Body = $_body | ConvertTo-Json

        Write-Verbose "Message Body: `r$Body"

        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method `
                -Body $Body `
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.error.code)]: $($Err.error.message)`n"
        }
        
        #endregion

        return $Response
    }

    End { }
}