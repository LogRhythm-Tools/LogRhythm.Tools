using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrCaseStatus {
    <#
    .SYNOPSIS
        Update the status of a case.
    .DESCRIPTION
        The Update-LrCaseStatus cmdlet updates an existing case's status based on an integer
        representing one of LogRhythm's 5 status codes.

        Case Status must be changed in a particular order.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER StatusNumber
        Numeric identifier of the Case's Status. Status must be an integer between 1 and 5.
        1 - [Case]      Created
        2 - [Case]      Completed
        3 - [Incident]  Open
        4 - [Incident]  Mitigated
        5 - [Incident]  Resolved
    .PARAMETER Quiet
        Indicates that this cmdlet suppresses all output.
    .INPUTS
        [System.Object]   ->  Id
        [System.Int32]    ->  StatusNumber
    .OUTPUTS
        PSCustomObject representing the modified LogRhythm Case.
    .EXAMPLE
        PS C:\> Update-LrCaseStatus -Id "CC06D874-3AC5-4E6F-A8D1-C5F2AF477EEF" -StatusNumber 2
        ---
            id                      : CC06D874-3AC5-4E6F-A8D1-C5F2AF477EEF
            number                  : 1815
            externalId              :
            dateCreated             : 2019-10-04T22:16:37.0980428Z
            dateUpdated             : 2019-10-05T02:46:22.8836839Z
            dateClosed              : 2019-10-05T02:46:22.8802919Z
            owner                   : @{number=52; name=API, LogRhythm; disabled=False}
            lastUpdatedBy           : @{number=52; name=API, LogRhythm; disabled=False}
            name                    : Test Case - Pester Automated Test
            status                  : @{name=Completed; number=2}
            priority                : 5
            dueDate                 : 2019-10-15T09:18:22Z
            resolution              :
            resolutionDateUpdated   :
            resolutionLastUpdatedBy :
            summary                 : Case created by Pester automation
            entity                  : @{number=-100; name=Global Entity}
            collaborators           : {@{number=52; name=API, LogRhythm; disabled=False}}
            tags                    : {}
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


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [object] $Id,

        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Status,

        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru,

        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $Summary
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Request Method
        $Method = $HttpMethod.Put

        # Set initial ProcessedCount
        $ProcessedCount = 0
    }


    Process {
        # Get Case Id
        $IdInfo = Test-LrCaseIdFormat $Id
        if (! $IdInfo.IsValid) {
            throw [ArgumentException] "Parameter [Id] should be an RFC 4122 formatted string or an integer."
        }


        # Validate Case Status
        $_status = ConvertTo-LrCaseStatusId -Status $Status
        if (! $_status) {
            throw [ArgumentException] "Invalid case status: $Status"
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/cases/$Id/actions/changeStatus/"


        # Request Body
        $Body = [PSCustomObject]@{
            statusNumber = $_status
        } | ConvertTo-Json

        
        # Send Request
        Write-Verbose "[$Me]: request body is:`n$Body"

        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
            }
        }
        $ProcessedCount++

        # Return
        if ($PassThru) {
            return $Response    
        }
    }

    
    End { 
        if ($Summary) {
            Write-Host "Updated $ProcessedCount cases to status $Status"
        }
    }
}