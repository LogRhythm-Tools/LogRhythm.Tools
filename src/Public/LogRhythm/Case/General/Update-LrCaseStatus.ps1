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
        PS C:\> Update-LrCaseStatus -id 2 -Status 2 -Summary
        ---
        Updated 1 cases to status 2
    .EXAMPLE
        PS C:\> Update-LrCaseStatus -id "case 2" -Status 1 -Summary
        ---
        Updated 1 cases to status 1
    .EXAMPLE
        PS C:\> Update-LrCaseStatus -id "case 2" -Status 1 -PassThru
        ---

        id                      : 408C2E88-2E5D-4DA5-90FE-9F4D63B5B709
        number                  : 2
        externalId              :
        dateCreated             : 2020-06-06T13:46:49.4964154Z
        dateUpdated             : 2020-07-17T02:03:20.2314328Z
        dateClosed              :
        owner                   : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy           : @{number=1; name=lrtools; disabled=False}
        name                    : Case 2
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-06-07T13:46:44Z
        resolution              : 
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 :
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=-100; name=LogRhythm Administrator; disabled=False}, @{number=1; name=lrtools; disabled=False}}
        tags                    : {}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 0
        )]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Status,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $Summary,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
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
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }

        # Validate Case Status
        $_status = ConvertTo-LrCaseStatusId -Status $Status
        if (! $_status) {
            throw [ArgumentException] "Invalid case status: $Status"
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/actions/changeStatus/"


        # Request Body
        $Body = [PSCustomObject]@{
            statusNumber = $_status
        } | ConvertTo-Json

        
        # Send Request
        Write-Verbose "[$Me]: request body is:`n$Body"

        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
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