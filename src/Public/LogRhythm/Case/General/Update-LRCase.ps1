using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrCase {
    <#
    .SYNOPSIS
        Update an existing case.
    .DESCRIPTION
        The Update-LrCase cmdlet updates an existing case and returns the updated case record as a PSCustomObject.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Name
        Name of the case.
    .PARAMETER Priority
        (int 1-5) Priority of the case.
    .PARAMETER DueDate
        When the case is due, as [System.DateTime] or a date-parsable [System.String]
        If ommitted, a due date will be set for 24 hours from the current time.
    .PARAMETER Summary
        Note summarizing the case.
    .INPUTS
        Name, Priority, DueDate, and Summary can all be sent by name through the pipeline.
    .OUTPUTS
        PSCustomObject representing the newly created case.
    .EXAMPLE
        PS C:\> Update-LrCase -Id 5 -Name "test" -Priority 5 -Summary "test summary" -DueDate "10-20-2020 14:22:11"
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName = $true, Position=1)]
        [object] $Id,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName = $true, Position=2)]
        [ValidateLength(1,250)]
        [string] $Name,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName = $true, Position=3)]
        [ValidateRange(1,5)]
        [int] $Priority,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [DateTime] $DueDate,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [ValidateLength(1,10000)]
        [string] $Summary
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
    }

    Process {
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        } 

        $CaseDetails = Get-LrCaseById -Id $CaseNumber

        if ($Name) {
            $_name = $Name
        } else {
            $_name = $CaseDetails.Name
        }

        if ($DueDate) {
            $_dueDate = $DueDate
        } else {
            $_dueDate = $CaseDetails.dueDate
        }

        if ($Priority) {
            $_priority = $Priority
        } else {
            $_priority = $CaseDetails.priority
        }

        if ($Summary) {
            $_summary = $Summary
        } else {
            $_summary = $CaseDetails.summary
        }

        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/"

        # Request Body
        $Body = [PSCustomObject]@{
            name = $_name
            priority = $_priority
            externalId = $null
            dueDate = [Xml.XmlConvert]::ToString(($_dueDate),[Xml.XmlDateTimeSerializationMode]::Utc)
            summary = $_summary
        }
        $Body = $Body | ConvertTo-Json

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
                Write-Verbose "[$Me]: Created Case $($Response.id)" 
            }
            catch {
                $Err = Get-RestErrorMessage $_
                throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
                Write-Verbose "[$Me]: Created Case $($Response.id)"
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
            }
        }

        # Done!
        return $Response
    }


    End { }
}