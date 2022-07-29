using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrCaseAssociatedCase {
    <#
    .SYNOPSIS
        Add an assocaited case to a LogRhythm case.
    .DESCRIPTION
        The Add-LrCaseAssociatedCase cmdlet adds a case as an association to an existing case.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string,
        or as a number, or the exact name of the case.
    .PARAMETER Ids
        Array of case identifiers to add as associated cases.
    .INPUTS
        [System.Object]     "Id" ==> [Id] : The ID of the Case to modify.
        [System.Int[array]] "Ids" ==> [Ids] : The ID(s) of the Cases to associate.
    .OUTPUTS
        PSCustomObject representing the added playbook.
    .EXAMPLE
        PS C:\> Add-LrCaseAssociatedCase -Id 267 -Ids 213
        ---
        id         : 29EF7E22-94B1-4C06-9E0E-778F608A2494
        number     : 4
        externalId :
        private    : False
        summary    : @{id=29EF7E22-94B1-4C06-9E0E-778F608A2494; number=4; externalId=; dateCreated=2020-07-24T20:40:43.6694297Z; dateUpdated=2020-07-25T23:46:29.4980008Z; dateClosed=; owner=;
                    lastUpdatedBy=; name=Concurrent VPN Connection from Disparate Locations; status=; priority=2; dueDate=2020-07-25T20:40:43.6534399Z; resolution=; resolutionDateUpdated=;
                    resolutionLastUpdatedBy=; summary=Remote Access VPN authenticating from multiple geographic locations within close time proximity.  Time between authentications: Days: 0 Hours: 0
                    Secs: 30.  The distance between the two locations is greater than 2000 miles.; entity=; collaborators=System.Object[]; tags=System.Object[]}
    .EXAMPLE
        PS C:\> Add-LrCaseAssociatedCase -Id 267 -Ids @(213, 217)
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


        [Parameter( Mandatory = $true, Position = 2)]
        [ValidateNotNull()]
        [int32[]] $Ids
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        

        # Request URI
        $Method = $HttpMethod.Post
    }


    Process {
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }  

        [string[]]$ValidIDs = @()
        # Test Associated Case Ids
        ForEach ($Number in $Ids) {
            $CaseStatus = Test-LrCaseIdFormat $Number
            if ($CaseStatus.IsValid) {
                $ValidIds += $CaseStatus.CaseGuid
            }
        }

        Write-Verbose "ValidUserId: $ValidIDs"
        # Create request body with people numbers
        if (!($ValidId -Is [System.Array])) {
            $Body = "{ `"ids`": [`"$ValidIds`"] }"
        } else {
            # multiple values, create an object
            $Body = [PSCustomObject]@{ ids = $ValidIds } | ConvertTo-Json
        }
        
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/associated/"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        if ($PassThru) {
            return $Response
        }
    }


    End { }
}