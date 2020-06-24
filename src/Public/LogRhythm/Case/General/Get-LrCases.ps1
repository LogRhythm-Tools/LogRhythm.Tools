using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace Microsoft.PowerShell.Commands

Function Get-LrCases {
    <#
    .SYNOPSIS
        Returns a filtered list of LogRhythm Cases.
    .DESCRIPTION
        The Get-LrCases cmdlet performs a search returning one or more
        LogRhythm cases based on the criteria provided.

        Unless a Count parameter is provided, the maximum number of
        records returned is limited to 500. It is not required to
        set any parameters in order to retrieve a result, the cases
        will be returned in the order in which they were added to the
        LogRhythm_CMDB.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Name
        Filter results that contain a string value.  Exact match available via -exact switch.
    .PARAMETER DueBefore
        Filter results that have a due date before the specified date.
    .PARAMETER Priority
        Filter results that have a specific case priority (1-5)
    .PARAMETER StatusNumber
        Filter cases by the provided status. You can specify
        one or more status numbers or names. When filtering for multiple
        Status, pass the parameter values as an array.
    .PARAMETER Owners
        Filter cases owned by one or more users. You can specify
        one or more [LrUser].number integers, or provide the names of
        the Owners to use. When filtering for multiple Owners, pass the
        parameter values as an array.
    .PARAMETER Collaborator
        Filter cases that have the specified Collaborator user. You can
        provide either the LrUser number or name, and only one collaborator
        can be included.
    .PARAMETER Tags
        Filter cases that include one or more tags, identified by tag number or name.
        Multiple tags should be provided in an array.
    .PARAMETER ExcludeTags
        Filter out cases that include one or more tags, identified by tag number or name.
        Multiple tags should be provided in an array.
    .PARAMETER Text
        Filter results that have a case number or name that contains the specified value.
    .PARAMETER EvidenceType
        Filter results that have evidence of the specified type:

        'alarm'
        'userEvents'
        'log'
        'note'
        'file'
    .PARAMETER UpdatedAfter
        Filter results that were updated after the specified date.
    .PARAMETER UpdatedBefore
        Filter results that were updated before the specified date.
    .PARAMETER CreatedAfter
        Filter results that were created after the specified date.
    .PARAMETER CreatedBefore
        Filter results that were created before the specified date.
    .PARAMETER OrderBy
        Sorts the returned results by the specified field:

        'dateCreated'
        'dateClosed'
        'dateUpdated'
        'name'
        'number'
        'priority'
        'dueDate'
        'age'
        'statusNumber'
    .PARAMETER Sort
        Sort the results in ascending (asc) or descending (desc) order.
    .PARAMETER Count
        Maximum number of results to be returned (default 500)
    .PARAMETER Exact
        Forces the name parameter to be exact matches only for returned results.
    .INPUTS
        None
    .OUTPUTS
        ==================================================
        [PSCustomObject] (LrCase)
        ==================================================
        id                      : [System.String] (guid)
        number                  : [System.Int32]
        externalId              : <always null>
        dateCreated             : [System.DateTime]
        dateUpdated             : [System.DateTime]
        dateClosed              : [System.DateTime]
        owner                   : PSCustomObject (LrUser)
        lastUpdatedBy           : PSCustomObject (LrUser)
        name                    : [System.String]
        status                  : PSCustomObject (LrStatus)
        priority                : [System.Int32]
        dueDate                 : [System.DateTime]
        resolution              : [System.String]
        resolutionDateUpdated   : [System.String]
        resolutionLastUpdatedBy : PSCustomObject (LrUser)
        summary                 : [System.String]
        entity                  : PSCustomObject (LrEntity)
        collaborators           : PSCustomObject (LrUser)
        tags                    : PSCustomObject (LrTag)
    .EXAMPLE
        PS C:\> Get-LrCases -Tags ("Malware","Server Reboot") -Verbose
        ---
        Get all cases containing the tags Malware or Server Reboot
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

        [Parameter(Mandatory = $false, Position = 16)]
        [switch] $Summary,

        [Parameter(Mandatory = $false, Position = 17)]
        [switch] $Exact,

        [Parameter(Mandatory = $false, Position = 18)]
        [string] $Name,

        #region: Query Parameters ___________________________________________________________
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [datetime] $DueBefore,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(1,5)]
        [int[]] $Priority,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [string[]] $Status,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [string[]] $Owners,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [string] $Collaborator,


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [string[]] $Tags,


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [string[]] $ExcludeTags,


        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNull()]
        [string] $Text,


        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateSet("alarm","userEvents","log","note","file")]
        [string[]] $EvidenceType,
        #endregion



        #region: Header Parameters___________________________________________________________
        [Parameter(Mandatory = $false, Position = 9)]
        [DateTime] $UpdatedAfter,


        [Parameter(Mandatory = $false, Position = 10)]
        [DateTime] $UpdatedBefore,


        [Parameter(Mandatory = $false,Position = 11)]
        [DateTime] $CreatedAfter,


        [Parameter(Mandatory = $false,Position = 12)]
        [DateTime] $CreatedBefore,


        [Parameter(Mandatory = $false,Position = 13)]
        [ValidateSet(
            "dateCreated",
            "dateClosed",
            "dateUpdated",
            "name",
            "number",
            "priority",
            "dueDate",
            "age",
            "statusNumber"
            )]
        [string] $OrderBy = "dateCreated",


        [Parameter(Mandatory = $false,Position = 14)]
        [ValidateSet("asc","desc")]
        [string] $Sort = "asc",


        [Parameter(Mandatory = $false, Position = 15)]
        [int] $Count = 500

    )
        #endregion



    #region: Setup_______________________________________________________________________
    $Me = $MyInvocation.MyCommand.Name

    $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
    $Token = $Credential.GetNetworkCredential().Password

    # Enable self-signed certificates and Tls1.2
    Enable-TrustAllCertsPolicy
    #endregion



    #region: Process Query Parameters____________________________________________________
    $QueryParams = [Dictionary[string,string]]::new()

    # DueBefore
    if ($DueBefore) {
        $_dueBefore = $DueBefore | ConvertTo-Rfc3339
        $QueryParams.Add("dueBefore", $_dueBefore)
    }


    # Priority
    if ($Priority) {
        if ($Priority.Count -gt 1) {
            $_priority = $Priority -join ','
        } else {
            $_priority = $Priority
        }
        $QueryParams.Add("priority", $_priority)
    }


    # Status
    if ($Status) {
        $_statusNumbers = $Status | ConvertTo-LrCaseStatusId
        if (! $_statusNumbers) {
            throw [ArgumentException] "Status in [$Status] not found."
        }
        if ($_statusNumbers.count -gt 1) {
            $_status = $_statusNumbers -join ','
        } else {
            $_status = $_statusNumbers
        }
        $QueryParams.Add("statusNumber", $_status)
    }


    # Owner
    if ($Owners) {
        $_ownerNumbers = $Owners | Get-LrUserNumber
        if (! $_ownerNumbers) {
            throw [ArgumentException] "Owner(s) [$Owners] not found."
        }
        if ($_ownerNumbers.count -gt 1) {
            $_owner = $_ownerNumbers -join ','
        } else {
            $_owner = $_ownerNumbers
        }
        $QueryParams.Add("ownerNumber", $_owner)
    }


    # Collaborator
    if ($Collaborator) {
        $_collabNumber = $Collaborator | Get-LrUserNumber
        if ($_collabNumber) {
            $QueryParams.Add("collaboratorNumber", $_collabNumber)
        } else {
            throw [ArgumentException] "Collaborator [$Collaborator] not found."
        }
    }


    # Tags  (Exclude Tags are removed from the final result)
    if ($Tags) {
        $_tagNumbers = $Tags | Get-LrTagNumber
        if (! $_tagNumbers) {
            throw [ArgumentException] "Tag(s) $Tags not found."
        }
        if ($_tagNumbers.count -gt 1) {
            $_tags = $_tagNumbers -join ','
        } else {
            $_tags = $_tagNumbers
        }
        $QueryParams.Add("tagNumber", $_tags)
    }


    # Text
    if ($Text) {
        # should we uri-encode this?
        $QueryParams.Add("text", $Text)
    }


    # EvidenceType
    if ($EvidenceType) {
        if ($EvidenceType.Count -gt 1) {
            $EvidenceType = $EvidenceType -join ','
        }
        $QueryParams.Add("evidenceType", $EvidenceType)
    }

    if ($QueryParams.Count -gt 0) {
        $QueryString = $QueryParams | ConvertTo-QueryString
        Write-Verbose "[$Me]: QueryString is [$QueryString]"
    }
    #endregion



    #region: Process Request Headers_____________________________________________________
    $Headers = [Dictionary[string,string]]::new()
    $Headers.Add("Authorization", "Bearer $Token")
    $Headers.Add("count", $Count)
    $Headers.Add("direction", $Sort)

    # Update / Create DateTimes
    if ($UpdatedAfter) {
        $_updatedAfter = $UpdatedAfter | ConvertTo-Rfc3339
        $Headers.Add("updatedAfter", $_updatedAfter)
    }
    if ($UpdatedBefore) {
        $_updatedBefore = $UpdatedBefore | ConvertTo-Rfc3339
        $Headers.Add("updatedBefore", $_updatedBefore)
    }
    if ($CreatedAfter) {
        $_createdAfter = $CreatedAfter | ConvertTo-Rfc3339
        $Headers.Add("createdAfter", $_createdAfter)
    }
    if ($CreatedBefore) {
        $_createdBefore = $CreatedBefore | ConvertTo-Rfc3339
        $Headers.Add("createdBefore", $_createdBefore)
    }
    #endregion



    #region: Send RequestHeaders_________________________________________________________
    # Request URI
    $Method = $HttpMethod.Get
    $RequestUrl = $BaseUrl + "/cases/" + $QueryString


    # REQUEST
    if ($PSEdition -eq 'Core'){
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }
    } else {
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }
    }

    # For Summary, return a formatted report
    if ($Summary) {
        return Format-LrCaseListSummary -InputObject $Response
    }


    # Exclude Tags
    if ($ExcludeTags -and $Response) {
        $FilteredResult = [List[Object]]::new()

        # Check every case
        foreach ($case in $Response) {
            $Exclude = $false
            # Inspect each case's tags
            foreach ($tag in $case.tags) {
                # Check each case tag against Excluded Tags
                foreach ($excludedTag in $ExcludeTags) {
                    if ($tag.text -eq $excludedTag) {
                        Write-Verbose "Excluding Case $($case.number) because it contains tag $excludedTag."
                        $Exclude = $true
                    }
                }
            }
            if (-not $Exclude) {
                $FilteredResult.Add($case)
            }
        }
        # Return filtered result
        return $FilteredResult
    }
    #endregion

    if ($Exact) {
        if ($FilteredResult) {
            $Pattern = "^$Name$"
            $FilteredResult | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        } else {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        }
    } elseif ($Name) {
        if ($FilteredResult) {
            $Pattern = ".*$Name.*"
            $FilteredResult | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        } else {
            $Pattern = ".*$Name.*"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        }
    } else {
        if ($FilteredResult) {
            return $FilteredResult
        } else {
            return $Response
        }
    }
}