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
        Filter results that have a case number or name that contains the specified value.  
        
        Exact match available via -exact switch.
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
    .PARAMETER Direction
        Direction the results in ascending (asc) or descending (desc) order.
    .PARAMETER Count
        Maximum number of results to be returned (default 500)
    .PARAMETER Exact
        Forces the name parameter to be exact matches only for returned results.
    .PARAMETER Metrics
        Include case metrics in each case returned by Get-LrCases.
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
        PS C:\> Get-LrCases -tags alpha

        id                      : 56C2007B-4E8D-41C8-95C8-4F91346EC727
        number                  : 1
        externalId              :
        dateCreated             : 2020-07-16T16:46:48.3522746Z
        dateUpdated             : 2020-07-16T16:53:46.0262639Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Alpha Case
        status                  : @{name=Created; number=1}
        priority                : 4
        dueDate                 : 2020-07-17T16:46:48.3362732Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Alpha case is the first case created through API.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {@{number=2; text=Alpha}}

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T16:56:27.8545625Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Mock case
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-10-20T14:22:11Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Mock case summary for automation validation.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {@{number=2; text=Alpha}}
    .EXAMPLE
        PS C:\> Get-LrCases -Name "Mock"

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T16:56:27.8545625Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Mock case
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-10-20T14:22:11Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Mock case summary for automation validation.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {@{number=2; text=Alpha}}
    .EXAMPLE
        PS C:\> Get-LrCases -Name "Mock" -Exact
        
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
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

        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateSet("all","any")]
        [string] $TagSearchMode,


        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNull()]
        [string[]] $ExcludeTags,


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
        [string] $Direction = "asc",


        [Parameter(Mandatory = $false, Position = 15)]
        [switch] $Summary,


        [Parameter(Mandatory = $false, Position = 16)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 17)]
        [switch] $Metrics,


        [Parameter(Mandatory = $false, Position = 18)]
        [int] $Count = 500,


        [Parameter(Mandatory = $false, Position = 19)]
        [int] $PageNumber = 1,


        [Parameter(Mandatory = $false, Position = 20)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )
        #endregion
    Begin {
        #region: Setup_______________________________________________________________________
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        #region: Process Request Headers_____________________________________________________
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")
        $Headers.Add("count", $Count)

        # Page requested via Offset for Results from API
        if ($PageNumber) {
            $Offset = ($PageNumber -1) * $Count
            $Headers.Add("offset", $Offset)
        }

        $Headers.Add("direction", $Direction)

        # HTTP Method
        $Method = $HttpMethod.Get

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
        #endregion
    }


    Process {
        # Define ErrorObject
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

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
                $ErrorObject.Error = $true
                $ErrorObject.Type = "User not found."
                $ErrorObject.Code = 404
                $ErrorObject.Note = "Owner(s) [$Owners] not found."
                return $ErrorObject
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
                $ErrorObject.Error = $true
                $ErrorObject.Type = "User not found."
                $ErrorObject.Code = 404
                $ErrorObject.Note = "Collaborator [$Collaborator] not found."
                return $ErrorObject
            }
        }


        # Tags  (Exclude Tags are removed from the final result)
        if ($Tags) {
            $_tagNumbers = [list[string]]::new()
            # With TagSearchMode All, all tags must exist in order to be able to return results.
            # If a tag requested does not exist, return the request with an error for missing tag.
            switch ($TagSearchMode) {
                "all" {
                    ForEach ($Tag in $Tags) {
                        $TagResults = $Tag | Get-LrTagNumber
                        if ($TagResults) {
                            if ($_tagNumbers -notcontains $TagResults) {
                                $_tagNumbers.add($TagResults)
                            }
                        } else {
                            $ErrorObject.Error = $true
                            $ErrorObject.Type = "Tag not found."
                            $ErrorObject.Code = 404
                            $ErrorObject.Note = "Tag [$Tag] not found."
                            return $ErrorObject
                        }
                        Start-Sleep 0.1
                    }
                }
                "any" {
                    ForEach ($Tag in $Tags) {
                        $TagResults = $Tag | Get-LrTagNumber
                        if ($TagResults) {
                            if ($_tagNumbers -notcontains $TagResults) {
                                $_tagNumbers.add($TagResults)
                            }
                        }
                        Start-Sleep 0.1
                    }
                    if ($null -eq $TagResults -or $TagResults.count -eq 0) {
                        $ErrorObject.Error = $true
                        $ErrorObject.Type = "Tag not found."
                        $ErrorObject.Code = 404
                        $ErrorObject.Note = "Tags $([string]::Join(', ', $Tags)) not found."
                        return $ErrorObject
                    }
                }
                default {
                    ForEach ($Tag in $Tags) {
                        $TagResults = $Tag | Get-LrTagNumber
                        if ($TagResults) {
                            if ($_tagNumbers -notcontains $TagResults) {
                                $_tagNumbers.add($TagResults)
                            }
                        }
                        Start-Sleep 0.1
                    }
                }
            }

            if ($_tagNumbers.count -gt 1) {
                $_tags = $_tagNumbers -join ','
            } else {
                $_tags = $_tagNumbers
            }

            $QueryParams.Add("tagNumber", $_tags)
        }


        # Name
        if ($Name) {
            # should we uri-encode this?
            $QueryParams.Add("text", $Name)
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
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/" + $QueryString

        # REQUEST
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        # Pagination
        if ($Response.Count -eq $Count) {
            DO {
                Start-Sleep 0.1
                # Increment Page Count / Offset
                $PageNumber = $PageNumber + 1
                $Offset = ($PageNumber -1) * $Count
                # Update Header Pagination Paramater
                $Headers.offset = $Offset
                
                # Retrieve Query Results
                try {
                    $PaginationResults = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
                } catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Code = $($Err.statusCode)
                    $ErrorObject.Note = $($Err.message)
                    $ErrorObject.Raw = $_
                    return $ErrorObject
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $Count)
        }
    }

    End {
        # Set the case results into List form to support manipulation
        $Results = [List[Object]]::new()
        ForEach ($CaseResult in $Response) {
            $Results.add($CaseResult) | Out-Null
        }

        # Exclude Tags
        if ($ExcludeTags -and $Response) {
            $FilterResults = [List[Object]]::new()

            # Check every case
            foreach ($Case in $Results) {
                $Exclude = $false
                
                # Inspect each case's tags
                ForEach ($tag in $Case.tags) {
                    # Check each case tag against Excluded Tags
                    ForEach ($excludedTag in $ExcludeTags) {
                        If ($tag.text -like $excludedTag) {
                            Write-Verbose "Excluding Case $($case.number) because it contains tag $excludedTag."
                            $Exclude = $true
                        }
                    }
                }
                # Add excluded case to FilterResults for removal
                if ($Exclude) {
                    $FilterResults.Add($Case) | Out-Null
                }
            }

            # Iterate through FilterResults to remove from Results
            ForEach ($FilterResult in $FilterResults) {
                $Results.remove($FilterResult) | Out-Null
            }
        }
        #endregion

        if ($TagSearchMode -like "all" -and $Tags) {
            $FilterResults = [List[object]]::new()
            # Check every case
            foreach ($Case in $Results) {
                $Exclude = $false
                
                # Inspect each case's tags
                foreach ($_tag in $_tagNumbers) {
                    if ($case.tags.number -notcontains $_tag) {
                        Write-Verbose "Case #: $($Case.number) Mising Tag #: $_tag"
                        $Exclude = $true
                    }
                }


                if ($Exclude -eq $true) {
                    $FilterResults.add($case) | Out-Null
                }
            }

            # Iterate through FilterResults to remove from Results
            ForEach ($FilterResult in $FilterResults) {
                $Results.remove($FilterResult) | Out-Null
            }
        }

        if ($TagSearchMode -like "any" -and $Tags) {
            $FilterResults = [List[object]]::new()
            # Check every case
            foreach ($Case in $Results) {
                $Include = $false
                
                # Inspect each case's tags
                foreach ($_tag in $_tagNumbers) {
                    if ($case.tags.number -contains $_tag) {
                        Write-Verbose "Case #: $($Case.number) Tag #: $_tag"
                        $Include = $true
                    }
                }

                if ($Include -eq $true) {
                    if ($FilterResults -notcontains $case) {
                        $FilterResults.add($case) | Out-Null
                    }
                }
            }

            # Iterate through FilterResults to remove from Results
            if ($FilterResults.count -ge 1) {
                $Results = $FilterResults
            } else {
                return $null
            }
            
        }

        # For Summary, return a formatted report
        if ($Summary) {
            return Format-LrCaseListSummary -InputObject $Results
        }

        #region: Return Results                                                                        
        # [Exact Match] - return a single result based on exact name
        if ($Exact) {
            $Pattern = "^$Name$"
            # LogRhythm allows multiple cases to share the same exact name - find all the exact
            # matches, add to collection, and warn if there are more than one.
            $ExactCaseMatches = [List[object]]::New()

            # [Exact Match] - Filtered Results
            $Results | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact case name match found: $($_.Name)"
                    $ExactCaseMatches.Add($_) | Out-Null
                }
            }

            # [Exact Match] - Get Metrics if requested
            if ($Metrics) {
                if ($ExactCaseMatches[0]) {
                    $_metrics = $ExactCaseMatches[0] | Get-LrCaseMetrics    
                    $ExactCaseMatches[0] | Add-Member -MemberType NoteProperty -Name "Metrics" -Value $_metrics
                } 
            }

            # [Exact Match] - Check Result Count
            if ($ExactCaseMatches.Count -gt 1) {
                Write-Warning "More than one case found matching exact name: $Name"
                Write-Warning "Only the first result will be returned"
            }
            return $ExactCaseMatches[0]
            
        # [Name Match] - return one or more resuls based on partial name match
        } elseif ($Name) {
            $Pattern = ".*$Name.*"
            $CaseMatches = [List[object]]::New()

            # [Name Match]
            $Results | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -like $Name)) {
                    # [Name Match] - Get Metrics if requested
                    if ($Metrics) {
                        $_metrics = $_ | Get-LrCaseMetrics    
                        $_ | Add-Member -MemberType NoteProperty -Name "Metrics" -Value $_metrics -Force
                    }
                    $CaseMatches.Add($_) | Out-Null
                }
            }

            return $CaseMatches
        # [Default] - return all results
        } else {
            if ($Metrics) {
                $Response | ForEach-Object {
                    $_metrics = $_ | Get-LrCaseMetrics
                    $_ | Add-Member -MemberType NoteProperty -Name "Metrics" -Value $_metrics -Force
                }
            }
            return $Results
        }
    }
    #endregion
}