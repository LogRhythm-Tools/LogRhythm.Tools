using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrSearch {
    <#
    .SYNOPSIS
        Initiate a search in the LogRhythm SIEM environment.  Requires LogRhythm 7.5.0+.
    .DESCRIPTION
        New-LrSearch initiates a new search request.

        To retrieve search results reference cmdlet: Get-LrSearchResults.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER MaxMsgsToQuery
        Cmdlet currently under development.
    .PARAMETER QueryTimeout
        Cmdlet currently under development.
    .PARAMETER QueryRawLog
        Cmdlet currently under development.
    .PARAMETER QueryEventManager
        Cmdlet currently under development.
    .PARAMETER SearchMode
        Cmdlet currently under development.
    .PARAMETER SearchServerIPAddress
        Cmdlet currently under development.
    .PARAMETER DateCriteria
        Cmdlet currently under development.
    .PARAMETER DateMin
        Cmdlet currently under development.
    .PARAMETER DateMax
        Cmdlet currently under development.
    .PARAMETER LastIntervalValue
        Cmdlet currently under development.
    .PARAMETER LastIntervalUnit
        Cmdlet currently under development.
    .PARAMETER LogSource
        Cmdlet currently under development.
    .PARAMETER MsgFilterType
        Cmdlet currently under development.
    .PARAMETER GroupFilterItemType
        Cmdlet currently under development.
    .PARAMETER GroupFilterOperator
        Cmdlet currently under development.
    .PARAMETER GroupFilterMode
        Cmdlet currently under development.
    .PARAMETER GroupFilterGroupOperator
        Cmdlet currently under development.
    .PARAMETER ItemFilterItemType
        Cmdlet currently under development.
    .PARAMETER ItemFilterFieldOperator
        Cmdlet currently under development.
    .PARAMETER ItemFilterMode
        Cmdlet currently under development.
    .PARAMETER Param1MetaField
        Cmdlet currently under development.
    .PARAMETER Param1Value
        Cmdlet currently under development.
    .PARAMETER Param1Operator
        Cmdlet currently under development.
    .PARAMETER Param1MatchType
        Cmdlet currently under development.
    .PARAMETER Param1FilterType
        Cmdlet currently under development.
    .PARAMETER Param2MetaField
        Cmdlet currently under development.
    .PARAMETER Param2Value
        Cmdlet currently under development.
    .PARAMETER Param2Operator
        Cmdlet currently under development.
    .PARAMETER Param2MatchType
        Cmdlet currently under development.
    .PARAMETER Param2FilterType
        Cmdlet currently under development.
    .PARAMETER Param3MetaField
        Cmdlet currently under development.
    .PARAMETER Param3Value
        Cmdlet currently under development.
    .PARAMETER Param3Operator
        Cmdlet currently under development.
    .PARAMETER Param3MatchType
        Cmdlet currently under development.
    .PARAMETER Param3FilterType
        Cmdlet currently under development.
    .INPUTS
        None
    .OUTPUTS
        PSCustomObject representing the new search task, its status, and the associated TaskId used to retrieve results.
    .EXAMPLE
        PS C:\> New-LrSearch
        ----
        StatusCode      : 200
        StatusMessage   : Success
        ResponseMessage : Success
        TaskStatus      : Searching
        TaskId          : efaa62ab-84ed-4d9e-96a9-c280973c3307
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [int32] $MaxMsgsToQuery = 100,


        [Parameter(Mandatory = $false, Position = 1)]
        [int32] $QueryTimeout = 300,


        [Parameter(Mandatory = $false,  Position = 2)]
        [bool] $QueryRawLog = $true,


        [Parameter(Mandatory = $false,  Position = 3)]
        [bool] $QueryEventManager = $true,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('maxn','paged','pagedsorteddateasc','pagedsorteddatedesc', 'pagedsortedriskasc', 'pagedsortedriskdesc', ignorecase=$true)]
        [string] $SearchMode = "pagedSortedDateAsc",


        [Parameter(Mandatory = $false,  Position = 5)]
        [string] $SearchServerIPAddress = $LrtConfig.LogRhythm.DataIndexerIP,


        [Parameter(Mandatory = $false, Position = 6)]
        [string] $DateCriteria,


        [Parameter(Mandatory = $false, Position = 7)]
        [datetime] $DateMin,


        [Parameter(Mandatory = $false, Position = 8)]
        [datetime] $DateMax,


        [Parameter(Mandatory = $false, Position = 9)]
        [int32] $LastIntervalValue = 1,


        [Parameter(Mandatory = $false, Position = 10)]
        [ValidateSet('year','quarter','month','dayofyear', 'day', 'weekofyear', 'weekday', 'hour', 'minute', 'second', ignorecase=$true)]
        [string] $LastIntervalUnit = "Month",
        

        [Parameter(Mandatory = $false, Position = 11)]
        [string[]] $LogSources = "",


        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('flatlegacy','grouped', ignorecase=$true)]
        [string] $MsgFilterType = "grouped",


        [Parameter(Mandatory = $false, Position = 13)]
        [ValidateSet('filter','group', 'polylist', ignorecase=$true)]
        [string] $GroupFilterItemType = "group",


        [Parameter(Mandatory = $false, Position = 14)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string] $GroupFilterOperator = "",


        [Parameter(Mandatory = $false, Position = 15)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string] $GroupFilterMode = "",


        [Parameter(Mandatory = $false, Position = 16)]
        [ValidateSet('and','or', ignorecase=$true)]
        [string] $GroupFilterGroupOperator = "",


        [Parameter(Mandatory = $false, Position = 17)]
        [ValidateSet('simple','group', ignorecase=$true)]
        [string] $ItemFilterItemType,


        [Parameter(Mandatory = $false, Position = 18)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string] $ItemFilterFieldOperator,


        [Parameter(Mandatory = $false, Position = 19)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string] $ItemFilterMode,


        [Parameter(Mandatory = $false, Position = 20)]
        [string] $Param1MetaField,


        [Parameter(Mandatory = $false, Position = 21)]
        [string] $Param1Value,


        [Parameter(Mandatory = $false, Position = 22)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string] $Param1Operator,


        [Parameter(Mandatory = $false, Position = 23)]
        [ValidateSet('value' ,'SQLPattern' ,'Regex', ignorecase=$true)]
        [string] $Param1MatchType,


        [Parameter(Mandatory = $false, Position = 24)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string] $Param1FilterType,


        [Parameter(Mandatory = $false, Position = 25)]
        [string] $Param2MetaField,


        [Parameter(Mandatory = $false, Position = 26)]
        [string] $Param2Value = $null,


        [Parameter(Mandatory = $false, Position = 27)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string] $Param2Operator,


        [Parameter(Mandatory = $false, Position = 28)]
        [ValidateSet('value' ,'SQLPattern' ,'Regex', ignorecase=$true)]
        [string] $Param2MatchType,


        [Parameter(Mandatory = $false, Position = 29)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string] $Param2FilterType,


        [Parameter(Mandatory = $false, Position = 30)]
        [string] $Param3MetaField,


        [Parameter(Mandatory = $false, Position = 31)]
        [string] $Param3Value = $null,


        [Parameter(Mandatory = $false, Position = 32)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string] $Param3Operator,


        [Parameter(Mandatory = $false, Position = 33)]
        [ValidateSet('value' ,'SQLPattern' ,'Regex', ignorecase=$true)]
        [string] $Param3MatchType,


        [Parameter(Mandatory = $false, Position = 34)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string] $Param3FilterType = "filterin",


        [Parameter(Mandatory = $false, Position = 35)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Value Testing Paramater
        $_int = 0
    }

    Process {
        if ($LogSources) {
            $_logSources = [List[int]]::new()
            ForEach ($LogSource in $LogSources) {
                # Check if LogSource value is an integer
                if ([int]::TryParse($LogSource, [ref]$_int)) {
                    Write-Verbose "[$Me]: Id parses as integer."
                    $_logSources.add($LogSource)
                } else {
                    Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                    $LogSourceLookup = Get-LrLogSources -Name $LogSource -Exact
                    if ($LogSourceLookup.Error -eq $true) {
                        return $LogSourceLookup
                    } else {
                        $_logSources.add($LogSourceLookup.Id)
                    }
                }
            }
        }

        if ($MaxMsgsToQuery -gt 10000) {
            Write-Verbose "$(Get-Timestamp) MaxMsgsToQuery $MaxMsgsToQuery > Maximum Value of 10,000"
            $MaxMsgsToQuery = 10000
            Write-Verbose "$(Get-Timestamp) Set MaxMsgToQuery to Value: 10,000"
        }

        if ($QueryRawLog -eq $true) {
            $_queryRawLog = "true"
        } else {
            $_queryRawLog = "false"
        }

        if ($QueryEventManager -eq $true) {
            $_queryEventManager = "true"
        } else {
            $_queryEventManager = "false"
        }

        Switch ($SearchMode) {
            maxn {$_searchMode = 0}
            paged {$_searchMode = 1}
            pagedsorteddateasc {$_searchMode = 2}
            pagedsorteddatedesc {$_searchMode = 3}
            pagesortedriskasc {$_searchMode = 4}
            pagesortedriskdesc {$_searchMode = 5}
            default {$_searchMode = 0}
        }

        Switch ($LastIntervalUnit) {
            year {$_lastIntervalUnit = 0}
            quarter {$_lastIntervalUnit = 1}
            month {$_lastIntervalUnit = 2}
            dayofyear {$_lastIntervalUnit = 3}
            day {$_lastIntervalUnit = 4}
            weekofyear {$_lastIntervalUnit = 5}
            weekday {$_lastIntervalUnit = 6}
            hour {$_lastIntervalUnit = 7}
            minute {$_lastIntervalUnit = 8}
            second {$_lastIntervalUnit = 9}
            default {$_lastIntervalUnit = 4}
        }

        # Query Filters Section
        Switch ($MsgFilterType) {
            flatlegacy {$_msgFilterType = 1}
            grouped {$_msgFilterType = 2}
            default {$_msgFilterType = 2}
        }

        Switch ($GroupFilterItemType) {
            filter {$_groupFilterItemType = 0}
            group {$_groupFilterItemType = 1}
            polylist {$_groupFilterItemType = 2}
            default {$_groupFilterItemType = 0}
        }

        Switch ($GroupFilterOperator) {
            none {$_groupFilterOperator = 0}
            and {$_groupFilterOperator = 1}
            or {$_groupFilterOperator = 2}
            andprevious {$_groupFilterOperator = 3}
            orprevious {$_groupFilterOperator = 4}
            default {$_groupFilterOperator = 0}
        }

        Switch ($GroupFilterMode) {
            filterin {$_groupFilterMode = 1}
            filterout {$_groupFilterMode = 2}
            default {$_groupFilterMode = 1}
        }

        # First Filter Item
        Switch ($ItemFilterItemType) {
            simple {$_itemFilterItemType = 0}
            group {$_itemFilterItemType = 1}
            default {$_itemFilterItemType = 0}
        }

        Switch ($ItemFilterFieldOperator) {
            none {$_itemFilterFieldOperator = 0}
            and {$_itemFilterFieldOperator = 1}
            or {$_itemFilterFieldOperator = 2}
            andprevious {$_itemFilterFieldOperator = 3}
            orprevious {$_itemFilterFieldOperator = 4}
            default {$_itemFilterFieldOperator = 0}
        }

        Switch ($ItemFilterMode) {
            filterin {$_itemFilterMode = 0}
            filterout {$_itemFilterMode = 1}
            default {$_itemFilterMode = 0}
        }

        Switch ($ItemFilterMatchType) {
            value {$_itemFilterMatchType = 0}
            sqlpattern {$_itemFilterMatchType = 1}
            regex {$_itemFilterMatchType = 2}
            default {$_itemFilterMatchType = 0}
        }

        $_filterItems = [List[Object]]::new()

        # If the MetaField is integer, lookup Metadata fields by ID
        if ($Param1MetaField) {


            if ([int]::TryParse($Param1MetaField, [ref]$_int)) {
                $Param1Results = Test-LrFilterType -Id $Param1MetaField
            } else {
                $Param1Results = Test-LrFilterType -DisplayName $Param1MetaField
                if ($Param1Results.IsValid -eq $false) {
                    $Param1Results = Test-LrFilterType -EnumName $Param1MetaField 
                }
            }
            if ($Param1Results.IsValid -eq $false) {
                Return "Unable to lookup Parameter 1 - Metadata Type: $Param1MetaField"
            } else {
                $FilterItem = [PSCustomObject]@{
                    filterItemType = 0
                    fieldOperator = 0
                    filterMode = 1
                    filterType = $Param1Results.Id
                    values = @([PSCustomObject]@{
                        valueType = $Param1Results.ValueTypeEnum
                        filterType = $Param1Results.Id
                        value =  [PSCustomObject]@{
                            value = $($Param1Value.tolower())
                            matchType = 0
                        }
                        displayValue = $($Param1Value.tolower())
                    })
                    name = $Param1Results.DisplayName
                }
            }
            $_filterItems.Add($FilterItem)
        }

        # If the MetaField is integer, lookup Metadata fields by ID
        if ($Param2MetaField) {
            if ([int]::TryParse($Param2MetaField, [ref]$_int)) {
                $Param2Results = Test-LrFilterType -Id $Param2MetaField
            } else {
                $Param2Results = Test-LrFilterType -DisplayName $Param2MetaField
                if ($Param2Results.IsValid -eq $false) {
                    $Param2Results = Test-LrFilterType -EnumName $Param2MetaField 
                }
            }
            if ($Param2Results.IsValid -eq $false) {
                Return "Unable to lookup Parameter 2 - Metadata Type: $Param2MetaField"
            } else {
                $_param2FilterType = $Param2Results.id
                $_param2ValueType = $Param2Results.ValueTypeEnum
                $_param2ValueName = $Param2Results.DisplayName
            }
        }

        # If the MetaField is integer, lookup Metadata fields by ID
        if ($Param3MetaField) {
            if ([int]::TryParse($Param3MetaField, [ref]$_int)) {
                $Param3Results = Test-LrFilterType -Id $Param3MetaField
            } else {
                $Param3Results = Test-LrFilterType -DisplayName $Param3MetaField
                if ($Param3Results.IsValid -eq $false) {
                    $Param3Results = Test-LrFilterType -EnumName $Param3MetaField 
                }
            }
            if ($Param3Results.IsValid -eq $false) {
                Return "Unable to lookup Parameter 3 - Metadata Type: $Param3MetaField"
            } else {
                $_param3FilterType = $Param1Results.id
                $_param3ValueType = $Param1Results.ValueTypeEnum
                $_param3ValueName = $Param1Results.DisplayName
            }
        }


        if ($ItemFilterType) {
            # Check if LogSource value is an integer
            if ([int]::TryParse($ItemFilterType, [ref]$_int)) {
                Write-Verbose "[$Me]: Id parses as integer."
                $ItemFilterDetails = Test-LrFilterType -Guid $ItemFilterType
            } else {
                $_logSource = $LogSourceLookup | Select-Object -ExpandProperty id
            }
            $_itemFilterType = $ItemFilterDetails.EnumName
            $_itemFilterValueType = $ItemFilterDetails.ValueType
            $_itemFilterName = $ItemFilterDetails.DisplayName
        }


#            searchServerIPAddress = $SearchServerIPAddress
        # Establish Body Contents
        $Body = [PSCustomObject]@{
            maxMsgsToQuery = $MaxMsgsToQuery
            queryTimeout = $QueryTimeout
            queryRawLog = $_queryRawLog
            searchMode = $_searchMode
            dateCriteria = @{
                useInsertedDate = "false"
                lastIntervalValue = $LastIntervalValue
                lastIntervalUnit = $_lastIntervalUnit
            }
            queryLogSources = $_logSources
            queryFilter = @{
                msgFilterType = $_msgFilterType
                isSavedFilter = "false"
                filterGroup = [pscustomobject]@{
                    filterItemType = 1
                    fieldOperator = 1
                    filterGroupOperator = 0
                    filterItems = $_filterItems
                }
            }
        } | ConvertTo-Json -Depth 7

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-search-api/actions/search-task"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        return $Response
    }

    End { 
    }

}