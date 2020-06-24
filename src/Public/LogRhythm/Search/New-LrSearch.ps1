using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrSearch {
    <#
    .SYNOPSIS
        Initiate a search in the LogRhythm SIEM environment.  Requires LogRhythm 7.5.0+.
    .DESCRIPTION
        Create-LrNetwork returns a full LogRhythm Host object, including details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Entity
        Parameter for specifying the existing LogRhythm Entity for the new Network record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Network object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Network Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Name
        [System.String] Parameter for specifying a new network name.  
        
        *If the Id parameter is not provided the Name paramater will be attempted to identify the appropraite record.
    .PARAMETER ShortDescription
        A brief description of the network entity.
    .PARAMETER LongDescription
        An extended description of the network entity.
    .PARAMETER RiskLevel
        Designated network segment Risk Level.

        Valid entries: "None" "Low-Low" "Low-Medium" "Low-High" "Medium-Low" "Medium-Medium" "Medium-High" "High-Low" "High-Medium" "High-High"
    .PARAMETER ThreatLevel
        Designated network segment Threat Level.

        Valid entries: "None" "Low-Low" "Low-Medium" "Low-High" "Medium-Low" "Medium-Medium" "Medium-High" "High-Low" "High-Medium" "High-High"

    .INPUTS
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
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
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [int32]$MaxMsgsToQuery = 100,

        [Parameter(Mandatory = $false, Position = 2)]
        [int32]$QueryTimeout = 300,

        [Parameter(Mandatory = $false,  Position = 3)]
        [bool]$QueryRawLog = $true,

        [Parameter(Mandatory = $false,  Position = 3)]
        [bool]$QueryEventManager = $true,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('maxn','paged','pagedsorteddateasc','pagedsorteddatedesc', 'pagedsortedriskasc', 'pagedsortedriskdesc', ignorecase=$true)]
        [string]$SearchMode = "pagedSortedDateAsc",

        [Parameter(Mandatory = $false,  Position = 6)]
        [string]$SearchServerIPAddress = $LrtConfig.LogRhythm.DataIndexerIP,

        [Parameter(Mandatory = $false, Position = 7)]
        [string]$DateCriteria,

        [Parameter(Mandatory = $false, Position = 8)]
        [datetime]$DateMin,

        [Parameter(Mandatory = $false, Position = 9)]
        [datetime]$DateMax,

        [Parameter(Mandatory = $false, Position = 10)]
        [int32]$LastIntervalValue = 1,

        [Parameter(Mandatory = $false, Position = 11)]
        [ValidateSet('year','quarter','month','dayofyear', 'day', 'weekofyear', 'weekday', 'hour', 'minute', 'second', ignorecase=$true)]
        [string]$LastIntervalUnit = "Month",
        
        [Parameter(Mandatory = $false, Position = 12)]
        [string]$LogSource = "",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('flatlegacy','grouped', ignorecase=$true)]
        [string]$MsgFilterType = "grouped",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('filter','group', 'polylist', ignorecase=$true)]
        [string]$GroupFilterItemType = "group",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string]$GroupFilterOperator = "",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string]$GroupFilterMode = "",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('and','or', ignorecase=$true)]
        [string]$GroupFilterGroupOperator = "",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('simple','group', ignorecase=$true)]
        [string]$ItemFilterItemType = "simple",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string]$ItemFilterFieldOperator = "none",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string]$ItemFilterMode = "filterin",

        [Parameter(Mandatory = $false, Position = 12)]
        [string]$Param1MetaField = "User (Origin or Impacted)",

        [Parameter(Mandatory = $false, Position = 12)]
        [string]$Param1Value = "administrator",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string]$Param1Operator = "none",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('value' ,'SQLPattern' ,'Regex', ignorecase=$true)]
        [string]$Param1MatchType = "value",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string]$Param1FilterType = "filterin",

        [Parameter(Mandatory = $false, Position = 12)]
        [string]$Param2MetaField = "User (Origin or Impacted)",

        [Parameter(Mandatory = $false, Position = 12)]
        [string]$Param2Value = $null,

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string]$Param2Operator = "none",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('value' ,'SQLPattern' ,'Regex', ignorecase=$true)]
        [string]$Param2MatchType = "value",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string]$Param2FilterType = "filterin",

        [Parameter(Mandatory = $false, Position = 12)]
        [string]$Param3MetaField = "User (Origin or Impacted)",

        [Parameter(Mandatory = $false, Position = 12)]
        [string]$Param3Value = $null,

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('none','and', 'or', 'andprevious', 'orprevious',ignorecase=$true)]
        [string]$Param3Operator = "none",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('value' ,'SQLPattern' ,'Regex', ignorecase=$true)]
        [string]$Param3MatchType = "value",

        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateSet('filterin','filterout', ignorecase=$true)]
        [string]$Param3FilterType = "filterin"
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.SearchBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Value Testing Paramater
        $_int = 0
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            ResponseUrl           =   $null
            Value                 =   $Name
        }

        if ($LogSource) {
            # Check if LogSource value is an integer
            if ([int]::TryParse($LogSource, [ref]$_int)) {
                Write-Verbose "[$Me]: Id parses as integer."
                $_logSource = $Id
            } else {
                Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                $LogSourceLookup = Get-LrLogSources -Name $LogSource -Exact
                if ($LogSourceLookup.Error -eq $true) {
                    $ErrorObject.Error = $LogSourceLookup.Error
                    $ErrorObject.Type = $LogSourceLookup.Type
                    $ErrorObject.Code = $LogSourceLookup.Code
                    $ErrorObject.Note = $LogSourceLookup.Note
                    return $ErrorObject
                } else {
                    $_logSource = $LogSourceLookup | Select-Object -ExpandProperty id
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
            default {$_searchMode = 2}
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
            default {$_groupFilterItemType = 1}
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
            filterin {$_groupFilterMode = 0}
            filterout {$_groupFilterMode = 1}
            default {$_groupFilterMode = 0}
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
                $_param1FilterType = $Param1Results.id
                $_param1ValueType = $Param1Results.ValueTypeEnum
                $_param1ValueName = $Param1Results.DisplayName
            }
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

        if ($ItemFilterMatchType) {
            value {$_itemFilterMatchType = 0}
            sqlpattern {$_itemFilterMatchType = 1}
            regex {$_itemFilterMatchType = 2}
            default {$_itemFilterMatchType = 0}
        }


        # Second Filter Item

        #Date Format: 2020-04-01T06:00:00Z

        <#
         "filterGroup":{  -- A filter group will be created even if there is only one filter, either it contains group filters or not        

         "filterItemType":1,  -- Filter = 0 ; Group = 1; PolyList = 2 
         "fieldOperator":1, -- None = 0; [And] = 1 ; [Or] = 2 ; AndPrevious = 3; OrPrevious = 4
         "filterMode":1, -- FilterIn = 1; FilterOut = 2
         "filterGroupOperator":0, -- And = 0; Or = 1 Note that the Operator is 0; means AND condition will be applied to all filter items
         "filterItems":[ 

            {

FIRST FILTER ITEM GOES HERE:

               "filterItemType":0, Note that filterItemType is 0; means this is not a group filter; Simple Filter
               "fieldOperator":0, Note that filterOperator is 0; means this does not apply any condition, AND condition will be applied according to above filterGroup level
               "filterMode":1,  -- FilterIn
               "filterType":29, -- The value of this filterType can be referred from FieldFilterTypeEnum
               "values":[                   

                    { 

                     "filterType":29, -- The value of this filterType can be referred from FieldFilterTypeEnum
                     "valueType":4, -- The value of this valueType can be referred from FieldFilterValueTypeEnum
                     "value":{ 
                        "value":"user origin value",   --User supplied value
                        "matchType":0  -- Value = 0; SQLPattern = 1; Regex = 2
                      },
                     "displayValue":"user origin value" --User supplied value
                   }
                ],
               "name":"User (Origin)"
             },
        #>

        # Establish Body Contents
        $BodyContents = [PSCustomObject]@{
            maxMsgsToQuery = $MaxMsgsToQuery
            queryTimeout = $QueryTimeout
            queryRawLog = $_queryRawLog
            searchMode = $_searchMode
            searchServerIPAddress = $SearchServerIPAddress
            dateCriteria = @{
                useInsertedDate = "false"
                lastIntervalValue = $LastIntervalValue
                lastIntervalUnit = $_lastIntervalUnit
            }
            queryLogSources = @()
            queryFilter = @{
                msgFilterType = $_msgFilterType
                isSavedFilter = "false"
                filterGroup = @{
                    filterItemType = $_groupFilterItemType
                    fieldOperator = $_itemFilterFieldOperator
                    filterMode = $_groupFilterMode
                    filterGroupOperator = $_groupFilterOperator
                    filterItems = @( @{
                        filterItemType = 0
                        fieldOperator = 0
                        filterMode = 1
                        filterType = 29
                        values = @(@{
                            filterType = 29
                            valueType = 4
                            value = @{
                                value = "administrator"
                                matchType = 0
                            }
                            displayValue = "administrator"
                        })
                        name = "User (Origin)"
                    })
                }
            }
        } | ConvertTo-Json -Depth 7

        Write-Verbose $BodyContents


        # Define Query URL
        $RequestUrl = $BaseUrl + "/actions/search-task"

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
                return $ErrorObject
            }
        }
        
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            return $Err
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.Exception.Response.StatusCode.value__)
            $ErrorObject.Note = $($Err.Exception.Response.StatusDescription)
            $ErrorObject.ResponseUrl = $($Err.Exception.Response.ResponseUrl)
            return $ErrorObject
        }
        #>
        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($Exact) {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        } else {
            return $Response
        }
    }

    End { 
    }

}