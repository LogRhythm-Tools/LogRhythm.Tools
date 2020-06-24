using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrAgentLogSources {
    <#
    .SYNOPSIS
        Retrieve the Log Source details from a LogRhythm System Monitor agent.
    .DESCRIPTION
        Get-LrHostLogSources returns all log sources for an Agent, including retired log sources, unless filtered out.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [System.String] (Name or Int)
        Specifies a LogRhythm system monitor agent object by providing one of the following property values:
          + List Name (as System.String), e.g. "MYSECRETAGENT"
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER OrderBy
        Sorts records by name or Id.
    .PARAMETER Direction
        Sorts records by ascending or descending.

        Valid values: "asc" "desc"
    .PARAMETER Name
        String used to search Entity Host records by Name.
    .PARAMETER MessageSourceTypeId
        Filters results for a specific Message Source Type Id in resources.
    .PARAMETER Virtual
        Filters results by whether the resources is virtual.

        Valid values: true, false
    .PARAMETER LoadBalanced
        Filters results by load balanced status of component.

        Valid values: true, false
    .PARAMETER Exact
        Filter name results with explicit match.
    .OUTPUTS
        PSCustomObject representing LogRhythm Agent Log Sources record and its contents.
    .EXAMPLE
        PS C:\> Get-LrAgentLogSources -Id WIN-A10PJE5DII3
        ---
        id                       : 10
        systemMonitorId          : 2
        name                     : LogrhythmDXMonitor
        host                     : @{id=2; name=WINdows-A10PJE5DII3.brew.bad}
        entity                   : @{id=1; name=Primary Site}
        logSourceType            : @{id=1000648; name=Flat File - LogRhythm Data Indexer Monitor}
        mpePolicy                : @{id=-1000648; name=LogRhythm Default}
        trueSourcePolicy         :
        recordStatus             : Active
        status                   : Enabled
        isVirtual                : False
        logMartMode              : 13627389
        isLoadBalanced           : False
        mpeProcessingMode        : EventForwardingEnabled
        isArchivingEnabled       : True
        maxMsgCount              : 0
        defMsgTTLValue           : 0
        dateUpdated              : 2020-06-02T17:55:53.93Z
        isSilentLogSourceEnabled : False
        msgSourceDateFormatID    : 169
        filePath                 : C:\Program Files\LogRhythm\Data Indexer\logs\diags
        cryptoMode               : 0
        signMode                 : 0
        defMsgTTL                : 0
        defMsgArchiveMode        : Override_Archive
        msgPerCycle              : 100
        collectionDepth          : 0
        udlaStateFieldType       : Increment
        parameter1               : 0
        parameter2               : 0
        parameter3               : 0
        parameter4               : 0
        recursionDepth           : 2
        isDirectory              : True
        inclusions               : *.log
        compressionType          : none
        udlaConnectionType       : 0
        collectionThreadTimeout  : 120
        virtualSourceSortOrder   : 0
        virtualSourceCatchAllID  : 0
        persistentConnection     : False
        autoAcceptanceRuleId     :
        maxLogDate               : 2020-06-12T19:21:06.473Z

        id                       : 8
        systemMonitorId          : 2
        name                     : NetworkConnectionMonitor
        host                     : @{id=2; name=WINdows-A10PJE5DII3.brew.bad}
        entity                   : @{id=1; name=Primary Site}
        logSourceType            : @{id=1000162; name=LogRhythm Network Connection Monitor (Windows)}
        mpePolicy                : @{id=-1000162; name=LogRhythm Default}
        trueSourcePolicy         :
        recordStatus             : Active
        status                   : Enabled
        isVirtual                : False
        logMartMode              : 13627389
        isLoadBalanced           : False
        mpeProcessingMode        : EventForwardingEnabled
        isArchivingEnabled       : True
        maxMsgCount              : 0
        defMsgTTLValue           : 0
        dateUpdated              : 2020-06-02T17:55:53.743Z
        isSilentLogSourceEnabled : False
        cryptoMode               : 0
        signMode                 : 0
        defMsgTTL                : 0
        defMsgArchiveMode        : Override_Archive
        msgPerCycle              : 100
        collectionDepth          : 0
        udlaStateFieldType       : Increment
        parameter1               : 0
        parameter2               : 0
        parameter3               : 0
        parameter4               : 0
        recursionDepth           : 0
        isDirectory              : False
        compressionType          : none
        udlaConnectionType       : 0
        collectionThreadTimeout  : 120
        virtualSourceSortOrder   : 0
        virtualSourceCatchAllID  : 0
        persistentConnection     : False
        autoAcceptanceRuleId     :
        maxLogDate               : 1900-01-01T00:00:00Z
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

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true ,Position = 1)]
        [object]$Id,

        [Parameter(Mandatory = $false, Position = 1)]
        [int]$PageValuesCount = 1000,

        [Parameter(Mandatory = $false, Position = 2)]
        [int]$PageCount = 1,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('asc','desc', ignorecase=$true)]
        [string]$Direction = "asc",

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('name','id', ignorecase=$true)]
        [string]$OrderBy = "name",

        [Parameter(Mandatory = $false, Position = 5)]
        [string]$Name,

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet('all','active','retired', ignorecase=$true)]
        [string]$RecordStatus = "all",

        [Parameter(Mandatory = $false, Position = 7)]
        [int32]$MessageSourceTypeId,
        
        [Parameter(Mandatory = $false, Position = 8)]
        [bool]$LoadBalanced,

        [Parameter(Mandatory = $false, Position = 9)]
        [bool]$Virtual,

        [Parameter(Mandatory = $false, Position = 10)]
        [switch]$Exact
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LogRhythm.Version

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
        
        # Integer reference
        [int32]$_int = 0
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
        }

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $Guid = $Id
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $AgentLookup = Get-LrAgentsAccepted -Name $Id -Exact
            if ($AgentLookup.Error) {
                return $AgentLookup
            } else {
                $Guid = $AgentLookup.id
            }
        }

        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # PageCount
        if ($PageValuesCount) {
            $_pageValueCount = $PageValuesCount
        } else {
            $_pageValueCount = 1000
        }
        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $_pageValueCount)

        # Query Offset - PageCount
        $Offset = ($PageCount -1) * $_pageValueCount
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if ($Name) {
            $_name = $Name
            $QueryParams.Add("name", $_name)
        }

        # Return results direction, ascending or descending
        if ($Direction) {
            $ValidStatus = "ASC", "DESC"
            if ($ValidStatus.Contains($($Direction.ToUpper()))) {
                if ($LrVersion -like "7.5.*") {
                    if($Direction.ToUpper() -eq "ASC") {
                        $_direction = "ascending"
                    } else {
                        $_direction = "descending"
                    }
                } else {
                    return "$(Get-Timestamp) Function Get-LrLogSources requires LogRhythm version 7.5.0+.  Set LogRhythm version in LR Tools Preferences."
                }
                $QueryParams.Add("dir", $_direction)
            } else {
                throw [ArgumentException] "Direction [$Direction] must be: asc or desc."
            }
        }

        # Filter by Object Name
        if ($Name) {
            $_name = $Name
            $QueryParams.Add("name", $_name)
        }

        # LoadBalanced
        if ($LoadBalanced) {
            $_loadBalanced = $LoadBalanced
            $QueryParams.Add("isLoadBalanced", $_loadBalanced)
        }

        # Virtual
        if ($Virtual) {
            $_virtual = $Virtual
            $QueryParams.Add("isVirtual", $_virtual)
        }

        # RecordStatus
        if ($RecordStatus) {
            $ValidStatus = "all", "active", "retired"
            if ($ValidStatus.Contains($($RecordStatus.ToLower()))) {
                $_recordStatus = $RecordStatus.ToLower()
                $QueryParams.Add("recordStatus", $_recordStatus)
            } else {
                throw [ArgumentException] "RecordStatus [$RecordStatus] must be: all, active, or retired."
            }
        }

        # Filter by Object Name
        if ($MessageSourceTypeId) {
            # Area to add SourceType lookup to validate LogSource type by Name or Int32.
            $_messageSourceTypeId = $MessageSourceTypeId
            $QueryParams.Add("messageSourceTypeId", $_messageSourceTypeId)
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/agents/$Guid/logsources/" + $QueryString

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        }
    }

    End {
        if ($Response.Count -eq $_pageValueCount) {
            # Need to get next page results
            $CurrentPage = $PageCount + 1
            #return 
            Return $Response + (Get-LrLogSources -PageCount $CurrentPage) 
        }
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
}