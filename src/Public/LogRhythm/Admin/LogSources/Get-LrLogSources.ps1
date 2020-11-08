using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrLogSources {
    <#
    .SYNOPSIS
        Retrieve a list of accepted Log Sources from the LogRhythm.
    .DESCRIPTION
        Get-LrLogSources returns a list of accepted Log Sources, including details.
    .PARAMETER SystemMonitorId
        Filters results for a specific System Monitor Id in resources.
    .PARAMETER HostId
        Filter results based on Array of Known Host Identifier ID #s.

    .PARAMETER RecordStatus
        Filters records by object recordStatus

        Valid values: All, Active, Retired
    .PARAMETER EntityId
        Filter results based on Array of Entity ID #s.
    .PARAMETER OrderBy
        Sorts records by name or Id.
    .PARAMETER Description
        Filters records by object description.
    .PARAMETER Direction
        Sorts records by ascending or descending.
    .PARAMETER MessageSourceTypeId
        Filters results for a specific Message Source Type Id in resources.
    .PARAMETER Virtual
        Filters results by whether the resource is virtual.
    .PARAMETER LoadBalanced
        Filters results by load balanced status of the component.
    .PARAMETER Exact
        Restricts the results of the Name paramater to exact matches only.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Name
        String used to search Entity Host records by Name.
    .PARAMETER Exact,
        Switch used to specify Name search for Entity Host record is explicit.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        PS C:\> Get-LrLogSources
        ----
        id                       : 4
        systemMonitorId          : 1
        name                     : WinFileMon
        host                     : @{id=1; name=LRXM75}
        entity                   : @{id=1; name=Primary Site}
        logSourceType            : @{id=3; name=LogRhythm File Monitor (Windows)}
        mpePolicy                : @{id=-3; name=LogRhythm Default}
        recordStatus             : Active
        status                   : Enabled
        isVirtual                : False
        logMartMode              : 13627389
        isLoadBalanced           : False
        mpeProcessingMode        : EventForwardingEnabled
        isArchivingEnabled       : True
        maxMsgCount              : 0
        defMsgTTLValue           : 0
        dateUpdated              : 2020-10-07T23:01:57.05Z
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
        maxLogDate               : 2020-11-01T01:49:26.42Z

        id                       : 5
        systemMonitorId          : 1
        name                     : WinDataDefender
        host                     : @{id=1; name=LRXM75}
        entity                   : @{id=1; name=Primary Site}
        logSourceType            : @{id=1000044; name=LogRhythm Data Loss Defender}
        mpePolicy                : @{id=-1000044; name=LogRhythm Default}
        recordStatus             : Active
        status                   : Enabled
        isVirtual                : False
        logMartMode              : 13627389
        isLoadBalanced           : False
        mpeProcessingMode        : EventForwardingEnabled
        isArchivingEnabled       : True
        maxMsgCount              : 0
        defMsgTTLValue           : 0
        dateUpdated              : 2020-10-07T23:01:57.14Z
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
    .EXAMPLE
        PS C:\> Get-LrLogSources -MessageSourceTypeId 1000044
        ---
        id                       : 5
        systemMonitorId          : 1
        name                     : WinDataDefender
        host                     : @{id=1; name=LRXM75}
        entity                   : @{id=1; name=Primary Site}
        logSourceType            : @{id=1000044; name=LogRhythm Data Loss Defender}
        mpePolicy                : @{id=-1000044; name=LogRhythm Default}
        recordStatus             : Active
        status                   : Enabled
        isVirtual                : False
        logMartMode              : 13627389
        isLoadBalanced           : False
        mpeProcessingMode        : EventForwardingEnabled
        isArchivingEnabled       : True
        maxMsgCount              : 0
        defMsgTTLValue           : 0
        dateUpdated              : 2020-10-07T23:01:57.14Z
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
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [int32] $SystemMonitorId,


        [Parameter(Mandatory = $false, Position = 2)]
        [int32[]] $HostId,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('all','active','retired', ignorecase=$true)]
        [string] $RecordStatus = "active",


        [Parameter(Mandatory = $false, Position = 4)]
        [int32[]] $EntityId,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('name','id', ignorecase=$true)]
        [string] $OrderBy = "name",


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet('asc','desc', ignorecase=$true)]
        [string] $Direction,


        [Parameter(Mandatory = $false, Position = 7)]
        [string] $Description,


        [Parameter(Mandatory = $false, Position = 8)]
        [string] $MessageSourceTypeId,
        


        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateSet('true','false', ignorecase=$true)]
        [string] $Virtual,



        [Parameter(Mandatory = $false, Position = 10)]
        [ValidateSet('true','false', ignorecase=$true)]
        [string] $LoadBalanced,


        [Parameter(Mandatory = $false, Position = 11)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 13)]
        [int] $PageValuesCount = 1000,

        
        [Parameter(Mandatory = $false, Position = 14)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 15)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
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
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
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

        # Filter by Object Description
        if ($Description) {
            $_description = $Description
            $QueryParams.Add("desc", $_description)
        }

        # Filter by Object Entity Id
        if ($EntityId) {            
            if ($EntityId.count -gt 1) {
                $_entityId = $EntityId -join ','
            } else {
                $_entityId = $EntityId
            }
            $QueryParams.Add("entityId", $_entityId)
        }

        # Filter by Message Source Type Id Name
        if ($MessageSourceTypeId) {
            $_messageSourceTypeId = $MessageSourceTypeId
            $QueryParams.Add("messageSourceTypeId", $_messageSourceTypeId)
        }

        # Filter by System MonitorId
        if ($SystemMonitorId) {
            $_systemMonitorId = $SystemMonitorId
            $QueryParams.Add("systemMonitorId", $_systemMonitorId)
        }

        # Filter based on LogSource Virtual True/False
        if ($Virtual) {
            $_virtual = $Virtual
            $QueryParams.Add("isVirtual", $_virtual)
        }

        # Filter based on LoadBalance True/False
        if ($LoadBalanced) {
            $_loadBalanced = $LoadBalanced
            $QueryParams.Add("isLoadBalanced", $_loadBalanced)
        }

        # Filter by array of Known Host Identifier ID #s
        if ($HostId) {
            if ($HostId.count -gt 1) {
                $_hostId = $HostId -join ','
            } else {
                $_hostId = $HostId
            }
            $QueryParams.Add("hostId", $_hostId)
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

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/logsources/" + $QueryString

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch {
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