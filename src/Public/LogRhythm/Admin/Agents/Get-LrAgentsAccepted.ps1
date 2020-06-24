using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrAgentsAccepted {
    <#
    .SYNOPSIS
        Returns details of all accepted Agents that match the specified criteria.
    .DESCRIPTION
        Get-LrAgentsAccepted returns a list of accepted Agents, including details.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER OrderBy
        Sorts records by name or Id.
    .PARAMETER Direction
        Sorts records by ascending or descending.

        Valid values: "asc" "desc"
    .PARAMETER Name
        String used to search records by Name.
    .PARAMETER AgentLicenseType
        Filter based by license type.

        Valid values: "None" "SystemMonitorBasic" "SystemMonitor"
    .PARAMETER SearchScope
        Filters by search scope.

        Valid values: "SystemMonitorSearch" "ParentEntitySearch" "GlobalSearch"
    .PARAMETER Entity
        Parameter for specifying the existing LogRhythm Entity for the new Host record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Entity object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Segment Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Version
        The deployment version of the component.

        Version schema: (\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})
    .PARAMETER AgentType
        Filter results by type of agent.

        Valid values: "None" "Windows" "Linux" "Solaris" "Aix" "Hpux" "All"
    .PARAMETER LoadBalanced
        Filters results by load balanced status of component.

        Valid values: true, false
    .PARAMETER RecordStatus
        Filter records by object Record Status.

        Valid values: "all" "active" "retired"
    .PARAMETER FetchAIERecords
        Filters results by whether AIE records should be fetched.

        Valud values: true, false
    .PARAMETER Exact,
        Switch used to specify Name is explicit.
    .INPUTS

    .OUTPUTS
        PSCustomObject representing Accepted Agents and their contents.
    .EXAMPLE
        PS C:\> Get-LrAgentsAccepted
        ----
        id                       : 2
        guid                     : 0e5f3a78-3bf8-4107-b81d-916822ec85f1
        name                     : WIN-A10PJE5DII3
        hostName                 : WINdows-A10PJE5DII3.brew.bad
        hostId                   : 2
        hostEntity               : Primary Site
        agentType                : Windows
        syslogEnabled            : False
        netflowEnabled           : False
        recordStatusName         : Active
        dateUpdated              : 2020-06-03T12:49:39.39Z
        licenseType              : SystemMonitor
        os                       : Windows
        osVersion                : Microsoft Windows NT 10.0.14393.0
        searchScope              : ParentEntitySearch
        sflowEnabled             : False
        isLoadBalanced           : False
        osType                   : Server
        dldPolicy                : -1
        smConfigPolicy           : N/A
        shortDesc                :
        longDesc                 :
        activeLogSources         : 8
        status                   : Enabled
        lastHeartbeat            : 2020-06-12T19:22:26Z
        lastDataProcessor        : WIN-A10PJE5DII3
        version                  : 7.4.10.8017
        capabilities             : None
        rimEnabled               : False
        disableFlushThrottle     : False
        heartbeatWarningInterval : 60
        msgBuffer                : 1000
        netflowServerCrypto      : False
        passphrase               : ''
        syslogServerCrypto       : False
        tcpNodeDelay             : True
        tcpRecvBufferSize        : 524288
        tcpSendBufferSize        : 524288
        tcpReuse                 : True
        entityId                 : 1
        policyId                 : 0
        snmpCommunityStrings     : {}
        general                  : @{compress=0; connectionTimeout=7200; cycleTime=10; eventLogBuffer=8; eventLogCacheLifetime=30; eventLogTimeout=10; heartbeatInterval=6; failbackDelay=60; flushBatch=1000;  
                                loadBalanceDelay=4320; localLogLifetime=7; logLevel=Warning; maxLogQueueMemory=256; maxServiceMemory=2048; maxSyslogSuspenseSize=5; processPriority=normal;
                                socketReceiveTimeout=60000; socketSendTimeout=60000; virtualSourceDNSResolution=True; compressBatch=50; logSourceVirtualizationThreadCount=5;
                                logsourceVirtualizationTimeoutMillsec=100}
        netFlowServer            : @{netflowServerNIC=0; port=5500; netflowVerbose=False}
        networkConnectionMonitor : @{networkConnectionMonitor=False; ncmIncludeUAMData=False; logListeners=False; logEstablishedInboundConnections=False; logEstablishedOutboundConnections=False;
                                networkConnectionMonitorInterval=5}
        processMonitor           : @{pmincludeUAMData=False; processMonitor=False; processMonitorInterval=5}
        secureSyslogServer       : @{port=6514; useServerCert=False; certStore=; certSubject=; certLocation=; enforceClientCertTrust=False; enforceClientCertRevocation=False; requireClientCert=False;
                                clientCertOCSPURL=}
        sFlowServer              : @{logCounters=False; serverEnabled=False; serverNIC=0; udpPort=6343; extraLogging=False; logDetails=False}
        tlsCertificates          : @{certLocation=; certStore=; certSubject=; tlsCert=False; mediatorTLSCertOCSPURL=; enforceMediatorTLSCertTrust=False; enforceMediatorTLSCertRevocation=False;
                                mediatorTLSCertLocation=; certFile=; secretKeyFilename=; secretKeyPassword=}
        fileIntegrityMonitor     : @{fileMonitorEnabled=False; dataDefender=False; includeUAMData=False; realtimeFileMonitor=False; realtimeAnomalyDetection=False; realtimeRecordBufferLimit=2147483647;       
                                realtimeIDMPollingInterval=60; RTFIMExcludeNestedDirectoryEvents=False}
        uniDirectionalAgent      : @{hashMode=NoHash; mediatorPort=40000; isEnabled=False}
        userActivityMonitor      : @{logonActivity=False; processActivity=False; networkSessionActivity=False; interval=30; history=24}
        snmpTrapReceiver         : @{receiver=False; localIP=0; localPort=162}
        syslogServer             : @{file=False; filePath=C:\Program Files\LogRhythm\LogRhythm System Monitor\logs\syslogfile.log; serverNIC=0; udpPort=514; tcpPort=514; fileRotationSize=5; fileHistory=7;    
                                parsedHosts=;
                                parsedHostExpressions=^<(?<priority>\d{1,3})>\s*(?<message>(?<month>[a-zA-Z]{3})\s*(?<day>\d{1,2})\s*(?<hour>\d{1,2}):(?<minute>\d{1,2}):(?<seconds>\d{1,2})\s*Message       
                                forwarded from (?<hostidentifier>\S+):.*)
                                ^<(?<priority>\d{1,3})>\s*(?<message>(?<month>[a-zA-Z]{3})\s*(?<day>\d{1,2})\s*(?<hour>\d{1,2}):(?<minute>\d{1,2}):(?<seconds>\d{1,2})\s*(\S+:)\s*.*)
                                ^<(?<priority>\d{1,3})>\s*(?<message>(?<month>[a-zA-Z]{3})\s*(?<day>\d{1,2})\s*(?<hour>\d{1,2}):(?<minute>\d{1,2}):(?<seconds>\d{1,2})\s*(?<hostidentifier>\S+)\s*.*)        
                                ^<(?<priority>\d{1,3})>\s*(?<message>.*)
                                ^(?<message>(?<month>[a-zA-Z]{3})\s*(?<day>\d{1,2})\s*(?<hour>\d{1,2}):(?<minute>\d{1,2}):(?<seconds>\d{1,2})\s*(?<hostidentifier>\S+)\s*.*); parameter1=False}
        snmpV3Credentials        : {}
        agentToMediators         : {@{systemMonitorID=2; mediator=; priority=1; clientAddress=192.168.2.127; clientPort=56988; serverSSLPort=6443; serverIP=192.168.2.127; serverIPv6=; serverDNS=}}
        agentVersionHistory      : {@{versionHistoryId=1; previousVersion=7.4.10.8016; currentVersion=7.4.10.8017; dateUpdated=2020-06-12T13:22:31.47Z}}
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
        [int]$PageValuesCount = 1000,

        [Parameter(Mandatory = $false, Position = 2)]
        [int]$PageCount = 1,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('asc','desc', ignorecase=$true)]
        [string]$Direction = "asc",

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('name','id', ignorecase=$true)]
        [string]$OrderBy = "name",

        [Parameter(Mandatory = $false, Position = 4)]
        [string]$Name,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('all','active','retired', ignorecase=$true)]
        [string]$RecordStatus = "all",

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet('none','systemmonitorbasic', 'systemmonitor', ignorecase=$true)]
        [string]$AgentLicenseType,

        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateSet('systemmonitorsearch','parententitysearch', 'globalsearch', ignorecase=$true)]
        [string]$SearchScope,

        [Parameter(Mandatory = $false, Position = 8)]
        [string]$Entity,

        [Parameter(Mandatory = $false, Position = 9)]
        [string]$Version,

        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateSet('none','windows', 'linux', 'solaris', 'aix', 'hpux', 'all', ignorecase=$true)]
        [string]$AgentType,
        
        [Parameter(Mandatory = $false, Position = 10)]
        [bool]$LoadBalanced,

        [Parameter(Mandatory = $false, Position = 11)]
        [bool]$FetchAIERecords,

        [Parameter(Mandatory = $false, Position = 13)]
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

        # Filter by Object Entity Name
        if ($Entity) {
            # Lookup Entity By ID or Name
            if ([int]::TryParse($Entity, [ref]$_int)) {
                Write-Verbose "[$Me]: Entity parses as integer."
                $EntityLookup = Get-LrEntityDetails -Id $Entity
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    return $ErrorObject
                } else {
                    $_entity = $EntityLookup
                }
            } else {
                Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                $EntityLookup = Get-LrEntities -Name $Entity -Exact
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    return $ErrorObject
                } else {
                    $_entity = $EntityLookup
                }
            }
            $QueryParams.Add("entity", $($_entity.Name))
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

        # SearchScope
        if ($AgentLicenseType) {
            $ValidStatus = @("none", "systemmonitorbasic", "systemmonitor")
            if ($ValidStatus.Contains($($AgentLicenseType.ToLower()))) {
                Switch ($AgentLicenseType) {
                    none {$_agentLicenseType = "None"}
                    systemmonitorbasic {$_agentLicenseType = "SystemMonitorBasic"}
                    systemmonitor {$_agentLicenseType = "SystemMonitor"}
                    default {$_agentLicenseType = "SystemMonitor"}
                }
                $QueryParams.Add("agentLicenseType", $_agentLicenseType)
            } else {
                throw [ArgumentException] "AgentLicenseType [$AgentLicenseType] must be: none, systemmonitorbasic, systemmonitor."
            }
        }

        # SearchScope
        if ($SearchScope) {
            $ValidStatus = @("systemmonitorsearch", "parententitysearch", "globalsearch")
            if ($ValidStatus.Contains($($SearchScope.ToLower()))) {
                Switch ($SearchScope) {
                    systemmonitorsearch {$_searchScope = "SystemMonitorSearch"}
                    parententitysearch {$_searchScope = "ParentEntitySearch"}
                    globalsearch {$_searchScope = "GlobalSearch"}
                    default {$_searchScope = "ParentEntitySearch"}
                }
                $QueryParams.Add("searchScope", $_searchScope)
            } else {
                throw [ArgumentException] "SearchScope [$SearchScope] must be: systemmonitorsearch, parententitysearch, globalsearch."
            }
        }

        # RecordStatus
        if ($AgentType) {
            $ValidStatus = @("none", "windows", "linux", "solaris", "aix", "hpux", "all")
            if ($ValidStatus.Contains($($AgentType.ToLower()))) {
                $_agentType = (Get-Culture).TextInfo.ToTitleCase($AgentType)
                $QueryParams.Add("agentType", $_agentType)
            } else {
                throw [ArgumentException] "AgentType [$AgentType] must be: none, windows, linux, solaris, aix, hpux, or all."
            }
        }

        # LoadBalanced
        if ($LoadBalanced) {
            $_loadBalanced = $LoadBalanced
            $QueryParams.Add("isLoadBalanced", $_loadBalanced)
        }

        # AIERecords
        if ($FetchAIERecords) {
            $_fetchAIERecords = $FetchAIERecords
            $QueryParams.Add("fetchAIERecords", $_fetchAIERecords)
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

        # Version
        if ($Version) {
            [regex]$ValidStatus = "(\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})"
            if ($Version -match $ValidStatus) {
                $_version = $Version
                $QueryParams.Add("version", $_version)
            } else {
                throw [ArgumentException] "Version [$Version] must match regex: (\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})"
            }
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/agents/" + $QueryString

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