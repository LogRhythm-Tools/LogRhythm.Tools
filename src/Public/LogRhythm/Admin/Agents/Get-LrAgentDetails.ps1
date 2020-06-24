using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrAgentDetails {
    <#
    .SYNOPSIS
        Retrieve the details from a LogRhythm System Monitor agent.
    .DESCRIPTION
        Get-LrHostDetails returns the details of the specified Agent.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [System.String] (Name or Int)
        Specifies a LogRhythm system monitor agent object by providing one of the following property values:
          + List Name (as System.String), e.g. "MYSECRETAGENT"
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .OUTPUTS
        PSCustomObject representing LogRhythm Agent record and its contents.
    .EXAMPLE
        PS C:\> Get-LrAgentDetails -Id 2
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
    .EXAMPLE 
        Get-LrAgentDetails -Id "WIN-A10PJE5DII3"
        ---
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

        [Parameter(Mandatory = $true, ValueFromPipeline=$true, Position = 1)]
        [ValidateNotNull()]
        [object] $Id
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

        # Value Testing Paramater
        $_int = 0

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $Id
            Code                  =   $Null
            Type                  =   $null
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

        
        $RequestUrl = $BaseUrl + "/agents/" + $Guid + "/"
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

        return $Response
    }

    End { }
}