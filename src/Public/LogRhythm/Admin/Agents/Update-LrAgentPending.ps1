using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrAgentPending {
    <#
    .SYNOPSIS
        Update an existing Pending Agent entry.
    .DESCRIPTION
        Update-LrAgentPending returns a full LogRhythm Entity object, including details and list items if provided the passthru flag.
    .PARAMETER Guid

    .PARAMETER AcceptanceStatus
        Supply which status for updating a pending agent's status to.

        Valid options: Accept, Associate, or Reject
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        PSCustomObject representing the new LogRhythm Host and its contents.
    .EXAMPLE
        PS C:\> Update-LrAgentPending -Guid 'sma' -AcceptanceStatus 'reject'
        ---
        id                         : 11
        guid                       : c4a8a6a7-1c23-435e-b3a3-8c6342156e23
        name                       : SMA
        acceptanceStatus           : Rejected
        dateUpdated                : 7/22/2022 7:32:26 AM
        entityId                   : 1
        hostName                   : SMA
        resolvedHostId             : 0
        ipAddress                  : 10.43.30.236|192.168.1.3
        clientAddress              : 10.43.30.236
        clientPort                 : 0
        agentType                  : Windows
        version                    : 7.9.0.8001
        os                         : Win32NT
        osVersion                  : Microsoft Windows NT 10.0.17763.0
        osType                     : Server
        capabilities               : None
        agentConfigurationPolicyId : -1
    .EXAMPLE 
        PS C:\> Update-LrAgentPending -Guid 'sma' -AcceptanceStatus delete
        ---
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Entity,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateSet('accept','associate', 'reject', ignorecase=$true)]
        [string] $AcceptanceStatus,

        [Parameter(Mandatory = $false, Position = 4)]
        [int] $AssociateAgentId,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateSet('SystemMonitor','SystemMonitorBasic', 'SystemMonitorCollector', ignorecase=$true)]
        [string] $LicenseType,

        [Parameter(Mandatory = $false, Position = 2)]
        [bool] $OverrideEntityForNewHosts = $false,

        [Parameter(Mandatory = $false, Position = 3)]
        [int] $ConfigPolicy,

        [Parameter(Mandatory = $false, Position = 4)]
        [string] $Guid,

        [Parameter(Mandatory = $false, Position = 5)]
        [int] $MediatorId,

        [Parameter(Mandatory = $false, Position = 6)]
        [int] $Priority,

        [Parameter(Mandatory = $false, Position = 7)]
        [int] $ClientAddress = 0,

        [Parameter(Mandatory = $false, Position = 8)]
        [int] $ClientPort = 0,

        [Parameter(Mandatory = $false, Position = 9)]
        [int] $MediatorSSLPort = 443,

        [Parameter(Mandatory = $false, Position = 10)]
        [string] $MediatorIPv4,

        [Parameter(Mandatory = $false, Position = 11)]
        [string] $MediatorIPv6,

        [Parameter(Mandatory = $false, Position = 12)]
        [string] $MediatorFQDN,

        [Parameter(Mandatory = $false, Position = 13)]
        [int] $FimPolicies,
        
        [Parameter(Mandatory = $false, Position = 14)]
        [int] $RealTimeRecordBufferLimit = 10485760,

        [Parameter(Mandatory = $false, Position = 15)]
        [int] $RealtimeIDMPollingInterval = 5,

        [Parameter(Mandatory = $false, Position = 19)]
        [bool] $RTFIMExcludeNestedDirectoryEvents = $false,

        [Parameter(Mandatory = $false, Position = 16)]
        [bool] $FIMEnabled = $false,

        [Parameter(Mandatory = $false, Position = 17)]
        [bool] $DataDefender = $false,

        [Parameter(Mandatory = $false, Position = 18)]
        [bool] $RTFIM = $false,

        [Parameter(Mandatory = $false, Position = 19)]
        [bool] $RTFIMAnomalyDetection = $false,
        

        [Parameter(Mandatory = $false, Position = 20)]
        [bool] $RIMEnabled = $false,

        [Parameter(Mandatory = $false, Position = 21)]
        [int] $RIMPolicies,

        [Parameter(Mandatory = $false, Position = 22)]
        [int] $DLDPolicy,

        [Parameter(Mandatory = $false, Position = 23)]
        [bool] $PMIncludeUAMData = $false,

        [Parameter(Mandatory = $false, Position = 24)]
        [bool] $PM = $false,

        [Parameter(Mandatory = $false, Position = 25)]
        [int] $PMInterval = 5,

        [Parameter(Mandatory = $false, Position = 26)]
        [bool] $NCM = $false,

        [Parameter(Mandatory = $false, Position = 27)]
        [bool] $NCMIncludeUAM = $false,

        [Parameter(Mandatory = $false, Position = 28)]
        [bool] $NCMLogListeners = $false,

        [Parameter(Mandatory = $false, Position = 29)]
        [bool] $NCMLogInbound = $false,

        [Parameter(Mandatory = $false, Position = 30)]
        [bool] $NCMLogOutbound = $false,

        [Parameter(Mandatory = $false, Position = 31)]
        [int] $NCMInterval = 5,

        [Parameter(Mandatory = $false, Position = 32)]
        [bool] $UAMLogonActivity = $false,

        [Parameter(Mandatory = $false, Position = 33)]
        [bool] $UAMProcessActivity = $false,

        [Parameter(Mandatory = $false, Position = 34)]
        [bool] $UAMSessionActivity = $false,

        [Parameter(Mandatory = $false, Position = 35)]
        [int] $UAMInterval = 5,

        [Parameter(Mandatory = $false, Position = 36)]
        [int] $UAMHistory = 1,

        [Parameter(Mandatory = $false, Position = 37)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 38)]
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
        $Method = $HttpMethod.Put

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Integer Reference
        [int32] $_int = 1
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Guid
            Raw                   =   $null
        }

        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7.[0-8].\d') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.9.0 and greater."

            return $ErrorObject
        }

        # Lookup Entity
        if ($Entity) {
            if ([int]::TryParse($Entity, [ref]$_int)) {
                Write-Verbose "[$Me]: Entity parses as integer."
                $_entity = Get-LrEntityDetails -Id $Entity
            } else {
                Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                $EntityLookup = Get-LrEntities -Name $Entity -Exact
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    $ErrorObject.Value = $Entity
                    return $ErrorObject
                } else {
                    $_entity = $EntityLookup
                }
            }
        }

        # Check if Guid value is a valid Guid
        
        if (Test-Guid $Guid) {
            Write-Verbose "[$Me]: Guid parses as valid guid."
        } else {
            Write-Verbose "[$Me]: Guid does not parse as guid.  Performing string lookup."
            $AgentLookup = Get-LrAgentsPending -Name $Guid -Exact
            if (!$AgentLookup) {
                $AgentLookup = Get-LrAgentsPending -Name $Guid -Exact -AcceptanceStatus 'rejected'
                if (!$AgentLookup) {
                    $ErrorObject.Error = $true
                    $ErrorObject.Code = 404
                    $ErrorObject.Raw = $Guid
                    $ErrorObject.Type = "Input.Validation.Lookup"
                    $ErrorObject.Note = "Guid String [$Guid] not found in Pending Agents."
                    return $ErrorObject
                } else {
                    $Guid = $AgentLookup.guid
                    $SystemMonitorId = $AgentLookup.id
                }
            } else {
                $Guid = $AgentLookup.guid
                $SystemMonitorId = $AgentLookup.id
            }
        }

            
        if ($AcceptanceStatus -like 'reject') {
            # Define Query URL
            $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/" + $Guid + "/reject"
        } elseif ($AcceptanceStatus -like 'associate') {
            if ([int]::TryParse($AssociateAgentId, [ref]$_int)) {
                Write-Verbose "[$Me]: AssociateAgentId parses as int."
                $AssociateAgentLookup = Get-LrAgentDetails -Id $AssociateAgentId
                if (($null -ne $AssociateAgentLookup.Error) -and ($AssociateAgentLookup.Error -eq $true)) {
                    return $AssociateAgentLookup
                }
                $_associateAgentId = $AssociateAgentId
            } else {
                Write-Verbose "[$Me]: AssociateAgentId does not parse as Int.  Performing string lookup."
                $AssociateAgentLookup = Get-LrAgentsAccepted -Name $AssociateAgentId -Exact
                if (!$AssociateAgentLookup) {
                        $ErrorObject.Error = $true
                        $ErrorObject.Code = 404
                        $ErrorObject.Raw = $AssociateAgentId
                        $ErrorObject.Type = "Input.Validation.Lookup"
                        $ErrorObject.Note = "Agent name [$AssociateAgentId] not found in Accepted Agents."
                        return $ErrorObject
                } elseif (($null -ne $AssociateAgentLookup.Error) -and ($AssociateAgentLookup.Error -eq $true)) {
                    return $AssociateAgentLookup
                } else {
                    $_associateAgentId = $AssociateAgentLookup.id
                }
            }

            $Body  = [PSCustomObject]@{
                agentId = $_associateAgentId
            } | ConvertTo-Json -Compress
    
            # Request URL
            $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/$Guid/associate"
        } else {
            $ErrorObject.Error = $true
            $ErrorObject.Code = 500
            $ErrorObject.Raw = $SystemMonitorId
            $ErrorObject.Type = "Accept.Reject"
            $ErrorObject.Note = "Accepting an agent is currently not available in this version of LogRhythm.Tools."
            return $ErrorObject

            $Body = [PSCustomObject]@{
                AgentType = 'Windows'
                overrideEntityForNewHosts = $OverrideEntityForNewHosts
                entity = [PSCustomObject]@{
                    name = $_entity.name
                    id = $_entity.id
                }
                licenseType = $LicenseType
                searchScope = 'ParentEntitySearch'
                syslogEnabled = $true
                #smConfigPolicy = $_smPolicyId
                agentToMediators = @( [PSCustomObject]@{
                    systemMonitorID = $SystemMonitorId
                    mediator = [PSCustomObject]@{
                        id = 1
                        name = 'g7-test'
                    }
                    priority = 1
                    clientAddress = "192.168.5.4"
                    clientPort = 33333
                    serverSSLPort = 443
                    serverIP = "10.1.0.80"
                    serverIPv6 = "2001:0db8:5b96:0000:0000:426f:8e17:642a"
                    serverDNS = "test.logrhythm.cloud"
                })
                #fimPolicies = $_fimPolicyId
                fileIntegrityMonitor = [PSCustomObject]@{
                    fileMonitorEnabled = $FIMEnabled # bool
                    dataDefender = $DataDefender # bool
                    realtimeFileMonitor = $RTFIM # bool
                    realtimeAnomalyDetection = $RTFIMAnomalyDetection # bool
                    realtimeRecordBufferLimit = $_Int_realtimeRecordBufferLimit # 0 to 2147483647, def 10485760
                    realtimeIDMPollingInterval = $RealtimeIDMPollingInterval # 5 to 86400, def 5
                    RTFIMExcludeNestedDirectoryEvents = $RTFIMExcludeNestedDirectoryEvents # bool
                }
                rimEnabled = $RIMEnabled
                #rimPolicies = @($_i_rimPolicies)
                dldPolicy = -1
                processMonitor = [PSCustomObject]@{
                    pmincludeUAMData = $PMIncludeUAMData
                    processMonitor = $PM
                    processMonitorInterval = $PMInterval # 1 to 86400, def 5
                }
                networkConnectionMonitor = [PSCustomObject]@{
                    networkConnectionMonitor = $NCM
                    ncmIncludeUAMData = $NCMIncludeUAM
                    logListeners = $NCMLogListeners
                    logEstablishedInboundConnections = $NCMLogInbound
                    logEstablishedOutboundConnections = $NCMLogOutbound
                    networkConnectionMonitorInterval = $NCMInterval # 1 to 86400, def 5
                }
                userActivityMonitor = [PSCustomObject]@{
                    logonActivity = $UAMLogonActivity
                    processActivity = $UAMProcessActivity
                    networkSessionActivity = $UAMSessionActivity
                    interval = $UAMInterval # 3 to 86400
                    history = $UAMHistory # 1 to 24
                }
            } | ConvertTo-Json -Depth 8 -Compress

            # Define Query URL
            $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/" + $Guid + "/accept"
        }
        

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        if ($AcceptanceStatus -like "reject") {
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
            if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
                return $Response
            }
        } else {
            Write-Verbose "[$Me]: Request Body:`n$Body"
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
            if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
                return $Response
            }
        }
        
        if ($PassThru) {
            return $Response
        }
    }

    End { }
}