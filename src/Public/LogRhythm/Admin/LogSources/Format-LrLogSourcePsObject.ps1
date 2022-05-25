using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Format-LrLogSourcePsObject {
    <#
    .SYNOPSIS
        Format Log Source object(s) to a flat hierchy PS Object.
    .DESCRIPTION
        Used to support data export/import operations for Log Source records.
    .PARAMETER LogSource
        PSObject containing all appropriate data points for Log Source record.
    .OUTPUTS
        PSCustomObject formatted to support Export-Csv.
    .EXAMPLE
        PS C:\> Get-LrLogSources | Format-LrLogSourcePsObject
        ---
        Bip                : 192.168.1.1
        DateUpdated        : 2020-07-20T22:50:57.433Z
        Eip                : 192.168.1.255
        EntityId           : 5
        Entity             : Secondary Site
        HostZone           : Internal
        Id                 : 1
        Name               : Network a
        LocationId         : -1
        Location           :
        LongDesc           :
        RiskLevel          : None
        ShortDesc          :
        ThreatLevel        : None
        ThreatLevelComment :

        Bip                : 192.168.20.1
        DateUpdated        : 2020-07-21T12:01:38.14Z
        Eip                : 192.168.20.255
        EntityId           : 1
        Entity             : Primary Site
        HostZone           : Internal
        Id                 : 3
        Name               : Network Alpha
        LocationId         : 291
        Location           : South Carolina
        LongDesc           : Additional details note.
        RiskLevel          : Medium-Medium
        ShortDesc          : Brief description value.
        ThreatLevel        : None
        ThreatLevelComment :

        Bip                : 172.16.20.1
        DateUpdated        : 2020-07-21T11:40:26.367Z
        Eip                : 172.16.21.255
        EntityId           : 1
        Entity             : Primary Site
        HostZone           : Internal
        Id                 : 4
        Name               : Network Beta
        LocationId         : -1
        Location           :
        LongDesc           :
        RiskLevel          : None
        ShortDesc          :
        ThreatLevel        : None
        ThreatLevelComment :

        Bip                : 10.77.20.1
        DateUpdated        : 2020-07-21T11:41:04.98Z
        Eip                : 10.77.20.255
        EntityId           : 1
        Entity             : Primary Site
        HostZone           : Internal
        Id                 : 5
        Name               : Network Charlie
        LocationId         : -1
        Location           :
        LongDesc           :
        RiskLevel          : None
        ShortDesc          :
        ThreatLevel        : None
        ThreatLevelComment :
    .EXAMPLE
        # Export all Networks to CSV
        PS C:\> Get-LrLogSources | Format-LrLogSourcePsObject | Export-Csv -Path ./LogSources.csv -NoTypeInformation

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position = 0)]
        [object]$LogSource
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $OutputObject = [list[object]]::new()  
    }

    Process {
        $LogObject = [PSCustomObject]@{
            id = $LogSource.id
            systemMonitorId = $LogSource.systemMonitorId
            name = $LogSource.name
            hostId = $LogSource.host.id
            hostName = $LogSource.host.name
            entityId = $LogSource.entity.id
            entityName = $LogSource.entity.name
            logSourceTypeId = $LogSource.logSourceType.id
            logSourceTypeName = $LogSource.logSourceType.name
            mpePolicyId = $LogSource.mpePolicy.id
            mpePolicyName = $LogSource.mpePolicy.name
            recordStatus = $LogSource.recordStatus
            status = $LogSource.status
            isVirtual = $LogSource.isVirtual
            logMartMode = $LogSource.logMartMode
            isLoadBalanced = $LogSource.isLoadBalanced
            mpeProcessingMode = $LogSource.mpeProcessingMode
            isArchivingEnabled = $LogSource.isArchivingEnabled
            maxMsgCount = $LogSource.maxMsgCount
            defMsgTTLValue = $LogSource.defMsgTTLValue
            dateUpdated = $LogSource.dateUpdated
            isSilentLogSourceEnabled = $LogSource.isSilentLogSourceEnabled
            filePath = $LogSource.filePath
            cryptoMode = $LogSource.cryptoMode
            signMode = $LogSource.signMode
            defMsgTTL = $LogSource.defMsgTTL
            defMsgArchiveMode = $LogSource.defMsgArchiveMode
            msgPerCycle = $LogSource.msgPerCycle
            collectionDepth = $LogSource.collectionDepth
            udlaStateFieldType = $LogSource.udlaStateFieldType
            parameter1 = $LogSource.parameter1
            parameter2 = $LogSource.parameter2
            parameter3 = $LogSource.parameter3
            parameter4 = $LogSource.parameter4
            recursionDepth = $LogSource.recursionDepth
            isDirectory = $LogSource.isDirectory
            compressionType = $LogSource.compressionType
            udlaconnectionType = $LogSource.udlaconnectionType
            collectionThreadTimeout = $LogSource.collectionThreadTimeout
            virtualSourceSortOrder = $LogSource.virtualSourceSortOrder
            virtualSourceCatchAllID = $LogSource.virtualSourceCatchAllID
            persistentConnection = $LogSource.persistentConnection
            autoAcceptanceRuleId = $LogSource.autoAcceptanceRuleId
            maxLogDate = $LogSource.maxLogDate
        }

        $OutputObject.add($LogObject)
    }

    End {
        return $OutputObject
    }
}