using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Format-LrHostPsObject {
    <#
    .SYNOPSIS
        Format Host Entity object(s) to a flat hierchy PS Object.
    .DESCRIPTION
        Used to support data export/import operations for Host records.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Network
        PSObject containing all appropriate data points for Host record.
    .OUTPUTS
        PSCustomObject formatted to support Export-Csv.
    .EXAMPLE
        PS C:\> Get-LrHosts | Format-LrHostPsObject
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
        PS C:\> Get-LrHosts | Format-LrHostPsObject | Export-Csv -Path ./HostEntities.csv -NoTypeInformation

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position = 0)]
        [object]$HostRecord
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $OutputObject = [list[object]]::new()  
    }

    Process {
        $HostObject = [PSCustomObject]@{
            Id = $HostRecord.id
            Name = $HostRecord.name
            Eip = $HostRecord.eip
            Bip = $HostRecord.bip
            DateUpdated = $HostRecord.dateUpdated
            EntityId = $HostRecord.entity.id
            Entity = $HostRecord.entity.name
            Zone = $HostRecord.HostZone
            LocationId = $null
            Location = $null
            LongDesc = $null
            RiskLevel = $HostRecord.RiskLevel
            RecordStatus = $HostRecord.recordStatusName
            ShortDesc = $null
            ThreatLevel = $HostRecord.ThreatLevel
            ThreatLevelComment = $null
        }

        if ($HostRecord.location.id -ne -1) {
            $HostObject.LocationId = $HostRecord.location.id
            $HostObject.Location = $HostRecord.location.name
        } else {
            $HostObject.LocationId = -1
        }

        if ($HostRecord.ShortDesc) {
            $HostObject.ShortDesc = $HostRecord.ShortDesc
        }

        if ($HostRecord.LongDesc) {
            $HostObject.LongDesc = $HostRecord.LongDesc
        }

        if ($HostRecord.ThreatLevelComment) {
            $HostObject.ThreatLevelComment = $HostRecord.ThreatLevelComment
        }

        $OutputObject.add($HostObject)
    }

    End {
        return $OutputObject
    }
}