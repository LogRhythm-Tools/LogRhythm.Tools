using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Format-LrNetworkPsObject {
    <#
    .SYNOPSIS
        Format Network Entity object(s) to a flat hierchy PS Object.
    .DESCRIPTION
        Used to support data export/import operations for Network records.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Network
        PSObject containing all appropriate data points for Network record.
    .OUTPUTS
        PSCustomObject formatted to support Export-Csv.
    .EXAMPLE
        PS C:\> Get-LrNetworks | Format-LrNetworkPsObject
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
        PS C:\> Get-LrNetworks | Format-LrNetworkPsObject | Export-Csv -Path ./NetworkEntities.csv -NoTypeInformation

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position = 0)]
        [object]$Network
    )

    Begin {
        $OutputObject = [list[object]]::new()  
    }

    Process {
        $NetObject = [PSCustomObject]@{
            Id = $Network.id
            Name = $Network.name
            Eip = $Network.eip
            Bip = $Network.bip
            DateUpdated = $Network.dateUpdated
            EntityId = $Network.entity.id
            Entity = $Network.entity.name
            Zone = $Network.HostZone
            LocationId = $null
            Location = $null
            LongDesc = $null
            RiskLevel = $Network.RiskLevel
            RecordStatus = $Network.recordStatusName
            ShortDesc = $null
            ThreatLevel = $Network.ThreatLevel
            ThreatLevelComment = $null
        }

        if ($Network.location.id -ne -1) {
            $NetObject.LocationId = $Network.location.id
            $NetObject.Location = $Network.location.name
        } else {
            $NetObject.LocationId = -1
        }

        if ($Network.ShortDesc) {
            $NetObject.ShortDesc = $Network.ShortDesc
        }

        if ($Network.LongDesc) {
            $NetObject.LongDesc = $Network.LongDesc
        }

        if ($Network.ThreatLevelComment) {
            $NetObject.ThreatLevelComment = $Network.ThreatLevelComment
        }

        $OutputObject.add($NetObject)
    }

    End {
        return $OutputObject
    }
}