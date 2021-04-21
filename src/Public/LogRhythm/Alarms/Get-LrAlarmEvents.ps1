using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Get-LrAlarmEvents {
    <#
    .SYNOPSIS
        Retrieve the AIE Event details for a specific Alarm from the LogRhythm SIEM.
    .DESCRIPTION
        LrAlarmEvents returns a detailed LogRhythm Alarm Event data object.
    .PARAMETER AlarmId
        Intiger representing the Alarm required for detail retrieval.
    .PARAMETER ResultsOnly
        Switch used to specify return only alarmEventsDetails results.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.Int]          -> AlarmId
        [System.Switch]       -> ResultsOnly
        [PSCredential]        -> Credential
    .OUTPUTS
        PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Get-LrAlarmEvents -AlarmId 181

        alarmEventsDetails
        ------------------
        {@{account=; action=; amount=; bytesIn=; bytesOut=; classificationId=2200; classificationName=Suspicious; classificationTypeName=Security; command=; commonEventId=1000000002; cve=; commonEventName=AIE: Test Rule - Ca…

    .EXAMPLE
        PS C:\> Get-LrAlarmEvents -AlarmId 181 -ResultsOnly


        account                  :
        action                   :
        amount                   :
        bytesIn                  :
        bytesOut                 :
        classificationId         : 2200
        classificationName       : Suspicious
        classificationTypeName   : Security
        command                  :
        commonEventId            : 1000000002
        cve                      :
        commonEventName          : AIE: Test Rule - Calc.exe
        count                    : 1
        directionId              : 0
        directionName            : Unknown
        domain                   :
        duration                 : 0
        entityId                 : -1000001
        entityName               :
        group                    :
        impactedEntityId         : -100
        impactedEntityName       : Global Entity
        impactedHostId           : -1
        impactedHostName         :
        impactedInterface        :
        impactedIP               :
        impactedLocation         : @{countryCode=; name=; latitude=0; locationId=0; locationKey=; longitude=0; parentLocationId=0; recordStatus=Deleted; regionCode=; type=NULL; dateUpdated=1/1/0001 12:00:00 AM}
        impactedMAC              :
        impactedName             :
        impactedNATIP            :
        impactedNATPort          :
        impactedNetwork          : @{beginIPRange=; dateUpdated=1/1/0001 12:00:00 AM; riskThreshold=; endIPRange=; entityId=0; hostZone=Unknown; locationId=0; longDesc=; name=; networkId=0; recordStatus=Deleted; shortDesc=}
        impactedPort             : -1
        impactedZone             : Unknown
        itemsPacketsIn           : 0
        itemsPacketsOut          : 0
        logDate                  : 1/20/2021 6:26:54 PM
        login                    :
        logMessage               : <aie v="1"><_0 FactCount="1" NormalMsgDate="2021-01-20 18:26:54" NormalMsgDateLower="2021-01-20 18:26:54" NormalMsgDateUpper="2021-01-20 18:26:55" Process="calc.exe" RuleBlockType="1" /><_
                                AIERuleID="1000000002" DateEdited="2020-12-17 17:42:59" /></aie>
        logSourceHostId          : -1000001
        logSourceHostName        : AI Engine Server
        logSourceName            : AI Engine
        logSourceTypeName        : LogRhythm AI Engine
        messageId                : 98829
        mpeRuleId                : -1
        mpeRuleName              :
        normalDateMax            : 1/1/0001 12:00:00 AM
        objectName               :
        objectType               :
        originEntityId           : -100
        originEntityName         : Global Entity
        originHostId             : -1
        originHostName           :
        originInterface          :
        originIP                 :
        originLocation           : @{countryCode=; name=; latitude=0; locationId=0; locationKey=; longitude=0; parentLocationId=0; recordStatus=Deleted; regionCode=; type=NULL; dateUpdated=1/1/0001 12:00:00 AM}
        originMAC                :
        originName               :
        originNATIP              :
        originNATPort            :
        originNetwork            : @{beginIPRange=; dateUpdated=1/1/0001 12:00:00 AM; riskThreshold=; endIPRange=; entityId=0; hostZone=Unknown; locationId=0; longDesc=; name=; networkId=0; recordStatus=Deleted; shortDesc=}
        originPort               : -1
        originZone               : Unknown
        parentProcessId          :
        parentProcessName        :
        parentProcessPath        :
        policy                   :
        priority                 : 24
        process                  : calc.exe
        processId                : 9
        protocolId               : -1
        protocolName             :
        quantity                 : 0
        rate                     : 0
        reason                   :
        recipient                :
        result                   :
        responseCode             :
        sender                   :
        session                  :
        sessionType              :
        serialNumber             :
        serviceId                : -1
        serviceName              :
        severity                 :
        status                   :
        size                     : 0
        subject                  :
        threatId                 :
        threatName               :
        url                      :
        userAgent                :
        vendorInfo               :
        vendorMsgId              :
        version                  :
        originUserIdentityName   :
        impactedUserIdentityName :
        originUserIdentityId     :
        impactedUserIdentityId   :
        senderIdentityId         :
        senderIdentityName       :
        recipientIdentityId      :
        recipientIdentityName    :
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [Int32] $AlarmId,


        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $ResultsOnly,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AlarmBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy        
    }

    Process {
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Verify version
        if ([int]$LrtConfig.LogRhythm.Version.split(".")[1] -le 6) {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.7.0 and greater."
            return $ErrorObject
        }

        $RequestUrl = $BaseUrl + "/alarms/" + $AlarmId + "/events"

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }


        # If ResultsOnly flag is provided, return only the alarmEventsDetails.
        if ($ResultsOnly) {
            return $Response.alarmEventsDetails
        } else {
            return $Response
        }
    }

    End { }
}