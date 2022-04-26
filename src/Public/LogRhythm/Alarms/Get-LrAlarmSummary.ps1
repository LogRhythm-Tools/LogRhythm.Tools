using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Get-LrAlarmSummary {
    <#
    .SYNOPSIS
        Retrieve the event data details from a specific Alarm from the LogRhythm SIEM.
    .DESCRIPTION
        Get-LrAlarm returns a detailed LogRhythm Alarm object.
    .PARAMETER AlarmId
        Intiger representing the Alarm required for detail retrieval.
    .PARAMETER ResultsOnly
        Switch used to specify return only alarmSummaryDetails results.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.Int]          -> AlarmId
        [System.Switch]       -> ResultsOnly
        [PSCredential]        -> Credential
    .OUTPUTS
        PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Get-LrAlarmSummary -AlarmId 185

        alarmSummaryDetails                                                                                                                                                           statusCode statusMessage responseMessage
        -------------------                                                                                                                                                           ---------- ------------- ---------------
        @{dateInserted=1/20/2021 6:26:41 PM; rbpMax=24; rbpAvg=24; alarmRuleId=1000000002; alarmRuleGroup=; briefDescription=; additionalDetails=; alarmEventSummary=System.Object[]}        200 OK            Success
    .EXAMPLE
        PS C:\> Get-LrAlarmSummary -AlarmId 185 -ResultsOnly
        
        dateInserted      : 1/20/2021 6:26:41 PM
        rbpMax            : 24
        rbpAvg            : 24
        alarmRuleId       : 1000000002
        alarmRuleGroup    :
        briefDescription  :
        additionalDetails :
        alarmEventSummary : {@{msgClassId=2200; msgClassName=Suspicious; commonEventId=1000000002; commonEventName=AIE: Test Rule - Calc.exe; originHostId=-1; impactedHostId=-1; originUser=; impactedUser=;
                            originUserIdentityId=; impactedUserIdentityId=; originUserIdentityName=; impactedUserIdentityName=; originEntityName=Global Entity; impactedEntityName=Global Entity}}
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
        $Me = $MyInvocation.MyCommand.Name

        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
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

        $RequestUrl = $BaseUrl + "/lr-alarm-api/alarms/" + $AlarmId + "/summary"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }


        # If ResultsOnly flag is provided, return only the alarmSummaryDetails.
        if ($ResultsOnly) {
            return $Response.alarmSummaryDetails
        } else {
            return $Response
        }
    }

    End { }
}