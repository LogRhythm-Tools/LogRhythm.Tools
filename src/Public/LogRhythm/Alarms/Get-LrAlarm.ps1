using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrAlarm {
    <#
    .SYNOPSIS
        Retrieve the details from a specific Alarm from the LogRhythm SIEM.
    .DESCRIPTION
        Get-LrAlarm returns a detailed LogRhythm Alarm object.
    .PARAMETER AlarmId
        Intiger representing the Alarm required for detail retrieval.
    .PARAMETER ResultsOnly
        Switch used to specify return only alarmDetails results.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.Int]          -> AlarmId
        [System.Switch]       -> ResultsOnly
        [PSCredential]        -> Credential
    .OUTPUTS
        PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Get-LrAlarm -AlarmId 185
         

        alarmDetails    : @{alarmRuleID=1000000007; alarmId=185; personId=6; alarmDate=3/31/2021 8:54:01 PM; alarmStatus=1; alarmStatusName=Opened; entityId=-100; entityName=Global Entity; alarmRuleName=AIE: MAC Address
                  Observed; lastUpdatedID=6; lastUpdatedName=Hart, Eric AD; dateInserted=3/31/2021 8:54:01 PM; dateUpdated=4/20/2021 12:16:26 PM; associatedCases=System.Object[]; lastPersonID=6; eventCount=1;
                  eventDateFirst=3/31/2021 8:54:33 PM; eventDateLast=3/31/2021 8:54:33 PM; rbpMax=35; rbpAvg=35; smartResponseActions=; alarmDataCached=Y}
        statusCode      : 200
        statusMessage   : OK
        responseMessage : Success

    .EXAMPLE
        PS C:\> Get-LrAlarm -AlarmId 185 -ResultsOnly
        

        alarmRuleID          : 1000000007
        alarmId              : 185
        personId             : 6
        alarmDate            : 3/31/2021 8:54:01 PM
        alarmStatus          : 7
        alarmStatusName      : Closed: Unresolved
        entityId             : -100
        entityName           : Global Entity
        alarmRuleName        : AIE: MAC Address Observed
        lastUpdatedID        : 6
        lastUpdatedName      : Hart, Eric AD
        dateInserted         : 3/31/2021 8:54:01 PM
        dateUpdated          : 4/16/2021 1:14:02 PM
        associatedCases      : {13277FFF-B723-42E7-8D10-D7464646E6B7,  5E5E9EE0-EF92-4280-89F8-E64F37798B67}
        lastPersonID         : 6
        eventCount           : 1
        eventDateFirst       : 3/31/2021 8:54:33 PM
        eventDateLast        : 3/31/2021 8:54:33 PM
        rbpMax               : 0
        rbpAvg               : 0
        smartResponseActions :
        alarmDataCached      : Y
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


        [Parameter(Mandatory = $false, Position = 1)]
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

        $RequestUrl = $BaseUrl + "/lr-alarm-api/alarms/" + $AlarmId

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        if ($ResultsOnly) {
            return $Response.alarmDetails
        } else {
            return $Response
        }
        
    }

    End {}
}