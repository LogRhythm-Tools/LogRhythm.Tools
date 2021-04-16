using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Update-LrAlarm {
    <#
    .SYNOPSIS
        Update the status or Risk Based Priority for a specific Alarm from the LogRhythm SIEM.
    .DESCRIPTION
        Update-LrAlarm returns a summary LogRhythm Alarm object properties that have been updated.
    .PARAMETER AlarmStatus
        String value representing the updated AlarmStatus.  
        
        If not provided the AlarmStatus will remain unchanged.

        Valid entries: New, Opened, Working, Escalated, Closed, Closed_FalseAlarm, Closed_Resolved
                       Closed_Unresolved, Closed_Reported, Closed_Monitor
    .PARAMETER RBP
        Intiger value applied as a new value for the Alarm's Risk Based Priority score.

        If not provided the RBP will remain unchanged.

        Valid range: 0-100
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.Int]           -> PageCount
        [System.String]        -> Name
        [System.String]        -> Entity
        [System.String]        -> RecordStatus
        [System.String[array]] -> HostIdentifier
        [System.Switch]        -> Exact
    .OUTPUTS
        PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Get-LrAlarm -AlarmId 185 -Verbose
        --- 

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
        [ValidateSet(
            'new',
            'opened',
            'working',
            'escalated',
            'closed',
            'closed_falsealarm',
            'closed_resolved',
            'closed_reported',
            'closed_monitor',
            0, 1, 2, 3, 4,
            5, 6, 7, 8, 9,
            ignorecase=$true
        )]
        [String] $AlarmStatus,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(0, 100)]
        [Int32] $RBP,


        [Parameter(Mandatory = $false, Position = 3)]
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
        $Method = $HttpMethod.Patch

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LogRhythm.Version

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

        # Ensure proper syntax RecordStatus
        if ($AlarmStatus) {
            $ValidStatus = Test-LrAlarmStatus -Id $AlarmStatus
            if ($ValidStatus.IsValid -eq $true) {
                $_alarmStatus = $ValidStatus.AlarmStatus
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Code  = 416
                $ErrorObject.Type  = "AlarmStatus is not valid."
                $ErrorObject.Note = "Value provided did not pass Test-LrAlarmStatus validation."
                $ErrorObject.Raw = $ValidStatus
            }
        } else {
            $AlarmDetails = Get-LrAlarm -AlarmId $AlarmId
            if ($AlarmDetails.error -ne $true) {
                $ValidStatus = Test-LrAlarmStatus -Id $AlarmDetails.alarmStatus
                $_alarmStatus = $ValidStatus.AlarmStatus
            }
        }

        if ($RBP) {
            $_RBP = $RBP
        } else {
            $AlarmDetails = Get-LrAlarm -AlarmId $AlarmId
            if ($AlarmDetails.error -ne $true) {
                $_RBP = $AlarmDetails.rbpMax
            }
        }

        $BodyContents = [PSCustomObject]@{
            AlarmStatus = $_alarmStatus
            rBP = $_RBP
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json

        Write-Verbose "$Body"


        $RequestUrl = $BaseUrl + "/alarms/" + $AlarmId

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        if ($Response.alarmDetails) {
            return $Response.alarmDetails
        } else {
            return $Response
        }
        
    }

    End {
    }
}