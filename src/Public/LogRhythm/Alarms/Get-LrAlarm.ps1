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



        $RequestUrl = $BaseUrl + "/alarms/" + $AlarmId

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

        if ($Response.alarmDetails) {
            return $Response.alarmDetails
        } else {
            return $Response
        }
        
    }

    End {
    }
}