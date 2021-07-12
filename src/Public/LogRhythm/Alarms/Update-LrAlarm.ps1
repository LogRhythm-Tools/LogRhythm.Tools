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
                       1, 2, 3, 4, 5, 6, 7, 8, 9
    .PARAMETER RBP
        Intiger value applied as a new value for the Alarm's Risk Based Priority score.

        If not provided the RBP will remain unchanged.

        Valid range: 0-100
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.Int]          -> AlarmId
        [System.String]       -> AlarmStatus
        [System.Int]          -> RBP
        [System.Switch]       -> PassThru
        [PSCredential]        -> Credential
    .OUTPUTS
        By defaul the output is null unless an error is generated.
        
        With the PassThru switch a PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Update-LrAlarm -AlarmId 185 -AlarmStatus New
         
    .EXAMPLE
        PS C:\> Update-LrAlarm -AlarmId 185 -AlarmStatus opened -RBP 35
        
    .EXAMPLE
        PS C:\> Update-LrAlarm -AlarmId 185 -AlarmStatus New -PassThru 

        statusCode statusMessage responseMessage
        ---------- ------------- ---------------
            200 OK            Success
    .EXAMPLE
        PS C:\> Update-LrAlarm -AlarmId 185 -AlarmStatus opened -RBP 35 -PassThru

        statusCode statusMessage responseMessage
        ---------- ------------- ---------------
            200 OK            Success
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
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Patch

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
            $AlarmDetails = Get-LrAlarm -AlarmId $AlarmId -ResultsOnly
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


        $RequestUrl = $BaseUrl + "/lr-alarm-api/alarms/" + $AlarmId

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

        if ($PassThru) {
            if ($Response.alarmDetails) {
                return $Response.alarmDetails
            } else {
                return $Response
            }
        }
    }

    End {
    }
}