using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrAlarmStatus {
    <#
    .SYNOPSIS
        Validates provided LogRhythm Alarm Status is a valid Status type.
    .DESCRIPTION

    .PARAMETER Id
        The LogRhythm AlarmStatus to be tested.
    .INPUTS
        [System.String] -> Id
    .OUTPUTS
        System.Object with IsValid, Value
    .EXAMPLE
        C:\PS> Test-LrListType "commonevent"
        IsValid    Value
        -------    -----
        True    CommonEvent
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position=0)]
        [ValidateNotNull()]
        [string] $Id
    )
    Begin { 
        $Me = $MyInvocation.MyCommand.Name
    }
    
    Process {
        $OutObject = [PSCustomObject]@{
            IsValid               =   $false
            AlarmStatus           =   $null
            AlarmStatusID         =   $null
            SubmittedId           =   $Id
            SubmittedType         =   $null
        }

        $_int = 0

        $ValidStatus = [PSCustomObject]@{
            0 = "New"
            1 = "Opened"
            2 = "Working"
            3 = "Escalated"
            4 = "Closed"
            5 = "Closed_FalseAlarm"
            6 = "Closed_Resolved"
            7 = "Closed_Unresolved"
            8 = "Closed_Reported"
            9 = "Closed_Monitor"
        }

        # Validate if Id is AlarmStatus# or AlarmStatus String
        if ([int]::TryParse($Id, [ref]$_int)) {
            $OutObject.SubmittedType = "Int"
            if ([int]$Id -ge 0 -and [int]$Id -le 9) {
                $OutObject.IsValid = $true
                $OutObject.AlarmStatus = $ValidStatus.$Id
                $OutObject.AlarmStatusID = $Id
            }
        } else {
            $OutObject.SubmittedType = "String"
            $StatusMembers = $ValidStatus.psobject.Members | where-object membertype -like 'noteproperty'
            foreach ($AlarmStatus in $StatusMembers) {
                # Now you can do what you want with the name and value.
                if ($Id -like $AlarmStatus.Value) {
                    $OutObject.IsValid = $true
                    $OutObject.AlarmStatus = $AlarmStatus.Value
                    $OutObject.AlarmStatusID = $AlarmStatus.Name
                    # Exit For loop if value is matched
                    break
                }
            }
        }
        
        return $OutObject
    }
}