using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrCaseEarliestEvidenceFromDrilldown {
    <#
    .SYNOPSIS
        Update the earliest evidence timestamp of an existing case using timestamps from AIE Drilldown Results
    .DESCRIPTION
        The Update-LrCaseEarliestEvidenceFromDrilldown cmdlet updates an existing case's earliest evidence based on a timestamp
        representing the earliest point in the cases evidence origination.

        Case Status must not be closed.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER AlarmID
        Unique identifier for the LogRhythm Alarm.
    .PARAMETER Quiet
        Indicates that this cmdlet suppresses all output.
    .INPUTS
        [System.Object]   ->  Id
        [System.Int32]    ->  AlarmID
    .OUTPUTS
        Optional summary output to validate Case Update status.
    .EXAMPLE
        PS C:\> Update-LrCaseEarliestEvidenceFromDrilldown -Id 8699 -AlarmId 396658 -Summary
        ---
        Updated Case: 8699 Based on Alarm: 396658 Drilldown Date: 2019-12-19T08:58:40Z
    .EXAMPLE
        PS C:\> Update-LrCaseEarliestEvidenceFromDrilldown -Id 2 -AlarmId 6 -PassThru  
        ---
        RequestedTimestamp: 07/17/2020 00:39:21 is greater than CaseCreateDate: 06/06/2020 13:46:49
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 0
        )]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $AlarmId,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $Summary,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $ProcessedCount = 0
    }


    Process {
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }

        # Get Alarm AIEDrilldown Results
        $DrilldownResults = Get-LrAieDrilldown -AlarmId $AlarmId

        # Identify Earliest Log
        $EarliestLog = $null
        Try {
            $Logs = $DrilldownResults.Logs
            $MinDate = ($Logs.normalDate | Measure-Object -Minimum).Minimum
            Write-Verbose "[$Me]: MinDate: $MinDate"
            if (($null -eq $EarliestLog) -or ($MinDate -lt $EarliestLog)) {
                
                #Update the Earliest Log if it's earlier
                $EarliestLog = $MinDate
            }
        } Catch {
            # Error occured during deserialization
            return $null
        }

        # Set EarliestLogDate
        $EarliestLogDate = (Get-Date "1970-01-01T00:00:00").AddMilliseconds($EarliestLog)
        Write-Verbose "[$Me]: Alarm: $AlarmId EarliestLogDate: $EarliestLogDate"

        # Convert NewEarliestEvidence date to proper format
        $NewEarliestEvidence = ($EarliestLogDate.ToString("yyyy-MM-ddTHH:mm:ssZ"))

        # Send Request
        $Response = Update-LrCaseEarliestEvidence -Id $CaseNumber -Timestamp $NewEarliestEvidence -Summary
        $ProcessedCount++

        # Return
        if ($PassThru) {
            return $Response    
        }
    }

    
    End {
        if ($Summary) {
            if ($UpdateEvidence -eq $true) {
                Write-Host "Updated Case: $CaseNumber Based on Alarm: $AlarmId Drilldown Date: $NewEarliestEvidence"
            } else {
                Write-Host "Unable to Update Case: $CaseNumber Based on Alarm: $AlarmId Drilldown Date: $NewEarliestEvidence Existing Date: $EarliestEvidenceDate"
            }
        }
    }
}