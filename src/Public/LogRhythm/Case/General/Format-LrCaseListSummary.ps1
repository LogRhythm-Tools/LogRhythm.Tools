using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Format-LrCaseListSummary {
    <#
    .SYNOPSIS
        Get summary information about a list of LogRhythm Cases.
    .DESCRIPTION
        The Format-LrCaseListSummary cmdlet takes an array of LogRhythm Case details
        and creates a summary report of the information.
        
        *IMPORTANT*: You may need to use the unary array operator ',' when passing a
        list of cases via the pipeline to avoid operating on each array element individually.
        See examples for more information.
    .PARAMETER InputObject
        An array of LogRhythm Case objects as returned by the Get-LrCases cmdlet.
    .INPUTS
        System.Object[] -> InputObject
    .OUTPUTS
        PSCustomObject with summary information about the case list.
    .EXAMPLE
        PS C:\> ,(Get-LrCases -Credential $token -CreatedAfter "2018-10-01 00:00:00") | Format-LrCaseListSummary
        ---
            Count       : 500
            Oldest      : 2018-10-01T20:22:55.227Z
            Newest      : 2019-02-05T16:12:56.07Z
            OpenCount   :
            ClosedCount : 500
            Tags        : {@{Name=Privilege Escalation; Count=17}, @{Name=Duplicate; Count=1}...}
            Status      : {@{Name=Completed; Count=498}, @{Name=Resolved; Count=2}}
            Owners      : {@{Name=Cruise, Frank; Count=463}, @{Name=Smith, Bob; Count=36}...}
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [object[]] $InputObject
    )


    Begin { }


    Process {
        # Validation - This is just a small sanity check. If user passes an LR API response,
        # the input objects should be properly formed.
        if (! ($InputObject[0].PSobject.Properties.Name -contains "id")) {
            throw [ArgumentException] `
                "Property 'id' not found in InputObject. InputObject must be valid LrCase."
        }

        # Determine Average Time to Close Case
        $CloseTimeSpans = [List[timespan]]::new()
        $InputObject | ForEach-Object {
            if ($_.dateCreated -and $_.dateClosed) {
                $CloseTimeSpans.Add([datetime] $_.dateClosed - [datetime] $_.dateCreated)    
            }
        }

        # Generate report
        $Report = [PSCustomObject]@{
            Count = $InputObject.Count
            Oldest = $InputObject | Select-Object -ExpandProperty dateCreated | Sort-Object | Select-Object -First 1
            Newest = $InputObject | Select-Object -ExpandProperty dateCreated | Sort-Object | Select-Object -Last 1

            AvgCloseTimeDays = ($CloseTimeSpans | Measure-Object -Average -Property TotalDays).Average
            AvgCloseTimeHours = ($CloseTimeSpans | Measure-Object -Average -Property TotalHours).Average

            TotalOpen = ($InputObject | Select-Object -ExpandProperty status | 
                Where-Object { $_.Name -in @("Created", "Incident") } | 
                Group-Object -Property name | 
                Measure-Object -Property Count -Sum).Sum


            TotalClosed = ($InputObject | Select-Object -ExpandProperty status | 
                Where-Object { $_.Name -in @("Completed", "Mitigated", "Resolved") } | 
                Group-Object -Property name | 
                Measure-Object -Property Count -Sum).Sum


            DistinctTags = ($InputObject | Select-Object -ExpandProperty tags |
                Select-Object -ExpandProperty text | 
                Sort-Object -Unique | 
                Measure-Object).Count


            DistinctOwners = ($InputObject | Select-Object -ExpandProperty owner |
                Select-Object -ExpandProperty number | 
                Sort-Object -Unique | 
                Measure-Object).Count


            Tags = $InputObject | Select-Object -ExpandProperty tags | 
                Group-Object -Property text | 
                Select-Object -Property Name, Count


            Status = $InputObject | Select-Object -ExpandProperty status | 
                Group-Object -Property name | 
                Select-Object -Property Name, Count


            Owners = $InputObject |  Select-Object -ExpandProperty owner | 
                Group-Object -Property name | 
                Select-Object -Property Name, Count
        }

        return $Report
    }


    End { }
}