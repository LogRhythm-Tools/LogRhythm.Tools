using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Measure-LrCaseMetrics {
    <#
    .SYNOPSIS
        Generates an average TTD, TTR, TTE, and TTC for a set of LogRhythm Cases.
    .DESCRIPTION
        xxxx
    .PARAMETER InputObject
        A collection of LogRhythm Case Objects passed through the pipeline or from 
        a list or array.
    .PARAMETER param2
        xxxx
    .INPUTS
        System.Object -> $InputObjectList
    .OUTPUTS
        xxxx
    .EXAMPLE
        xxxx
    .EXAMPLE
        xxxx
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [Object] $InputObject,


        [Parameter(Mandatory = $false, Position = 1)]
        [string[]] $Tags
    )


    Begin {
        # Total cases, regardless of whether they have a TTD,TTR, etc.
        $Total_Cases = 0
        $Total_Incidents = 0

        $TTD_Total = 0
        $TTD_Count = 0

        $TTR_Total = 0
        $TTR_Count = 0

        $TTE_Total = 0
        $TTE_Count = 0

        $TTC_Total = 0
        $TTC_Count = 0

        $Priority_Total = 0

        $Result = [PSCustomObject]@{
            Total_Cases      = 0
            Total_Incidents  = 0
            Priority_Average = 0
            TTD_Average      = 0
            TTR_Average      = 0
            TTE_Average      = 0
            TTC_Average      = 0
        }

        # Add a property for each requested tag to Result object
        foreach ($tag in $Tags) {
            $Result | Add-Member -MemberType NoteProperty -Name $tag -Value 0
        }
    }


    Process {

        # Case Count
        $Total_Cases++

        # Priority Average
        $Priority_Total += $InputObject.Priority

        # Incident Count
        $StatusType = (Get-LrCaseStatusTable -Number $InputObject.Status.Number).Type
        if ($StatusType -eq "Incident") {
            $Total_Incidents++
        }

        # TTD
        if ( -not ($InputObject.Metrics.TTD -match "N/A")) {
            $TTD_Total += $InputObject.Metrics.TTD.TotalSeconds
            $TTD_Count++
        }

        # TTR
        if ( -not ($InputObject.Metrics.TTR -match "N/A")) {
            $TTR_Total += $InputObject.Metrics.TTR.TotalSeconds
            $TTR_Count++
        }

        # TTE
        if ( -not ($InputObject.Metrics.TTE -match "N/A")) {
            $TTE_Total += $InputObject.Metrics.TTE.TotalSeconds
            $TTE_Count++
        }
        
        # TTC
        if ( -not ($InputObject.Metrics.TTC -match "N/A")) {
            $TTC_Total += $InputObject.Metrics.TTC.TotalSeconds
            $TTC_Count++
        }

        # Measure Tags
        foreach ($tag in $Tags) {
            if ($InputObject.Tags) {
                if (($InputObject.Tags | Select-Object -ExpandProperty Text).Contains($tag)) {
                    $Result.$tag++
                }
            }
        }
    }


    End {
        $Result.Total_Cases = $Total_Cases
        $Result.Priority_Average = $Priority_Total / $Total_Cases
        $Result.Total_Incidents = $Total_Incidents

        if ($TTD_Count -gt 0) {
            $Result.TTD_Average = [timespan]::FromSeconds($TTD_Total / $TTD_Count)
        }

        if ($TTR_Count -gt 0) {
            $Result.TTR_Average = [timespan]::FromSeconds($TTR_Total / $TTR_Count)
        }
        
        if ($TTE_Count -gt 0) {
            $Result.TTE_Average = [timespan]::FromSeconds($TTE_Total / $TTE_Count)
        }

        if ($TTC_Count -gt 0) {
            $Result.TTC_Average = [timespan]::FromSeconds($TTC_Total / $TTC_Count)
        }
        
        
        return $Result
     }
}