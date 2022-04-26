using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCaseStatusTable {
    <#
    .SYNOPSIS
        Get a list of all LogRhythm Case Status names and numbers.
    .DESCRIPTION
        Get-LrCaseStatusTable simply outputs a list of the 5 status names.
    .INPUTS
        None
    .OUTPUTS
        System.Collections.Generic.List[Object]
    .EXAMPLE
        PS> Get-LrCaseStatusTable
        ---
        Number      : 1
        Name        : Created
        State       : Open
        Transitions : {Completed, Incident}
        Type        : Case

        Number      : 2
        Name        : Completed
        State       : Closed
        Transitions : {Created}
        Type        : Case

        Number      : 3
        Name        : Incident
        State       : Open
        Transitions : {Created, Mitigated}
        Type        : Incident

        Number      : 4
        Name        : Mitigated
        State       : Open
        Transitions : {Incident, Resolved}
        Type        : Incident

        Number      : 5
        Name        : Resolved
        State       : Closed
        Transitions : {Mitigated}
        Type        : Incident
    .EXAMPLE
        PS> Get-LrCaseStatusTable | Format-Table
        ---
        Number Name      State  Transitions           Type
        ------ ----      -----  -----------           ----
            1 Created   Open   {Completed, Incident} Case
            2 Completed Closed {Created}             Case
            3 Incident  Open   {Created, Mitigated}  Incident
            4 Mitigated Open   {Incident, Resolved}  Incident
            5 Resolved  Closed {Mitigated}           Incident
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [int] $Number,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)]
        [ValidateSet('Created', 'Completed', 'Incident', 'Mitigated', 'Resolved', ignorecase=$true)]
        [string] $Name
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # Create an object for each status
        $Created = [PSCustomObject]@{
            Number      = 1
            Name        = "Created"
            State       = "Open"
            Transitions = @("Completed", "Incident")
            Type        = "Case"
        }

        $Completed = [PSCustomObject]@{
            Number      = 2
            Name        = "Completed"
            State       = "Closed"
            Transitions = @("Created")
            Type        = "Case"
        }

        $Incident = [PSCustomObject]@{
            Number      = 3
            Name        = "Incident"
            State       = "Open"
            Transitions = @("Created", "Mitigated")
            Type        = "Incident"
        }

        $Mitigated = [PSCustomObject]@{
            Number      = 4
            Name        = "Mitigated"
            State       = "Open"
            Transitions = @("Incident", "Resolved")
            Type        = "Incident"
        }

        $Resolved = [PSCustomObject]@{
            Number      = 5
            Name        = "Resolved"
            State       = "Closed"
            Transitions = @("Mitigated")
            Type        = "Incident"
        }


        # Create List
        $StatusList = [list[Object]]::new()
        $StatusList.Add($Created)
        $StatusList.Add($Completed)
        $StatusList.Add($Incident)
        $StatusList.Add($Mitigated)
        $StatusList.Add($Resolved)
    }


    Process {
        if ($Number) {
            return ($StatusList | Where-Object { $_.Number -eq $Number })
        }
    
        if ($Name) {
            return ($StatusList | Where-Object { $_.Name -eq $Name })
        }

        return $StatusList
    }


    End { }
}