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
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param()

    # Create an object for each status
    $Created = [PSCustomObject]@{
        Number      = 1
        Name        = "Created"
        State       = "Open"
        Transitions = @("Completed", "Incident")
    }

    $Completed = [PSCustomObject]@{
        Number      = 2
        Name        = "Completed"
        State       = "Closed"
        Transitions = @("Created")
    }

    $Incident = [PSCustomObject]@{
        Number      = 3
        Name        = "Incident"
        State       = "Open"
        Transitions = @("Created", "Mitigated")
    }

    $Mitigated = [PSCustomObject]@{
        Number      = 4
        Name        = "Mitigated"
        State       = "Open"
        Transitions = @("Incident", "Resolved")
    }

    $Resolved = [PSCustomObject]@{
        Number      = 5
        Name        = "Resolved"
        State       = "Closed"
        Transitions = @("Mitigated")
    }

    # Create a list and add each status
    $StatusList = [list[Object]]::new()
    $StatusList.Add($Created)
    $StatusList.Add($Completed)
    $StatusList.Add($Incident)
    $StatusList.Add($Mitigated)
    $StatusList.Add($Resolved)

    return $StatusList
}