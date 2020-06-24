using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrListGuidByName {
    <#
    .SYNOPSIS
        Get the unique identifier for a list, based on a search by list name.
    .DESCRIPTION
       Get-LRListGuidByName returns the Guid for a specified list name.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Name
        The name of the object or regex match.
    .PARAMETER Exact
        Switch to force PARAMETER Name to be matched explicitly.
    .INPUTS
        The Name parameter can be passed through the pipeline. (Does not support array)
    .OUTPUTS
        System.String (guid format)
    .EXAMPLE
        PS C:\> Get-LRListGuidByName "MyListName"
        FDD09F74-32A1-438A-A694-D36E9C4B7E17
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory=$true,Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter(Mandatory = $false, Position=2)]
        [switch] $Exact
    )

    Begin {
    }


    Process {

        try {
            if ($Exact) {
                $Response = Get-LrLists -Name $Name -Exact
            } else {
                $Response = Get-LrLists -Name $Name
            }
        }
        catch [System.Net.WebException] {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }

        if ($Response) {
            return $Response.Guid
        }
        return $null
    }


    End { }
}