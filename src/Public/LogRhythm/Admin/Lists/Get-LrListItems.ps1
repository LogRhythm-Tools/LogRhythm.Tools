using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrListItems {
    <#
    .SYNOPSIS
        Retrieve the specified list items from LogRhythm.
    .DESCRIPTION
        Get-LrListItems returns a full LogRhythm List Items object, including it's details.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Name
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER MaxItemsThreshold
        The maximum number of list items to retrieve from LogRhythm.
        The default value for this parameter is set to 1000.
    .PARAMETER Exact
        Switch to force PARAMETER Name to be matched explicitly.
    .INPUTS
        The Name parameter can be provided via the PowerShell pipeline.
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List contents.
    .EXAMPLE
        PS C:\> Get-LrListItems -Name "edea82e3-8d0b-4370-86f0-d96bcd4b6c19"
    .EXAMPLE
        PS C:\> Get-LrListItems -Name "Privileged Users: Local System Administrators" -Exact
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(1, 10000000)]
        [int] $MaxItemsThreshold = 10000000,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $ValuesOnly,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Value                 =   $Value
            Note                  =   $null
            Raw                   =   $null
        }

        # Process Identity Object
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
            $Guid = $Name.ToString()
        } else {
            if ($Exact) {
                $Guid = Get-LRListGuidByName -Name $Name.ToString() -Exact
            } else {
                $Guid = Get-LRListGuidByName -Name $Name.ToString()
            }
            if ($Guid.Error -eq $true ) {
                return $Guid
            } 
        }

        # Send Request
        $Response = Get-LrList -Name $Guid
        
        # Validate if error is present in cmdlet return
        if ($Response.Error -eq $true) {
            return $Response
        } else {
            $ResponseItems = $Response | Select-Object items
        }
        
        
        
        # Process Results
        if ($ValuesOnly) {
            $ReturnList = $($ResponseItems.items | Select-Object -ExpandProperty "value")
        } else {
            $ReturnList = $ResponseItems.items
        }
        

        if ($ValuesOnly) {
            return ,$ReturnList
        } else {
            return $ReturnList
        }
        
    }

    End { }
}