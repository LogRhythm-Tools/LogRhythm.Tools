using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrListValue {
    <#
    .SYNOPSIS
        Identifies if provided value is a member of a list.
    .DESCRIPTION
        The Test-LrListValue cmdlet displays information about a given value's
        presence on a specific LogRhythm List.
    .PARAMETER Value
        The LogRhythm List Value to be tested.
    .PARAMETER Name
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13   
    .INPUTS
        [System.String] -> Value   The Value parameter can be provided via the PowerShell pipeline.
        [System.String] -> Name
    .OUTPUTS
        System.Object with IsPresent, Value, ValueType, ListValid, ListName, ListGuid
    .EXAMPLE
        C:\PS> Test-LrListValue -Value "192.168.5.1" -Name "srfIP"
            IsPresent : True
            Value     : 192.168.5.1
            ValueType : IP
            ListValid : True
            ListName  : srfIP
            ListGuid  : 81059751-823E-4F5B-87BE-FEFFF1708E5E
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position=0
        )]
        [ValidateNotNull()]
        [string] $Value,

        [Parameter(
            Mandatory = $true,
            Position=0
        )]
        [ValidateNotNull()]
        [string] $Name
    )
    Begin {
        # Establish output object
        $OutObject = [PSCustomObject]@{
            IsPresent   =   $false
            Value       =   $Value
            ValueType   =   $null
            ListValid   =   $false
            ListName    =   $null
            ListGuid    =   $null
        }

        # Process List Name Object
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
            $Guid = $Name.ToString()
            $OutObject.ListName = (Get-LrList -Name $Guid | Select-Object -ExpandProperty Name)
        } else {
            Try {
                $Guid = Get-LRListGuidByName -Name $Name.ToString() -Exact
                $OutObject.ListValid = $true
            } Catch {
                $OutObject.ListValid = $false
            }
            # Set ListName for OutObject
            $OutObject.ListName = $Name.ToString()
        }
        # Set ListGuid and ListValid for OutObject
        $OutObject.ListGuid = $Guid
    }

    Process {
        Try {
            $ListItems = Get-LrListItems -Name $Guid
            $OutObject.ListValid = $true
        } Catch {
            $OutObject.ListValid = $false
        }
        
        # Review each item from ListItems and compare to Parameter Value
        foreach ($Item in $ListItems) {
            if ($Item.value -eq $Value) {
                $OutObject.Value = $Item.value
                $OutObject.IsPresent = $true
                $OutObject.ValueType = $Item.listItemType
            }
        }

        Return $OutObject
    }

    End { }
}