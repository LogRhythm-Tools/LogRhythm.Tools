using namespace System
using namespace System.IO
using namespace System.Net
using namespace System.Collections.Generic

Function Sync-LrListItems {
    <#
    .SYNOPSIS
        Synchronizes the provided value(s) to the specified list from LogRhythm.
    .DESCRIPTION
        New items from the provided value(s) are added to the specifified list.

        Items that exist on the provided value(s) and in the specified list are unchanged.

        Items that are not provided in the value(s) are removed from the specified list.
    .PARAMETER Name
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER Value
        The value to be added to the specified LogRhythm List Identity.
    .PARAMETER ItemType
        For use with Lists that support multiple item types.  Add-LrListItem will attempt to auto-define
        this value.  This parameter enables setting the ItemType.
    .PARAMETER IsPattern
        Switch Paramater that will specify the values being added are patterns.  

        If the values are provided with a prefix or postfix of % then that will be applied.  
        If no pattern % character is specified the default behavior will be to wrap the supplied value in %.

        Default behavior example:
            Submitted Value: hostname
            List Value: %hostname%
    .PARAMETER Clear
        Switch Paramater that will perform a synchronization of $null into the target list.  

        This paramater will cause the target list to have all list values removed.
    .INPUTS

    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List.

        If a Value parameter error is identified, a PSCustomObject is returned providing details
        associated to the error.
    .EXAMPLE
        Sync-LrListItems -Name "Network: Search : SSL/TLS" -Value $Null -PassThru

        ListGuid   : 3DBB29CB-AB09-4319-9D34-FEA8798DCF3D
        ListName   : Network: Search : SSL/TLS
        ValueCount : 0
        Before     : 502
        After      : 502
        Added      : 0
        Removed    : 502
    .EXAMPLE
        Sync-LrListItems -Name "LRT: Hashes" -Value $NewValues -PassThru

        ListGuid   : 11AF69E2-BDAA-4788-AD25-D6EE395B08E4
        ListName   : LRT: Hashes
        ValueCount : 50
        Before     : 50
        After      : 50
        Added      : 0
        Removed    : 0
        ListType   : GeneralValue
    .EXAMPLE
        Sync-LrListItems -Name "LRT: Hashes" -Clear -PassThru


        ListGuid   : 11AF69E2-BDAA-4788-AD25-D6EE395B08E4
        ListName   : LRT: Hashes
        ValueCount : 0
        Before     : 50
        After      : 0
        Added      : 0
        Removed    : 50
        ListType   : GeneralValue
    .EXAMPLE
        Sync-LrListItems -Name "LRT: Hashes" -Value "002438992142cec59436dfd31e75dabe" -PassThru

        ListGuid   : 11AF69E2-BDAA-4788-AD25-D6EE395B08E4
        ListName   : LRT: Hashes
        ValueCount : 1
        Before     : 0
        After      : 1
        Added      : 1
        Removed    : 0
        ListType   : GeneralValue
    .EXAMPLE 
        Sync-LrListItems -Name "LRT: Hashes" -PassThru -Value $NewValues

        ListGuid   : 11AF69E2-BDAA-4788-AD25-D6EE395B08E4
        ListName   : LRT: Hashes
        ValueCount : 50
        Before     : 1
        After      : 50
        Added      : 49
        Removed    : 0
        ListType   : GeneralValue
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Name,

        
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)]
        [string[]] $Value,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $Clear,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $IsPattern,


        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )
                                                                   
    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        if ($Value -is [array]) {
            $Value = $Value.Split('',[System.StringSplitOptions]::RemoveEmptyEntries)
        }
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $Value
            Note                  =   $null
            ListGuid              =   $null
            ListName              =   $null
            FieldType             =   $null
        }

        if (($Null -eq $Value) -And (! ($PSCmdlet.MyInvocation.BoundParameters["Clear"].IsPresent))) {
            $ErrorObject.Error = $true
            $ErrorObject.Note = "Null value submitted without the -Clear flag."
            $ErrorObject.ListName = $Name
            return $ErrorObject
        }

        # Establish General Output object
        $OutObject = [PSCustomObject]@{
            ListGuid              =   $null
            ListName              =   $null
            ValueCount            =   $($Value.count)
            Before                =   $null
            After                 =   $null
            Added                 =   $null
            Removed               =   $null
            ListType              =   $null
        }

        if ($IsPattern) {
            $_isPattern = $true
        } else {
            $_isPattern = $false
        }

        # Process Name
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
            Write-Verbose "Inspecting for List Name by GUID"
            $TargetList = Get-LrList -name $Name.ToString()
            if ($TargetList.Error -eq $true) {
                $ErrorObject.Error = $true
                $ErrorObject.ListName = $TargetList.Name
                $ErrorObject.ListGuid = $TargetList.Guid
                $ErrorObject.Note = $TargetList.Note
                return $ErrorObject
            } else {
                $OutObject.ListName = $TargetList.Name
                $OutObject.ListGuid = $TargetList.Guid
                $OutObject.Before = $TargetList.entryCount
                $OutObject.ListType = $TargetList.ListType
            }
        } else {
            Write-Verbose "Inspecting for List Name by Exact Name"
            $TargetList = Get-LrLists -Name $Name.ToString() -Exact
            if ($TargetList -is [array]) {
                $ErrorObject.Error = $true
                $ErrorObject.ListName = $Name.ToString()
                $ErrorObject.ListGuid = $Guid
                $ErrorObject.Note = "List lookup returned an array of values.  Ensure the list referenced is unique."
                return $ErrorObject
            } elseif ($TargetList.Error -eq $true) {
                $ErrorObject.Error = $true
                $ErrorObject.ListName = $TargetList.Name
                $ErrorObject.ListGuid = $TargetList.Guid
                $ErrorObject.Note = $TargetList.Note
                return $ErrorObject
            } else {
                $OutObject.ListName = $TargetList.Name
                $OutObject.ListGuid = $TargetList.Guid
                $OutObject.Before = $TargetList.entryCount
                $OutObject.ListType = $TargetList.ListType
            }
        }


        if ($OutObject.ListGuid) {
            Write-Verbose "[$Me]: $(Get-TimeStamp) - Retrieving List Values for: $($OutObject.ListName)"
            $ListValues = Get-LrListItems -Name $OutObject.ListGuid -ValuesOnly
            if ($Value.Count -ge 1 -And $ListValues.Count -ge 1) {
                Write-Verbose "[$Me]: $(Get-TimeStamp) - Number of ListValues: $($ListValues.Count) - Number of Values: $($Value.Count)"
                if ($_isPattern) {
                    $Items = [list[string]]::new()
                    ForEach ($Entry in $Value) {
                        if (!$Entry.StartsWith('%') -and !$Entry.EndsWith('%')) {
                            $Entry = '%' + $Entry + '%'
                        }
                        $Items.Add($Entry)
                    }
                }
                else {
                    $Items = $Value
                }
                $ComparisonResults = Compare-StringArrays $Items $ListValues -Unsorted
                Write-Verbose "[$Me]: $(Get-TimeStamp) - Comparison Complete"
                $RemoveList = $ComparisonResults | Where-Object SideIndicator -eq "=>" | Select-Object -ExpandProperty InputObject
                Write-Verbose "[$Me]: $(Get-TimeStamp) - RemoveList Count: $($RemoveList.Count)"
                $AddList = $ComparisonResults | Where-Object SideIndicator -eq "<=" | Select-Object -ExpandProperty InputObject
                Write-Verbose "[$Me]: $(Get-TimeStamp) - AddList Count: $($AddList.Count)"
            } elseif ($Value.Count -eq 0 -And $ListValues.Count -ge 1) {
                $RemoveList = $ListValues
            } else {
                $AddList = $Value
            }


            # Bulk remove of the RemoveList items
            if ($RemoveList) {
                Write-Verbose "[$Me]: $(Get-TimeStamp) - Remove Count: $($RemoveList.Count)"
                # Set quantity of removed values
                $OutObject.Removed = $RemoveList.Count
                # For large number of removals, break the additions into 1,000 items per API call
                if ($RemoveList.Count -ge 1000) {
                    Write-Verbose "[$Me]: $(Get-TimeStamp) - Enter Removal Segmentation"
                    $SegmentCount = ([Math]::Round(($($RemoveList.Count) / 1000), 0)) + 1
                    $SegmentedRemoveList = Create-LrPsArraySegments -InputArray $RemoveList -Segments $SegmentCount
                    foreach ($RemoveArray in $SegmentedRemoveList) {
                        Write-Verbose "[$Me]: $(Get-TimeStamp) - Submitting $($RemoveArray.count)"
                        Try {
                            Remove-LrListItem -name $OutObject.ListGuid -Value $RemoveArray -ItemType $OutObject.ListType
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit removal entries."
                            $ErrorObject.Value = $RemoveArray
                        }
                    }
                } else {
                    if ($ItemType) {
                        Try {
                            Remove-LrListItem -name $OutObject.ListGuid -Value $RemoveList -ItemType $OutObject.ListType
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit removal entries."
                            $ErrorObject.Value = $RemoveArray
                        }
                    } else {
                        Try {
                            Remove-LrListItem -name $OutObject.ListGuid -Value $RemoveList
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit removal entries."
                            $ErrorObject.Value = $RemoveArray
                        }
                    } 
                }
            } else {
                # Set quantity of removed values
                $OutObject.Removed = 0
            }

            # Bulk addition of the AddList items
            if ($AddList) {
                Write-Verbose "[$Me]: $(Get-TimeStamp) - Addition Count: $($AddList.Count)"
                # Set quantity of removed values
                $OutObject.Added = $AddList.Count
                # For large number of additions, break the additions into 1,000 items per API call
                if ($AddList.Count -ge 1000) {
                    Write-Verbose "[$Me]: $(Get-TimeStamp) - Enter Addition Segmentation"
                    $SegmentCount = ([Math]::Round(($($AddList.Count) / 1000), 0)) +1
                    $SegmentedAddList = Create-LrPsArraySegments -InputArray $AddList -Segments $SegmentCount
                    foreach ($AddArray in $SegmentedAddList) {
                        Write-Verbose "[$Me]: $(Get-TimeStamp) - Submitting $($AddArray.count)"
                        Try {
                            if ($_isPattern) {
                                Add-LrListItem -name $OutObject.ListGuid -Value $AddArray -ItemType $OutObject.ListType -IsPattern
                            } else {
                                Add-LrListItem -name $OutObject.ListGuid -Value $AddArray -ItemType $OutObject.ListType
                            }
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit addition entries."
                            $ErrorObject.Value = $AddArray
                        }
                    }
                } else {
                    if ($ItemType) {
                        Try {
                            if ($_isPattern) {
                                Add-LrListItem -name $OutObject.ListGuid -Value $AddArray -ItemType $OutObject.ListType -IsPattern
                            } else {
                                Add-LrListItem -name $OutObject.ListGuid -Value $AddArray -ItemType $OutObject.ListType
                            }
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit addition entries."
                            $ErrorObject.Value = $AddArray
                        }
                    } else {
                        Try {
                            if ($_isPattern) {
                                Add-LrListItem -Name $OutObject.ListGuid -Value $AddList -IsPattern
                            } else {
                                Add-LrListItem -Name $OutObject.ListGuid -Value $AddList
                            }
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit addition entries."
                            $ErrorObject.Value = $AddArray
                        }
                    }
                }
            } else {
                # Set quantity of added values
                $OutObject.Added = $AddList.Count
            }

            # Retrieve list final entry count:
            $OutObject.After = $(Get-LrList -Name $OutObject.ListGuid | Select-Object -ExpandProperty entryCount)
        }


        # Return output object
        if ($ErrorObject.Error -eq $true) {
            return $ErrorObject
        }
        if ($PassThru) {
            return $OutObject
        }
    }
    
    End { }
}