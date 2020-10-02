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
        [switch] $PassThru,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )
                                                                   
    Begin {
        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
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
            ListType              =   $ListType
        }

        # Process Name
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
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
                if (!$ListType) {
                    $ListType = $TargetList.listType
                    $OutObject.ListType = $TargetList.ListType
                }
            }
        } else {
            $TargetList = Get-LrList -Name $Name.ToString() -Exact
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
                if (!$ListType) {
                    $ListType = $TargetList.listType
                    $OutObject.ListType = $TargetList.ListType
                }
            }
        }


        if ($($OutObject.ListGuid) -or $($OutObject.ListName)) {
            Write-Verbose "$(Get-TimeStamp) - Retrieving List Values for: $($OutObject.ListName)"
            $ListValues = Get-LrListItems -Name $OutObject.ListName -ValuesOnly
            if ($Value.Count -ge 1 -And $ListValues.Count -ge 1) {
                Write-Verbose "$(Get-TimeStamp) - Number of ListValues: $($ListValues.Count) - Number of Values: $($Value.Count)"
                $ComparisonResults = Compare-StringArrays $Value $ListValues -Unsorted
                Write-Verbose "$(Get-TimeStamp) - Comparison Complete"
                $RemoveList = $ComparisonResults | Where-Object SideIndicator -eq "=>" | Select-Object -ExpandProperty InputObject
                Write-Verbose "$(Get-TimeStamp) - RemoveList Count: $($RemoveList.Count)"
                $AddList = $ComparisonResults | Where-Object SideIndicator -eq "<=" | Select-Object -ExpandProperty InputObject
                Write-Verbose "$(Get-TimeStamp) - AddList Count: $($AddList.Count)"
            } elseif ($Value.Count -eq 0 -And $ListValues.Count -ge 1) {
                $RemoveList = $ListValues
            } else {
                $AddList = $Value
            }


            # Bulk remove of the RemoveList items
            if ($RemoveList) {
                Write-Verbose "$(Get-TimeStamp) - Remove Count: $($RemoveList.Count)"
                # Set quantity of removed values
                $OutObject.Removed = $RemoveList.Count
                # For large number of removals, break the additions into 10,000 items per API call
                if ($RemoveList.Count -ge 1000) {
                    Write-Verbose "$(Get-TimeStamp) - Enter Removal Segmentation"
                    $SegmentCount = ([Math]::Round(($($RemoveList.Count) / 1000), 0)) + 1
                    $SegmentedRemoveList = Create-LrPsArraySegments -InputArray $RemoveList -Segments $SegmentCount
                    foreach ($RemoveArray in $SegmentedRemoveList) {
                        Write-Verbose "$(Get-TimeStamp) - Submitting $($RemoveArray.count)"
                        Try {
                            Remove-LrListItem -name $OutObject.ListGuid -Value $RemoveArray -ItemType $ListType | Out-Null
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit removal entries."
                            $ErrorObject.Value = $RemoveArray
                        }
                        start-sleep .2
                    }
                } else {
                    if ($ItemType) {
                        Try {
                            Remove-LrListItem -name $OutObject.ListGuid -Value $RemoveList -ItemType $ListType | Out-Null
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit removal entries."
                            $ErrorObject.Value = $RemoveArray
                        }
                    } else {
                        Try {
                            Remove-LrListItem -name $OutObject.ListGuid -Value $RemoveList | Out-Null
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
                Write-Verbose "$(Get-TimeStamp) - Addition Count: $($AddList.Count)"
                # Set quantity of removed values
                $OutObject.Added = $AddList.Count
                # For large number of additions, break the additions into 1,000 items per API call
                if ($AddList.Count -ge 1000) {
                    Write-Verbose "$(Get-TimeStamp) - Enter Addition Segmentation"
                    $SegmentCount = ([Math]::Round(($($AddList.Count) / 1000), 0)) +1
                    $SegmentedAddList = Create-LrPsArraySegments -InputArray $AddList -Segments $SegmentCount
                    foreach ($AddArray in $SegmentedAddList) {
                        Write-Verbose "$(Get-TimeStamp) - Submitting $($AddArray.count)"
                        Try {
                            Add-LrListItem -name $OutObject.ListGuid -Value $AddArray -ItemType $ListType | Out-Null
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit addition entries."
                            $ErrorObject.Value = $AddArray
                        }
                        start-sleep .2
                    }
                } else {
                    if ($ItemType) {
                        Try {
                            Add-LrListItem -Name $OutObject.ListGuid -Value $AddList -ItemType $ListType | Out-Null
                        } Catch {
                            $ErrorObject.Error = $true
                            $ErrorObject.Note = "Failed to submit addition entries."
                            $ErrorObject.Value = $AddArray
                        }
                    } else {
                        Try {
                            Add-LrListItem -Name $OutObject.ListGuid -Value $AddList | Out-Null
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