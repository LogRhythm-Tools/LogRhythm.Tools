using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Show-LrLocations {
    <#
    .SYNOPSIS
        Print a list of all locally stored Locations for LogRhythm.
    .DESCRIPTION
        Show-LrLocations returns a LogRhythm Location object, including it's details.

        The Location Name and LocationType parameters can be utilized in conjuection, with or without the exact parameter switch.

        This cmdlet references a local archive csv of LogRhythm locations.  For reference to latest locations
        utilize Get-LrLocations.
    .PARAMETER Name
        The name of the geographic location.

        Example: New York, Richmond, United Kingdom, or United Arab Emirates
    .PARAMETER Id
        Retrieve records that have a specific ID value.  Each Id is unique.
    .PARAMETER ParentLocationId
        Retrieve records that have a specific parent ID value.  
    .PARAMETER LocationType
        Retrieve records based on location type.

        Valid location types: Country, Region
    .PARAMETER Exact
        Exact is a switch parameter that enables explicit name value matching.
    .OUTPUTS
        PSCustomObject representing LogRhythm Locations its associated contents.
    .EXAMPLE
        PS C:\> Show-Lr-Locations
        ----
        Name                         Id ParentLocationId LocationType
        ----                         -- ---------------- ------------
        Dryfork                   63975              302 Region
        Monkeberg                 92125              596 Region
                                 126502               48 Region
        Alder Creek               37019              284 Region
    .EXAMPLE
        PS C:\> Show-LrLocations -Name "Spartanburg" -Exact
        ----
        Name           Id ParentLocationId LocationType
        ----           -- ---------------- ------------
        Spartanburg 29929              291 Region
    .EXAMPLE
        PS C:\> Show-LrLocations -Name "United" -LocationType "Country"
        ----
        Name                  Id ParentLocationId LocationType
        ----                  -- ---------------- ------------
        United Kingdom        77                0 Country
        United States        230                0 Country
        United Arab Emirates   2                0 Country
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [int32] $Id,


        [Parameter(Mandatory = $false, Position = 2)]
        [int32] $ParentLocationId,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('region','country', ignorecase=$true)]
        [string] $LocationType,

        
        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $Exact
    )

    Begin {
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
        }
        # Load locations from local filesystem
        $LRLocationsPath = Join-Path `
        -Path [Environment]::GetFolderPath("LocalApplicationData") `
        -ChildPath "LogRhythm.Tools" | Join-Path -ChildPath "LRLocations.csv"

        $LocationsFromArchive = Import-Csv -LiteralPath $LRLocationsPath

        # Establish output object
        $ResultList = [list[Object]]::new()

        # Filter results based on provided criteria, or return full object list
        if ($Id -Or $ParentLocationId -Or $name -Or $LocationType) {
            if ($Id -or $ParentLocationId) {
                $LocationsFromArchive | ForEach-Object {
                    if ($Id) {
                        if ($Id -eq $_.Id) {
                            Write-Verbose "[$Me]: Exact Id found."
                            $ResultList.add($_)
                        }
                    } else {
                        if ($ParentLocationId -eq $_.ParentLocationId) {
                            Write-Verbose "[$Me]: Exact Id found."
                            $ResultList.add($_)
                        }
                    }
                }
            }
            if ($Name -or $LocationType) {
                if ($Name) {
                    if ($Exact) {
                        $Pattern = "^$Name$"
                        $LocationsFromArchive | ForEach-Object {
                            if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                                Write-Verbose "[$Me]: Exact list name match found."
                                if ($LocationType) {
                                    Write-Verbose "[$Me]: Checking for matching Location Type: $LocationType"
                                    if ($LocationType -eq $_.LocationType) {
                                        Write-Verbose "[$Me]: Exact location type found."
                                        $ResultList.add($_)
                                    }
                                } else {
                                    $ResultList.add($_)
                                }
                            }
                        }
                    } else {
                        $Pattern = "$Name"
                        $LocationsFromArchive | ForEach-Object {
                            if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                                Write-Verbose "[$Me]: Exact list name match found."
                                if ($LocationType) {
                                    Write-Verbose "[$Me]: Checking for matching Location Type: $LocationType"
                                    if ($LocationType -eq $_.LocationType) {
                                        Write-Verbose "[$Me]: Exact location type found."
                                        $ResultList.add($_)
                                    }
                                } else {
                                    $ResultList.add($_)
                                }
                            }
                        }
                    }
                } else {
                    $LocationsFromArchive | ForEach-Object {
                        if ($LocationType -eq $_.LocationType) {
                            Write-Verbose "[$Me]: Exact location type found."
                            $ResultList.add($_)
                        }
                    }
                }
            }
        } else {
            return $LocationsFromArchive
        }

        return $ResultList
    }

    End { }
}