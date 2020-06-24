using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrLocations {
    <#
    .SYNOPSIS
        Retrieve a list of all available Locations from LogRhythm.
    .DESCRIPTION
        Show-LrLocations returns a LogRhythm Location object, including it's details.

        The Location Name and LocationType parameters can be utilized in conjuection, with or without the exact parameter switch.

        This cmdlet references a local archive csv of LogRhythm locations.  For reference to latest locations
        utilize Get-LrLocations.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
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
        PSCustomObject representing LogRhythm Entity its contents.
    .EXAMPLE
        PS C:\> Get-Lr-Locations
        ----
        Name                         Id ParentLocationId LocationType
        ----                         -- ---------------- ------------
        Dryfork                   63975              302 Region
        Monkeberg                 92125              596 Region
                                126502               48 Region
        Alder Creek               37019              284 Region
    .EXAMPLE
        PS C:\> Get-LrLocations -Name "Spartanburg" -Exact
        ----
        Name           Id ParentLocationId LocationType
        ----           -- ---------------- ------------
        Spartanburg 29929              291 Region
    .EXAMPLE
        PS C:\> Get-LrLocations -Name "United" -LocationType "Country"
        ----
        Name                  Id ParentLocationId LocationType
        ----                  -- ---------------- ------------
        United Kingdom        77                0 Country
        United States        230                0 Country
        United Arab Emirates   2                0 Country
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/SmartResponse-Framework/SmartResponse.Framework
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $false, Position = 1)]
        [string]$Name,

        [Parameter(Mandatory = $false, Position = 2)]
        [int32]$Id,

        [Parameter(Mandatory = $false, Position = 3)]
        [int32]$ParentLocationId,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('region','country', ignorecase=$true)]
        [string]$LocationType,

        [Parameter(Mandatory = $false, Position = 5)]
        [switch]$Exact
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Header
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LogRhythm.Version

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Define Search URL
        $RequestUrl = $BaseUrl + "/locations/"
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
        }

        if ($LrVersion -lt 7.5) {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "LogRhythm.Version"
            $ErrorObject.Code = 410
            $ErrorObject.Note = "Get-LrLocations requires LogRhythm version 7.5.0 or greater.  Use Show-LrLocations as an alternative cmdlet."
            return $ErrorObject
        }

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        }

        $ResultList = [list[Object]]::new()

        if ($Id -Or $ParentLocationId -Or $name -Or $LocationType) {
            if ($Id -or $ParentLocationId) {
                $Response | ForEach-Object {
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
                        $Response  | ForEach-Object {
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
                        $Response | ForEach-Object {
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
                    $Response | ForEach-Object {
                        if ($LocationType -eq $_.LocationType) {
                            Write-Verbose "[$Me]: Exact location type found."
                            $ResultList.add($_)
                        }
                    }
                }
            }
        } else {
            return $Response
        }

        return $ResultList
    }

    End { }
}