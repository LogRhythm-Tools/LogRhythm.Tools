using namespace System
using namespace System.Collections.Generic

Function Get-DistanceApi {
    <#
    .SYNOPSIS
        Retrieve Distance Calculation from www.distance24.org.
    .DESCRIPTION
        Provides Distance metrics based on personal travel.  Distance is not provided as a direct 
        line from point to point and should only be used as a reference. 

        Returned distance metrics are in Kilometers.
    .PARAMETER Location1
        City, state, or Zip
    .PARAMETER Location2
        City, state, or Zip
    .INPUTS
        System.String -> Domain
    .OUTPUTS
        PSCustomObject representing the report results.
    .EXAMPLE
        Get-DistanceApi -Location1 "Monroe" -Location2 "New York City"
        ---
        distances distance stops
        --------- -------- -----
        {1854}        1854 {@{travelGuides_timestamp=2013-02-17T19:06:12+00:00; locatedBy_version=7; locatedBy_timestamp=2012-10-29T12:09:56+00:00; city=Monroe; travelGuides=System.Object[]; nearByCiti...

    .NOTES
        Distance24-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string] $Location1,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [string] $Location2
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = "https://www.distance24.org/route.json?stops="
    }

    Process {
        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "$Location1|$Location2"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod $RequestUrl -Method $Method 
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }

        Return $Response
    }
 

    End { }
}