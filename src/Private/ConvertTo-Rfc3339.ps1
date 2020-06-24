using namespace System

Function ConvertTo-Rfc3339 {
    <#
    .SYNOPSIS
        Convert a System.DateTime to an RFC 3339 formatted string.
    .DESCRIPTION
        Convert a System.DateTime to an RFC 3339 formatted string, suitable for
        sending to LogRhythm API.
    .PARAMETER Date
        The date to convert.
    .INPUTS
        System.DateTime -> Date parameter
    .OUTPUTS
        System.String
    .EXAMPLE
        PS C:\> ConvertTo-Rfc3339 "2019-10-05 13:00:00"
        ---
        2019-10-05T13:00:00Z
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [string] $Date
    )


    Begin { }


    Process {
        return [Xml.XmlConvert]::ToString(($Date),[Xml.XmlDateTimeSerializationMode]::Utc)
    }


    End { }

}














# Must be an RFC 3339 formatted string
