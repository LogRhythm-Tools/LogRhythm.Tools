Function Get-RestErrorMessage {
    <#
    .SYNOPSIS
        Attempt to extract a real error message information from a System.Net.WebException.
    .PARAMETER Err
        System.Net.WebException instance
    .INPUTS
        Exception object
    .OUTPUTS
        PSObject containing the body of the Exception Response.
    .EXAMPLE
        PS C:\> Get-RestErrorMessage $_

        statusCode  message
        ----------  -------
               400  List has more than '100' items. Please change 'MaxItemsThreshold' header to appropriate value.
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    #region: Parameters
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [Object] $Err
    )

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Err.Exception.Response) {  
            $Reader = New-Object System.IO.StreamReader($Err.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ($ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json
            }
            return $ResponseBody
        }
    }
    else {
        return $Error.ErrorDetails.Message
    }
}