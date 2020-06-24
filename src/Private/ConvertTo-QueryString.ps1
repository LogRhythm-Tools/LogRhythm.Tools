using namespace System
Function ConvertTo-QueryString {
    <#
    .SYNOPSIS
        Turn a hashtable/dictionary into a uri-encoded query string.
    .DESCRIPTION
        The ConvertTo-QueryString cmdlet takes a hash table, Dictionary<string, string>
        or an object, and outputs a uri-encoded query string, which can then be appended 
        to a base url.

        Input is generally expected to be a hashtable or PSObject - if the order
        of the parameters is important, either use an [ordered] hashtable or a PSObject.
    .PARAMETER Params
        The hashtable or object to use.
    .PARAMETER OmitNull
        Null values will be left out of the string entirely.
    .PARAMETER Encode
        Encode (EscapeUriString) the full string once built.
    .INPUTS
        [hashtable] -> Params
        [PSObject]  -> Params
        [Object]    -> Params
    .OUTPUTS
        A Uri-encoded query string ready to be appended to a Uri, in the format of:
        
        ?Field=Value&Field=Value&Field=Value
    .EXAMPLE
        PS C:\> [PSCustomObject]@{ field1="value1"; field2="value 2"; field3=$false } | ConvertTo-QueryString
        ---
        ?field1=value1&field2=value%202&field3=False
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0, 
            ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [Object] $Params,


        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $OmitNull,


        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $Encode
    )

    $QueryString = "?"

    # Enumerate our input object into series a of "Field=Value&"

    # Hashtables and Dictionaries get enumerated slightly differently than other objects
    # This may be too specific a method given the number of hashtables, objects, dictionaries, lists, etc
    # that exist in .NET / Powershell
    if (($Params -is [hashtable]) -or ($Params -is [System.Collections.Generic.Dictionary[string,string]])) {
        foreach ($param in $Params.GetEnumerator()) {
            if ($OmitNull -and ([string]::IsNullOrEmpty($param.Value))) {
                continue
            }
            $QueryString += $param.Key
            $QueryString += "="
            $QueryString += $param.Value
            $QueryString += "&"
        }
    } else {
        # Mostly we expect PSCustomObject here, otherwise ALL the properties of the object
        # will be encoded!
        foreach ($param in $Params.PSObject.Properties) {
            if ($OmitNull -and ([string]::IsNullOrEmpty($param.Value))) {
                continue
            }
            $QueryString += $param.Name
            $QueryString += "="
            $QueryString += $param.Value
            $QueryString += "&"
        }
    }

    # Remove trailing "&"
    $QueryString = $QueryString -replace "&$"


    # If we don't have a param string (only "?"), return empty string.
    if ($QueryString -match "^\?$") {
        return ""
    }


    # Url encode & return ParamString
    if ($Encode) {
        $QueryString = [uri]::EscapeUriString($QueryString)    
    }
    
    return $QueryString
}