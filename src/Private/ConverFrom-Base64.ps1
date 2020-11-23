function ConvertFrom-Base64 {
    <#
        .SYNOPSIS
            Decodes the base64 string into a Unicode string.
        .PARAMETER String
            The base64 encoded string.
        .INPUT
            System.String. You can pipe a string into ConvertFrom-Base64.
        .OUTPUT
            System.String. ConvertFrom-Base64 returns a Unicode encoded string.
        .EXAMPLE
            PS C:\> ConvertFrom-Base64 -String "TQBpAGMAaABhAGUAbAA="
            Michael
        .NOTES
            Author:
            Michael West
    #>
    [OutputType('System.String')]
    param(
        [string]$String
    )

    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
}