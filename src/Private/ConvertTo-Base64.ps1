function ConvertTo-Base64 {
    <#
        .SYNOPSIS
            Encodes the plain text or Unicode string into a base64 encoded string.
        .PARAMETER String
            The plain text or Unicode string.
        .INPUT
            System.String. You can pipe a string into ConvertTo-Base64.
         .OUTPUT
            System.String. ConvertTo-Base64 returns a base64 encoded string.
        .EXAMPLE
            PS C:\> ConvertTo-Base64 -String "Michael"
            TQBpAGMAaABhAGUAbAA=
        .EXAMPLE
            PS C:\> ConvertTo-Base64 -String "Get-Process -Name Notes -ErrorAction SilentlyContinue | Stop-Process" | clip.exe
            PS C:\> powershell.exe -encodedcommand RwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBOAGEAbQBlACAATgBvAHQAZQBzACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlACAAfAAgAFMAdABvAHAALQBQAHIAbwBjAGUAcwBzAA==
        .NOTES
            Author:
            Michael West
    #>
    [OutputType('System.String')]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$String
    )

    [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($String))
}