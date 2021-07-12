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

            Updated By:
            Eric Hart
    #>
    [OutputType('System.String')]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$String,

        [Parameter(ValueFromPipeline=$false)]
        [ValidateSet(
            'BigEndianUnicode',
            'unicode',
            'utf7',
            'utf8', 
            'utf32', 
            ignorecase=$true
        )]
        [string]$Encoding
    )
    Begin {        
    }

    Process {
        switch ($Encoding) {
            unicode {
                [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($String))
            }
            utf7 {
                [System.Convert]::ToBase64String([System.Text.Encoding]::UTF7.GetBytes($String))
            }
            utf8 {
                [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($String))
            }
            utf32 {
                [System.Convert]::ToBase64String([System.Text.Encoding]::UT32.GetBytes($String))
            }
            bigendianunicode {
                [System.Convert]::ToBase64String([System.Text.Encoding]::BigEndianUnicode.GetBytes($String))
            }
            Default {
                [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($String))
            }
        }
    }    
}