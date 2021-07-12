function ConvertFrom-Base64 {
    <#
        .SYNOPSIS
            Decodes the base64 string into a Unicode string.
        .PARAMETER String
            The base64 encoded string.
        .INPUT
            System.String. You can pipe a string into ConvertFrom-Base64.
        .OUTPUT
            System.String. ConvertFrom-Base64 returns a encoded string.
        .EXAMPLE
            PS C:\> ConvertFrom-Base64 -String "TQBpAGMAaABhAGUAbAA="
            Michael
        .NOTES
            Author:
            Michael West

            Updated By:
            Eric Hart
    #>
    [OutputType('System.String')]
    param(
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
                [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
            }
            utf7 {
                [System.Text.Encoding]::UTF7.GetString([System.Convert]::FromBase64String($String))
            }
            utf8 {
                [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($String))
            }
            utf32 {
                [System.Text.Encoding]::UTF32.GetString([System.Convert]::FromBase64String($String))
            }
            bigendianunicode {
                [System.Text.Encoding]::BigEndianUnicode.GetString([System.Convert]::FromBase64String($String))
            }
            Default {
                [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
            }
        }
    }
    
}