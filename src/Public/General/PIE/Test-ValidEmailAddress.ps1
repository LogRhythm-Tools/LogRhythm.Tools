function Test-ValidEmailAddress {
    <#
        .SYNOPSIS
            Determines if the email address is in a valid format.
        .PARAMETER Address
            The email string to validate.
         .INPUT
            System.String. You can pipe a string into Test-Email.
        .OUTPUT
            System.Boolean. Test-Email returns True or False.
        .EXAMPLE
            PS C:\> Test-Email -Address "michael.west@concentra.com"
            True
        .NOTES
            Author:
            Michael West
            
        .LINK
            http://msdn.microsoft.com/en-us/library/01escwtf(v=vs.90).aspx                 
    #>
    [OutputType('System.Boolean')]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$Address
    )
    
    $invalid = $false

    if(-not $Address) {
        return $false
    }

    $idnMapper = {
        param(
            [System.Text.RegularExpressions.Match]$Match
        )

        $idn = New-Object System.Globalization.IdnMapping

        $domain = $Match.Groups[2].Value
        try {
            $domain = $idn.GetAscii($domain)
        } catch [System.ArgumentNullException] {
            $invalid = $true
        }

        $Match.Groups[1].Value + $domain
    }

    $Address = [System.Text.RegularExpressions.Regex]::Replace($Address, "(@)(.+)$", $idnMapper)

    if($invalid) {
        return $invalid
    }

    $pattern = @"
^(?("")(""[^""]+?""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-\w]*[0-9a-z]*\.)+[a-z0-9]{2,17}))$
"@
   
    [System.Text.RegularExpressions.Regex]::IsMatch($Address, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
}