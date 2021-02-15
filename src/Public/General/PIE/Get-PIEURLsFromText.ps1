<#
    .SYNOPSIS
        Retrieve array of URLs from raw text.
    .OUTPUTS
        Array of strings for matched URLs.
    .EXAMPLE
        Get-PIEURLsFromText -Text  $tres[2].EvaluationResults.Body.Original
        ---
        https://protect-us.mimecast.com/s/0wSdCVON0gczLDq1tGaO_q/
        https://www.optiv.com/security-solutions/security-services/threatdna-and-threatbeat
        file:///Users/christopher.lucas/Desktop/Advisory_teamplate/SecOps_ThreatBEATemailTemplate_HTML-KK.html
        https://www.twitter.com/optiv
        http://www.linkedin.com/company/optiv-inc
    .NOTES
        PIE     
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-PIEURLsFromText {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [string] $Text
    )
    Begin {
        $URLPattern = '(?:(?:https?|ftp|file)://|www\.|ftp\.)(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[A-Z0-9+&@#/%=~_|$])'
        $URLList = [list[ Dictionary[string,string]]]::new()
    }

    Process {
        $URLs = $Text | Select-String -AllMatches $URLPattern | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        return $URLs
    }
}