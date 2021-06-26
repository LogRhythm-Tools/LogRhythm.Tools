using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Retrieve array of URLs from HTML formatted text.
    .OUTPUTS
        PSCustomObject Array providing the identified URLs and additional data.
    .EXAMPLE
        Get-PIEURLsFromHTML -HTMLSource $HTMLSourceInput
        ---
        Type     : URL
        URL      : https://protect-us.mimecast.com/s/0wSdCVON0gczLDq1tGaO_q/
        Host     : protect-us.mimecast.com:443
        Hostname : protect-us.mimecast.com
        PathName : s/0wSdCVON0gczLDq1tGaO_q/
        Port     : 443
        Protocol : https
        Location : 0wSdCVON0gczLDq1tGaO_q

        Type     : URL
        URL      : https://www.optiv.com/security-solutions/security-services/threatdna-and-threatbeat
        Host     : www.optiv.com:443
        Hostname : www.optiv.com
        PathName : security-solutions/security-services/threatdna-and-threatbeat
        Port     : 443
        Protocol : https
        Location : threatdna-and-threatbeat

        Type    : Email
        Email   : ThreatDNA@Optiv.com
        IsValid : True

        Type      : File
        Name      : SecOps_ThreatBEATemailTemplate_HTML-KK.html
        Extension : .html
        Path      : Users/christopher.lucas/Desktop/Advisory_teamplate/SecOps_ThreatBEATemailTemplate_HTML-KK.html

        Type     : URL
        URL      : https://www.twitter.com/optiv
        Host     : www.twitter.com:443
        Hostname : www.twitter.com
        PathName : optiv
        Port     : 443
        Protocol : https
        Location : optiv

        Type     : URL
        URL      : http://www.linkedin.com/company/optiv-inc
        Host     : www.linkedin.com:80
        Hostname : www.linkedin.com
        PathName : company/optiv-inc
        Port     : 80
        Protocol : http
        Location : optiv-inc
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-PIEURLsFromHTML {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [string] $HTMLSource
    )
    Begin {
        $URLList = [list[object]]::new()
        $RegExHtmlTags = '<(.*?)>'
    }

    Process {
        $matchedItems = [regex]::matches($HTMLSource, $RegExHtmlTags, [system.Text.RegularExpressions.RegexOptions]::Singleline)
        foreach ($Match in $matchedItems) {
            $URLValue = [PSCustomObject]@{
                Type = $null
                Base = $false
            }
            if (!$Match.Value.StartsWith("</")) {
                try {
                    if ($Match.Value.StartsWith("<base ", [System.StringComparison]::InvariantCultureIgnoreCase)) {  
                        $Attributes = $Match.Value.Split(" ")
                        foreach ($Attribute in $Attributes) {
                            if ($Attribute.Length -gt 10) {
                                $URLValue.Base = $true
                                if ($Attribute.StartsWith('href=', [System.StringComparison]::InvariantCultureIgnoreCase)) {   
                                    $URLValue | Add-Member -MemberType NoteProperty -Name 'URL' -Value ([URI]($Attribute.Substring(6, $Attribute.Length - 7).Replace("`"", "").Replace("'", "").Replace("`r`n", ""))) -Force
                                    $URLValue.Type = 'URL'
                                }   
                            }                                
                        }                                  
                    }

                    if ($Match.Value.StartsWith("<a ", [System.StringComparison]::InvariantCultureIgnoreCase)) {
                        $Attributes = $Match.Value.Split(" ")
                        foreach ($Attribute in $Attributes) {
                            if ($Attribute.StartsWith('href=', [System.StringComparison]::InvariantCultureIgnoreCase)) {    
                                if ($Attribute.Length -gt 10) { 
                                    $hrefVal = ([URI]($Attribute.Substring(6, $Attribute.Length - 7).Replace("`"", "").Replace("'", "").Replace("`r`n", "`n")))
                                    if ($URLList.Base -contains $True) {
                                        if ([String]::IsNullOrEmpty($hrefVal.DnsSafeHost)) {
                                            $newHost = ($URLList | Where-Object -Property 'Base' -eq $True | Select-Object -First 1 -ExpandProperty 'URL' | Select-Object -ExpandProperty OriginalString) + $hrefVal.OriginalString
                                            $hrefVal = ([URI]($newHost))
                                        }
                                    }
                                    $URLValue.Type = "URL"
                                    $URLValue | Add-Member -MemberType NoteProperty -Name 'URL' -Value $hrefVal -Force
                                }                         
                        
                            }                                 
                        }                               
                    }

                    if ($Match.Value.StartsWith("<img ", [System.StringComparison]::InvariantCultureIgnoreCase)) {
                        $Attributes = $Match.Value.Split(" ")
                        foreach ($Attribute in $Attributes) {
                            if ($Attribute.Length -gt 7) {
                                if ($Attribute.StartsWith('src=', [System.StringComparison]::InvariantCultureIgnoreCase)) {                                        
                                    $URLValue.Type = "IMG"
                                    $URLValue | Add-Member -MemberType NoteProperty -Name 'URL' -Value ([URI]($Attribute.Substring(5, $Attribute.Length - 6).Replace("`"", "").Replace("'", "").Replace("`r`n", "`n"))) -Force
                                }
                            }                                 
                        }
                    }

                } catch {
                    Write-host ("Parse exception " + $_.Exception.Message + " on Message " + $Item.Subject)
                    $Error.Clear()
                }

                if ($null -ne $URLValue.URL) {
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Port' -Value $($UrlValue.URL.Port) -Force
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $($UrlValue.URL.Scheme) -Force
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Hostname' -Value $($UrlValue.URL.host) -Force
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Host' -Value ($($UrlValue.URL.host) + ':' + $($UrlValue.URL.Port.ToString())) -Force
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'PathName' -Value $($UrlValue.URL.PathAndQuery) -Force
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Location' -Value $($UrlValue.URL.Fragment) -Force

                    if ($URLList -notcontains $URLValue) {
                        $URLList.add($URLValue)
                    }
                }                   
            }
        }
        return $URLList
    }
}