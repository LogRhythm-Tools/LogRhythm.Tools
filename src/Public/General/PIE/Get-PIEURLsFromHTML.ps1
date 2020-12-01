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
        $HTMLObject = New-Object -Com "HTMLFile"
        $URLList = [list[object]]::new()
    }

    Process {
        write-verbose "HTML Source Length: $($HtmlSource.Length)"
        $HTMLObject.IHTMLDocument2_write($HTMLSource)
        $IMGArray = $HTMLObject.all.tags("img")
        $URLArray = $HTMLObject.all.tags("a")
        ForEach ($URL in $URLArray ) {
            $URLValue = [PSCustomObject]@{
                Type = $null
            }

            
            Switch ($($URL.protocol)) {
                "mailto:" {
                    $URLValue.Type = "Email"
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Email' -Value $($URL.pathname)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'IsValid' -Value $(Test-ValidEmailAddress -Address $URL.pathname)                    
                    break
                }
                "file:" {
                    $URLValue.Type = "File"
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Name' -Value $($URL.nameProp)
                    $FileExtension = [System.IO.Path]::GetExtension($($URL.nameProp))
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Extension' -Value $FileExtension
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Path' -Value $($URL.pathname)
                    break
                }
                default {
                    $URLValue.Type = "URL"
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'URL' -Value $($URL.href)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Host' -Value $($URL.host)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Hostname' -Value $($URL.hostname)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'PathName' -Value $($URL.pathname)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Port' -Value $($URL.port)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $($($URL.protocol).replace(':',''))
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Location' -Value $($URL.nameProp)                    
                    break
                }
            }

            if ($URLList -notcontains $URLValue) {
                if ($URLValue.Type -like "URL" -And $URLValue.Url) {
                    $URLList.Add($URLValue)
                } 
                if ($URLValue.Type -like "File" -Or $URLValue.Type -like "Email" ) {
                    $URLList.Add($URLValue)
                }
                
            }
        }

        ForEach ($ImgUrl in $IMGArray) {
            $URLValue = [PSCustomObject]@{
                Type = $null
            }

            if ($($ImgUrl.href) -like "http*") {
                $URLValue.Type = "Image"
                $URLValue | Add-Member -MemberType NoteProperty -Name 'URL' -Value $($ImgUrl.href)
                

                [System.Uri]$URLDetails = $($ImgUrl.href)
                $URLValue | Add-Member -MemberType NoteProperty -Name 'AbsolutePath' -Value $($URLDetails.AbsolutePath)
                $URLValue | Add-Member -MemberType NoteProperty -Name 'Host' -Value $($URLDetails.host+':'+$URLDetails.port)
                $URLValue | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $($URLDetails.host)
                $URLValue | Add-Member -MemberType NoteProperty -Name 'Port' -Value $($URLDetails.Port)
                $URLValue | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $($URLDetails.Scheme)
                $URLValue | Add-Member -MemberType NoteProperty -Name 'Name' -Value $($UrlDetails.segments[-1])
                $FileExtension = [System.IO.Path]::GetExtension($($UrlDetails.segments[-1]))
                $URLValue | Add-Member -MemberType NoteProperty -Name 'Extension' -Value $FileExtension
                
                if ($UrlDetails.HostNameType -Like "IPv6") {
                    If (($URLValue.PSobject.Properties.name -contains "IP")) {
                        $URLValue.IP = $URLDetails.Host
                    } else {
                        $URLValue | Add-Member -MemberType NoteProperty -Name 'IP' -Value $($URLDetails.Host)
                    }
                }
                if ($URLDetails.HostNameType -like "IPv4") {
                    $IPStatus = Test-ValidIPv4Address -IP $URLDetails.Host
                    # IP Address was resolved via Test-ValidIPv4Address.  Origin URL is IP Address
                    if ($IPStatus.IsValid -eq $True) { 
                        If (($URLValue.PSobject.Properties.name -contains "IP")) {
                            $URLValue.IP = $IPStatus.Value
                        } else {
                            $URLValue | Add-Member -MemberType NoteProperty -Name 'IP' -Value $($IPStatus.Value)
                        }
                        
                        $URLValue | Add-Member -MemberType NoteProperty -Name 'IsIP' -Value $($IPStatus.IsValid)
                        $URLValue | Add-Member -MemberType NoteProperty -Name 'IsPrivate' -Value $($IPStatus.IsPrivate)
                    }
                }


                if ($URLDetails.HostNameType -like "Dns") {
                    # IsIP - If URL is not direct link to IP address, IsIP = False
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'IsIP' -Value $False
                }
                if ($URLList -notcontains $URLValue) {
                    $URLList.Add($URLValue)
                }
            }
        }
        
        return $URLList
    }
}