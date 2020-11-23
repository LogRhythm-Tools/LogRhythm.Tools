Add-Type -Path "N:\Projects\git\MailKit\MailKit\MailKit\bin\Debug\net45\MailKit.dll"
Add-Type -Path "N:\Projects\git\MailKit\MailKit\MailKit\bin\Debug\net45\MimeKit.dll"
<#
    .SYNOPSIS
        Connect to IMAP mail server.
    .DESCRIPTION

    .PARAMETER EmailCredential
        PS Credential that contains the Username and Password required for Authentication.
    .OUTPUTS
        Object representing IMAP inbox.
    .EXAMPLE
        PS C:\> PIE-MKConnectIMAP -credential $MyCred -MailServer "outlook.office365.com" -MailServerPort 993 -Mode "read"
        -----
        votes       : 11815
        description : best ip cam search I have found yet.
        tags        : {webcam, surveillance, cams}
        timestamp   : 3/15/2010 1:32:32 PM
        title       : Webcam
        query       : Server: SQ-WEBCAM

        votes       : 4851
        description : admin admin
        tags        : {cam, webcam}
        timestamp   : 2/6/2012 9:04:16 AM
        title       : Cams
        query       : linux upnp avtech
    .NOTES
        Shodan-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-URLsFromText {
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
        <#
        return $URLs
        ForEach ($URL in $URLs ) {
            $URLValue = [Dictionary[string,string]]::new()
            Switch ($($URL.protocol)) {
                "mailto:" {
                    $URLValue.Add("Type", "Email")
                    $URLValue.Add("Email", $($URL.pathname))
                    $URLValue.Add("IsValid", $(Test-ValidEmailAddress -Address $URL.pathname))
                    break
                }
                "file:" {
                    $URLValue.Add("Type", "File")
                    $URLValue.Add("FileName", $($URL.nameProp))
                    $URLValue.Add("Path", $($URL.pathname))
                    break
                }
                default {
                    $URLValue.Add("Type", "URL")
                    if ($Url.Hostname) {
                        $IPStatus = Test-ValidIPv4Address -IP $($URL.hostname)
                        if ($IPStatus.IsValid -eq $True) { 
                            $URLValue.Add("IP", $($IPStatus.Value))
                            # IP Address was resolved via Test-ValidIPv4Address.  Origin URL is IP Address
                            $URLValue.Add("IsIP", $($IPStatus.IsValid))
                            $URLValue.Add("IsPrivate", $IPStatus.IsPrivate)
                            Try {
                                $ReverseDNSLookup = [System.Net.Dns]::gethostentry($($IPStatus.Value)).hostname
                                $URLValue.Add("ReverseDNS", $ReverseDNSLookup)
                            } Catch {
                                $URLValue.Add("ReverseDNS", "No reverse record found.")
                            }
                        } else {
                            # IsIP - If URL is not direct link to IP address, IsIP = False
                            $URLValue.Add("IsIP", $False)
                            Try {
                                $DNSLookup = Resolve-DnsName -Name $($Url.Hostname) -Type A
                            } Catch {
                                Write-Host "DNS Nope"
                            }
                            if ($DNSLookup) {
                                $DNSStatus = Test-ValidIPv4Address -IP $($DNSLookup | Select-Object -Property IPAddress | Select-Object -ExpandProperty IPAddress | Select-Object -First 1).ToString()
                            }

                            if ($DNSStatus.IsValid -eq $True) {
                                $URLValue.Add("IP", $DNSStatus.Value)
                                $URLValue.Add("IsPrivate", $DNSStatus.IsPrivate)
                            }
                        }
                    }
                    $URLValue.Add("href", $($URL.href))
                    $URLValue.Add("Defang", $($URL.href.replace('http','hxxp')))
                    $URLValue.Add("host", $($URL.host))
                    $URLValue.Add("hostname", $($URL.hostname))
                    $URLValue.Add("pathname", $($URL.pathname))
                    $URLValue.add("port", $($URL.port))
                    $URLValue.add("protocol", $($URL.protocol))
                    $URLValue.add("nameProp", $($URL.nameProp))
                    break
                }
            }
            $URLList.Add($URLValue)
        }
        return $URLList
        #>
    }
}