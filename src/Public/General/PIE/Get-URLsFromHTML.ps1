using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Retrieve array of URLs from HTML formatted text.
    .DESCRIPTION

    .OUTPUTS
        PSCustomObject Array providing the identified URLs and Domains.
    .EXAMPLE

    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/PIE
#>
function Get-URLsFromHTML {
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
        $HTMLObject.IHTMLDocument2_write($HTMLSource)
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
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'FileName' -Value $($URL.nameProp)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Path' -Value $($URL.pathname)    
                    break
                }
                default {
                    $URLValue.Type = "URL"
                    if ($Url.Hostname) {
                        $IPStatus = Test-ValidIPv4Address -IP $($URL.hostname)
                        # IP Address was resolved via Test-ValidIPv4Address.  Origin URL is IP Address
                        if ($IPStatus.IsValid -eq $True) { 
                            If (($URLValue.PSobject.Properties.name -contains "IP")) {
                                $URLValue.IP = $IPStatus.Value
                            } else {
                                $URLValue | Add-Member -MemberType NoteProperty -Name 'IP' -Value $($IPStatus.Value)
                            }
                            
                            $URLValue | Add-Member -MemberType NoteProperty -Name 'IsIP' -Value $($IPStatus.IsValid)
                            $URLValue | Add-Member -MemberType NoteProperty -Name 'IsPrivate' -Value $($IPStatus.IsPrivate)
                        } else {
                            # IsIP - If URL is not direct link to IP address, IsIP = False
                            $URLValue | Add-Member -MemberType NoteProperty -Name 'IsIP' -Value $False
                            Try {
                                $DNSLookup = Resolve-DnsName -Name $($Url.Hostname) -Type A
                            } Catch {
                                
                            }
                            if ($DNSLookup) {
                                $DNSStatus = Test-ValidIPv4Address -IP $($DNSLookup | Select-Object -Property IPAddress | Select-Object -ExpandProperty IPAddress | Select-Object -First 1).ToString()
                            }

                            if ($DNSStatus.IsValid -eq $True) {
                                If (($URLValue.PSobject.Properties.name -contains "IP")) {
                                    $URLValue.IP = $DNSStatus.Value
                                } else {
                                    $URLValue | Add-Member -MemberType NoteProperty -Name 'IP' -Value $($DNSStatus.Value)
                                }
                                
                                $URLValue | Add-Member -MemberType NoteProperty -Name 'IsPrivate' -Value $($DNSStatus.IsPrivate)
                            }
                        }
                    }
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'URL' -Value $($URL.href)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Defang' -Value $($URL.href.replace('http','hxxp'))
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Host' -Value $($URL.host)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Hostname' -Value $($URL.hostname)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'PathName' -Value $($URL.pathname)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Port' -Value $($URL.port)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $($URL.protocol)
                    $URLValue | Add-Member -MemberType NoteProperty -Name 'Location' -Value $($URL.nameProp)
                    break
                }
            }
            $URLList.Add($URLValue)
        }
        return $URLList
    }
}