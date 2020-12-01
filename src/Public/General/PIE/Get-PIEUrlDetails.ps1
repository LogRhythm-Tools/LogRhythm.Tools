using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Retrieve details associated to a given URL.  This function leverages the following PIE functions:
            Invoke-PIEUrlDecode
            Invoke-PIEUrlDNSLookup
            Invoke-PIEUrlExpand
            Optionally - Provided API keys are configured and switch paramater EnablePlugins is provided
            Get-VTUrlReport
            Get-VTDomainReport
            New-VTUrlScanRequest
            New-UrlScanRequest
            Get-UrlScanReport
            Get-ShodanHostIp
    .OUTPUTS
        PSCustomObject Array providing the identified URLs and Domains.
    .EXAMPLE
        Get-PIEUrlDetails -Url http://www.linkedin.com/
        ---
        Type       : Dns
        Url        : http://www.linkedin.com/
        Host       : www.linkedin.com
        IsIP       : False
        IsPrivate  : False
        DNS        : @{Status=True; IPv4=System.Collections.Generic.List`1[System.Net.IPAddress]; IPv6=System.Collections.Generic.List`1[System.Net.IPAddress]; URL=http://www.linkedin.com/}
        ScanTarget : @{Url=http://www.linkedin.com/; Domain=www.linkedin.com; Defang=hxxp://www.linkedin.com/; IP=13.107.42.14; DNS=}
        Rewrite    : False
        Shortlink  : False
        Plugins    : @{Shodan=; Urlscan=; VirusTotal=}
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-PIEUrlDetails {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNull()]
        [System.Uri]$Url,

        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $EnablePlugins,

        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $VTDomainScan
    )
    Begin {

    }

    Process {
        $ScanTarget = [PSCustomObject]@{
            Url = $null
            Domain = $null
            Defang = $null
            IP = $null
            DNS = $null
        }

        # Output object that represents data input details and enrichment through inspection
        $URLDetails = [PSCustomObject]@{
            Type = $Url.HostNameType
            Url = $Url.AbsoluteUri
            Host = $Url.Host
            IsIP = $null
            IsPrivate = $null
            DNS = $null
            ScanTarget = $null
            Rewrite = $false
            Shortlink = $false
            Plugins = [PSCustomObject]@{
                Shodan = $null
                Urlscan = $null
                VirusTotal = $null
            }
        }



        if ($Url.HostNameType -like "IPv4") {
            $IPStatus = Test-ValidIPv4Address -IP $Url.Host
            # IP Address was resolved via Test-ValidIPv4Address.  Origin URL is IP Address
            if ($IPStatus.IsValid -eq $True) { 
                $UrlDetails.IsIP = $IPStatus.IsValid
                $UrlDetails.IsPrivate = $IPStatus.IsPrivate
            }
         }

        if ($UrlDetails.HostNameType -Like "IPv6") {
            $URLValue.IP = $Url.Host
        }

        if ($Url.HostNameType -like "Dns") {
            # IsIP - If URL is not direct link to IP address, IsIP = False
            $UrlDetails.IsIP = $false
            # Establish initial ScanTarget URL
            $ScanTarget.Url = $URLDetails.Url

            # Begin Section - DNS Resolution
            # Retrieve DNS details associated with URL
            $DNSResults = Invoke-PIEUrlDNSLookup -Url $ScanTarget.Url
            if ($DNSResults.Status -eq $true) {
                $UrlDetails.DNS = $DNSResults
                $ScanTarget.DNS = $DNSResults
            }
            # End Section - DNS Resolution




            # Section - Begin URLDecode
            # Check for Rewritten URL
            $UrlRewriteResults = Invoke-PIEUrlDecode -Url $ScanTarget.Url
            if ($UrlRewriteResults.Status -eq $true) {
                $URLDetails.Rewrite = $UrlRewriteResults
                # Set ScanTarget to new Decoded URL
                $ScanTarget.Url = $UrlRewriteResults.After

            }
            # Section - End URLDecode


            # Section - Begin Shortlink Expansion
            $UrlShortlinkResults = Invoke-PIEUrlExpand -Url $ScanTarget.Url
            if ($UrlShortlinkResults.Status -eq $True) {
                $URLDetails.Shortlink = $UrlShortlinkResults
                # Set ScanTarget to new Expanded URL
                $ScanTarget.Url = $UrlShortlinkResults.After
            }
            # Section - End Shortlink Expansion
            $ScanTarget.Domain = [System.Uri]$ScanTarget.Url | Select-Object -ExpandProperty Host
            $ScanTarget.Defang = $ScanTarget.Url.replace('http','hxxp')
            
            
            # If the URL has not been modified, carry forward previous DNS results.  
            # Otherwise, perform new DNS lookup for new ScanTarget URL
            if ($ScanTarget.Url -ne $URLDetails.Url) {
                $STDNSResults = Invoke-PIEUrlDNSLookup -Url $ScanTarget.Url
                if ($STDNSResults.Status -eq $true) {
                    $ScanTarget.DNS = $STDNSResults
                }
            }

            # Set one IPv4 out of the DNS results as the IP Scan Target
            if ($ScanTarget.DNS.Status -eq $true) {
                $ScanTarget.IP = $ScanTarget.DNS.IPv4 | Select-Object -First 1 -ExpandProperty IPAddressToString
            }

            # Update UrlDetails.ScanTarget
            $UrlDetails.ScanTarget = $ScanTarget
            

            # Section - Plugins
            if ($EnablePlugins) {

                # Establish UrlScan Request
                if ($LrtConfig.UrlScan.ApiKey) {
                    $UrlScanRequest = New-UrlScanRequest -Url $URLDetails.ScanTarget.Url
                    Start-Sleep 5
                }

                # Retrieve VirusTotal Results
                if ($LrtConfig.VirusTotal.ApiKey) {
                    if ($VTDomainScan) {
                        $VTResults = Get-VtDomainReport -Domain $URLDetails.ScanTarget.Domain
                    } else {
                        $VTResults = Get-VTUrlReport -Url $URLDetails.ScanTarget.Url
                        # Request the URL to be scanned if it is not found in the dataset
                        if ($VTResults.response_code -eq 0) {
                            $VTNewScan = New-VTUrlScanRequest -Url $URLDetails.ScanTarget.Url
                            Start-Sleep 5
                        }
                        # Retrieve the results if the data is found within the dataset
                        if ($VTResults.response_code -eq 1) {
                            $URLDetails.Plugins.VirusTotal = $VTResults
                        }
                    }
                }

                # Retrieve Shodan Results
                if ($LrtConfig.Shodan.ApiKey) {
                    if ($URLDetails.ScanTarget.IP) {
                        $ShodanResults = Get-ShodanHostIp -IPAddress $URLDetails.ScanTarget.IP
                        $URLDetails.Plugins.Shodan = $ShodanResults
                    }
                }

                # Retrieve URLScan Results if a Scan was requested
                if ($UrlScanRequest.uuid) {
                    $EscapeCount = 0
                    DO {
                        Start-Sleep 5
                        try {
                            $UrlscanResults = Get-UrlScanReport -uuid $UrlScanRequest.uuid
                        } catch {
                            $UrlscanResults = $_.Exception.Response.StatusCode.Value__
                        }
                        Write-Verbose $UrlscanResults
                        $EscapeCount += 1
                    } Until ($($UrlscanResults.data) -or $EscapeCount -ge 25)
                    $URLDetails.Plugins.UrlScan = $UrlscanResults
                }

                # 

                if ($VTNewScan.response_code -eq 1) {
                    $VTResults = Get-VTUrlReport -Url $URLDetails.ScanTarget.Url
                    # Retrieve the results if the data is found within the dataset
                    if ($VTResults.response_code -eq 1) {
                        $URLDetails.Plugins.VirusTotal = $VTResults
                    }
                }
            }
        }
        return $URLDetails
    }
}

