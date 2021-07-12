using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Performs DNS resolution for a given URL and provides IPv4 and IPv6 resoution in a PSCustomObject result.
    .OUTPUTS
        PSCustomObject containing the Resolution Status, IPv4 array, IPv6 array, IsPrivate status, source URL for DNS lookup.
    .EXAMPLE
        Invoke-PIEUrlDNSLookup -Url 'https://bit.ly/37lYpxb'
        ---
        Status    : True
        IPv4      : {67.199.248.11, 67.199.248.10}
        IPv6      : {}
        IsPrivate : False
        URL       : https://bit.ly/37lYpxb
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Invoke-PIEUrlDNSLookup {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [System.Uri]$Url
    )
    Begin {
        # Define URL Rewrite Services
    }

    Process {
        $DNSOutput = [PSCustomObject]@{
            Status = $False
            IPv4 = $null
            IPv6 = $null
            IsPrivate = $null
            URL = $Url
        }

        Try {
            $DNSResults = Resolve-DnsName -Name $($Url.Host) -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue
        } Catch { 
            
        }
        # If successfull DNS results returned, split IPv4 and IPv6 resolution details into URLDetails object
        if ($DNSResults) {
            $DNSOutput.Status = $true
            $IPv6Results = $DNSResults | Where-Object -Property "Type" -like "AAAA"
            $IPv4Results = $DNSResults | Where-Object -Property "Type" -like "A"
            $IPv4Output = [list[string]]::new()
            $IPv6Output = [list[string]]::new()
            ForEach ($IPv4Result in $IPv4Results) {
                $IPv4 = Test-ValidIPv4Address -IP $($IPv4Result | Select-Object -ExpandProperty IP4Address).ToString()
                if ($IPv4.IsValid -eq $True) {
                    if ($IPv4Output -NotContains $IPv4.Value) {
                        $IPv4Output.Add($IPv4.Value)
                    }
                    if ($IPv4.IsPrivate) {
                        $DNSOutput.IsPrivate = $IPv4.IsPrivate
                    }
                }
            }

            ForEach ($IPv6Result in $IPv6Results) {
                $IPv6 = ($IPv6Result | Select-Object -ExpandProperty IP6Address).ToString()

                if ($IPv6) {
                    if ($IPv6Output -NotContains $IPv6) {
                        $IPv6Output.Add($IPv6)
                    }
                }
            }
            if (!$DNSOutput.IsPrivate) { 
                $DNSOutput.IsPrivate = $false
            }
            $DNSOutput.IPv4 = $IPv4Output
            $DNSOutput.IPv6 = $IPv6Output
        }

        return $DNSOutput
    }    
}