using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Inspects and enriches Header data as provided by PIE processing engine.
    .OUTPUTS
        PSCustomObject containing an enriched set of email header data.
    .EXAMPLE
        Invoke-PIEHeaderInspect -Headers $EvaluationResults.Headers
        ---
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Invoke-PIEHeaderInspect {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [Object]$Headers
    )

    Begin {
        $Regex_IPv6 = '(?<IPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:\)|\s+)'
        $Regex_IPv4 = '(?<IPv4>\d{1,3}(\.\d{1,3}){3})(?:\)|\s+)'
        # from x by y
        $Regex_Received1 = '^from\s+(?<fromhost>(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))\s\((?<fromaddr>(?<fIPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?<fIPv4>\d{1,3}(\.\d{1,3}){3}))\)\s+by\s+(?<by>(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))\s(\((?<byaddr>(?<bIPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?<bIPv4>\d{1,3}(\.\d{1,3}){3}))\))?.*,\s(?<date>(([0-9])|([0-2][0-9])|([3][0-1]))\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{4})\s(?<time>[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}).*$'
        # by y
        $Regex_Received2 = '^by\s+(?<byhost>(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))(\s\((?<byaddr>(?<bIPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?<bIPv4>\d{1,3}(\.\d{1,3}){3}))\))?\s+.*,\s(?<date>(([0-9])|([0-2][0-9])|([3][0-1]))\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{4})\s(?<time>[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}).*$'
    }

    Process {
        # Object that represents the data points for URL Shortlink services
        $HeaderOutput = [List[object]]::new()

        # Process Received
        $ReceivedData = $Headers | Where-Object -Property 'field' -like 'Received' | Sort-Object -Property Offset
        For ($i = 0; $i -lt $ReceivedData.Count; $i++) {
            $HeaderData = [PSCustomObject]@{
                Field = $ReceivedData[$i].Field
                Value = $ReceivedData[$i].Value
                Position = $null
                Step = $i
                From = [PSCustomObject]@{
                    Hostname = $null
                    IPv4 = $null
                    IPv6  = $null
                    Geolocation = $null
                }
                By = [PSCustomObject]@{
                    Hostname = $null
                    IPv4 = $null
                    IPv6  = $null
                    Geolocation = $null
                }
                Timestamp = $null
                
            }

            $Received1 = ([regex]::Matches($ReceivedData[$i].Value, $Regex_Received1))
            if ($Received1) {
                ForEach ($RegexMatch in $Received1) {
                    # From:
                    $HeaderData.From.Hostname = $RegexMatch.Groups["fromhost"].Value
                    if ($RegexMatch.Groups["fIPv6"].Value) {
                        $HeaderData.From.IPv6 = $RegexMatch.Groups["fIPv6"].Value
                    }
                    if ($RegexMatch.Groups["fIPv4"].Value) {
                        $HeaderData.From.IPv4 = $RegexMatch.Groups["fIPv4"].Value
                    }

                    # By:
                    if ($RegexMatch.Groups["by"].Value) {
                        $HeaderData.By.Hostname = $RegexMatch.Groups["by"].Value
                    }
                    if ($RegexMatch.Groups["bIPv6"].Value) {
                        $HeaderData.By.IPv6 = $RegexMatch.Groups["bIPv6"].Value
                    }
                    if ($RegexMatch.Groups["bIPv4"].Value) {
                        $HeaderData.By.IPv4 = $RegexMatch.Groups["bIPv4"].Value
                    }

                    # Time:
                    $Timestamp = $RegexMatch.Groups["date"].Value + " " + $RegexMatch.Groups["time"].Value
                    $HeaderData.timestamp = [datetime]::parseexact($Timestamp, 'd MMM yyyy HH:mm:ss', $null)
                }
            }
            
            $Received2 = ([regex]::Matches($ReceivedData[$i].Value, $Regex_Received2))
            if ($Received2) {
                ForEach ($RegexMatch in $Received2) {
                    # By:
                    if ($RegexMatch.Groups["byhost"].Value) {
                        $HeaderData.By.Hostname = $RegexMatch.Groups["byhost"].Value
                    }
                    if ($RegexMatch.Groups["bIPv6"].Value) {
                        $HeaderData.By.IPv6 = $RegexMatch.Groups["bIPv6"].Value
                    }
                    if ($RegexMatch.Groups["bIPv4"].Value) {
                        $HeaderData.By.IPv4 = $RegexMatch.Groups["bIPv4"].Value
                    }

                    # Time:
                    $Timestamp = $RegexMatch.Groups["date"].Value + " " + $RegexMatch.Groups["time"].Value
                    $HeaderData.timestamp = [datetime]::parseexact($Timestamp, 'd MMM yyyy HH:mm:ss', $null)
                }
            }

            
            # Set Header delivery chain position
            if ($i -eq 0) {
                $HeaderData.Position = "Destination"
            } elseif ($i -eq ($ReceivedData.Count -1)) {
                $HeaderData.Position = "Origin"
            } else {
                $HeaderData.Position = "Intermediary"
            }

            if ($HeaderOutput -NotContains $HeaderData) {
                $HeaderOutput.Add($HeaderData)
            }
        
        }


        Return $HeaderOutput
    }
}