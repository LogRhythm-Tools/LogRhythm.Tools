using namespace System.Collections.Generic
#====================================#
#       Shodan PIE plugin            #
#         Version 1.7                #
#        Author: Jtekt               #
#====================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
# Shodan.io integration for PIE.  
# This plugin provides a means to increase evidence collection capability and aid the risk assessment process based on Shodan observations.
#   
# Goals:
# <complete> - Collect additional evidence on link.  Geographic location, IP address, Certificate Authority & expiration.
# <complete> - Report self-signed certificates, expired, and Let's Encrypt Certificate Authorities.
# <complete> - Parse services running on host.  
#
# ThreatScore is increased by each of the following:
#     * Self-Signed Certificate Detected
#     * Expired Certificate Detected
#     * Let's Encrypt Certificate Authority
#     * Anonymous FTP Login Capable
#  
# .\Shodan.ps1 -key $shodanAPI -link $splitLink -caseID $caseID -caseFolder $caseFolder -pieFolder $pieFolder -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken

function Format-VTTextOutput {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [object] $VTData,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $TargetName
    )

    Begin {
    }

    Process {
        $DetectedUrls = [list[PSObject]]::new()
        $UndetectedUrls = [list[PSObject]]::new()


        #$DefangedUrl = $VTData.task.url -replace "(?<tag1>http)((s)?://)", "hxxp://$0"
        #Host Details
        Switch ($($VTData.verbose_msg)) {
            "Domain found in dataset" { 
                $VTScanType = "Domain "
                $VTScanStatus = $true
            }
            "IP address in dataset" {
                $VTScanType = "IP "
                $VTScanStatus = $true
            }
        }

        
        $status = "==== VirusTotal - $($VTScanType)Summary Report ===="
        if ($TargetName) { $status += "`r`n$VTScanType`: $TargetName" }
        # Section - IP 
        if ($VTScanType -like "IP ") {
            if ( $($VTData.asn) ) { $status += "`r`nASN: $($VTData.asn)"}
            if ( $($VTData.as_owner) ) { $status += "   ASN Owner: $($VTData.as_owner)"}
        }

        if ($VTScanStatus) {
            # Detected URL Stats
            if ($($VTData.detected_urls)) {
                if ($VTData.detected_urls.count -ge 2) {
                    foreach ($VTUrl in $($VTData.detected_urls)) {
                        $SplitValues = $VTUrl.scan_date -split " "
                        $DetectionObject = [PSCustomObject]@{
                            Value = $VTUrl.url
                            Detections = $VTUrl.positives
                            Detectors = $VTUrl.total
                            Date = $SplitValues[0]
                            Time = $SplitValues[1]
                        }
                        if ($DetectedUrls -notcontains $DetectionObject) {
                            Write-Verbose "$(Get-Timestamp) - List: DetectedUrls  Adding value for URL: $($DetectionObject.Value)"
                            $DetectedUrls.add($DetectionObject)
                        }
                    }
                } else {
                    $SplitValues = $($VTData.detected_urls) -split '\r?\n' -split " "
                    $DetectionObject = [PSCustomObject]@{
                        Value = $SplitValues[0]
                        Detections = $SplitValues[1]
                        Detectors = $SplitValues[2]
                        Date = $SplitValues[3]
                        Time = $SplitValues[4]
                    }
                    if ($DetectedUrls -notcontains $DetectionObject) {
                        Write-Verbose "$(Get-Timestamp) - List: DetectedUrls  Adding value for URL: $($DetectionObject.Value)"
                        $DetectedUrls.add($DetectionObject)
                    }
                }

                $DetectedUrlCount = $DetectedUrls.count
                $DetectedDetectorsAvg = $DetectedUrls | Measure-Object -Property Detectors -Average | Select-Object -ExpandProperty Average
                $DetectedDetectorsAvg = [Math]::round($DetectedDetectorsAvg)
                $DetectedDetectionsAvg = $DetectedUrls | Measure-Object -Property Detections -Average | Select-Object -ExpandProperty Average
                $DetectedDetectionsAvg = [Math]::round($DetectedDetectionsAvg)
                $DetectedDetectionsMax = $DetectedUrls | Measure-Object -Property Detections -Maximum | Select-Object -ExpandProperty Maximum
                $DetectedDetectionsMin = $DetectedUrls | Measure-Object -Property Detections -Minimum | Select-Object -ExpandProperty Minimum

                $status += "`r`n`r`n-- URL Entries - Detected Threats --"
                $status += "`r`nTotal URLs: $DetectedUrlCount"
                $status += "`r`nTop Threat Score: $DetectedDetectionsMax"
                $status += "`r`nBottom Threat Score: $DetectedDetectionsMin"
                $status += "`r`nAverage Threat Score: $DetectedDetectionsAvg"
                $status += "`r`nAverage Detector Count: $DetectedDetectorsAvg"
            }

            # Undetected URL Stats
            if ($($VTData.undetected_urls)) {
                if ($VTData.undetected_urls.count -ge 2) {
                    foreach ($VTUrl in $VTData.undetected_urls) {
                        $SplitValues = $VTUrl -split '\r?\n' -split " "
                        $DetectionObject = [PSCustomObject]@{
                            Value = $SplitValues[0]
                            Hash = $SplitValues[1]
                            Detections = $SplitValues[2]
                            Detectors = $SplitValues[3]
                            Date = $SplitValues[4]
                            Time = $SplitValues[5]
                        }
                        if ($UndetectedUrls -notcontains $DetectionObject) {
                            Write-Verbose "$(Get-Timestamp) - List: UnDetectedUrls   Adding value for URL: $($DetectionObject.Value)"
                            $UndetectedUrls.add($DetectionObject)
                        }
                    }
                } else {
                    $SplitValues = $($VTData.undetected_urls) -split '\r?\n' -split " "
                    $DetectionObject = [PSCustomObject]@{
                        Value = $SplitValues[0]
                        Hash = $SplitValues[1]
                        Detections = $SplitValues[2]
                        Detectors = $SplitValues[3]
                        Date = $SplitValues[4]
                        Time = $SplitValues[5]
                    }
                    if ($UndetectedUrls -notcontains $DetectionObject) {
                        Write-Verbose "$(Get-Timestamp) - List: UnDetectedUrls   Adding value for URL: $($DetectionObject.Value)"
                        $UndetectedUrls.add($DetectionObject)
                    }
                }
                $UndetectedUrlCount = $UndetectedUrls.count
                $UndetectedDetectorsAvg = $UndetectedUrls | Measure-Object -Property Detectors -Average | Select-Object -ExpandProperty Average
                $UndetectedDetectorsAvg = [Math]::round($UndetectedDetectorsAvg)
                $UndetectedDetectionsMax = $UndetectedUrls | Measure-Object -Property Detections -Maximum | Select-Object -ExpandProperty Maximum
                $UnDetectedDetectionsAvg = $UndetectedUrls | Measure-Object -Property Detections -Average | Select-Object -ExpandProperty Average
                $UnDetectedDetectionsMin = $UndetectedUrls | Measure-Object -Property Detections -Minimum | Select-Object -ExpandProperty Minimum


                $status += "`r`n`r`n-- URL Entries - Zero Threats --"
                $status += "`r`nTotal URLs: $UndetectedUrlCount"
                $status += "`r`nTop Threat Score: $UndetectedDetectionsMax"
                $status += "`r`nBottom Threat Score: $UnDetectedDetectionsMin"
                $status += "`r`nAverage Threat Score: $UnDetectedDetectionsAvg"
                $status += "`r`nAverage Detector Count: $UndetectedDetectorsAvg"
            }

            ## Section - Domain
            if ($VTScanType -like "Domain ") {
                $status += "`r`n`r`n-- $VTScanType`Category Info --"
                            
                if ( $($VTData."Webutation domain info") ) { 
                    $status += "`r`nWebutation Verdict: $((Get-Culture).TextInfo.ToTitleCase($VTData.`"Webutation domain info`".Verdict))    Adult Content: $((Get-Culture).TextInfo.ToTitleCase($VTData.`"Webutation domain info`"."Adult content"))    Safety Score: $((Get-Culture).TextInfo.ToTitleCase($VTData.`"Webutation domain info`"."Safety score"))"
                }
                if ( $($VTData."Forcepoint ThreatSeeker category") ) { $status += "`r`nForcepoint ThreatSeeker Category: $((Get-Culture).TextInfo.ToTitleCase($VTData.`"Forcepoint ThreatSeeker category`"))"}
                if ( $($VTData."Comodo Valkyrie Verdict category") ) { $status += "`r`nComodo Valkyrie Category: $((Get-Culture).TextInfo.ToTitleCase($VTData.`"Comodo Valkyrie Verdict category`"))"}
                if ( $($VTData."BitDefender category") ) { $status += "`r`nBitDefender Category: $((Get-Culture).TextInfo.ToTitleCase($VTData.`"BitDefender category`"))"}
                if ( $($VTData."sophos category") ) { $status += "`r`nSophos Category: $((Get-Culture).TextInfo.ToTitleCase($VTData.`"sophos category`"))"}

                
                if ($VTData.whois) {
                    $status += "`r`n`r`n-- Whois --`r`n$($VTData.whois)"
                }
            }
            # Section - Domain
        } else {
            $status += "`r`nUnable to retrieve VirusTotal results."
        }

        return $status
    }
}
