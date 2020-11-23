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


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true ,Position = 1)]
        [string] $Domain,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true ,Position = 2)]
        [string] $Hash,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true ,Position = 3)]
        [string] $IpAddr,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true ,Position = 4)]
        [string] $Url
    )

    Begin {
    }

    Process {
        $DetectedUrls = [list[PSObject]]::new()
        $UndetectedUrls = [list[PSObject]]::new()
        $DetectedHashes = [list[PSObject]]::new()
        $UndetectedHashes = [list[PSObject]]::new()
        $PositiveScans = [list[PSObject]]::new()

        #$DefangedUrl = $VTData.task.url -replace "(?<tag1>http)((s)?://)", "hxxp://$0"
        #Host Details
        if ($Url) {
            $VTScanType = "Url"
            $TargetName = $Url -replace "(?<tag1>http)((s)?://)", "hxxp://$0"
        }

        if ($IpAddr) {
            $VTScanType = "IP"
            $TargetName = $IpAddr
        }

        if ($Hash) {
            $VTScanType = "Hash"
            $TargetName = $Hash
        }

        if ($Domain) {
            $VTScanType = "Domain"
            $TargetName = $Domain
        }

        Switch ($($VTData.verbose_msg)) {
            "Domain found in dataset" {$VTScanStatus = $true;break}
            "IP address in dataset" {$VTScanStatus = $true;break}
            "Scan finished, scan information embedded in this object" {$VTScanStatus = $true;break}
            "Scan finished, information embedded" {$VTScanStatus = $true;break}
        }

        
        $status = "==== VirusTotal - $($VTScanType) Summary Report ===="
        if ($TargetName) { $status += "`r`n$VTScanType`: $TargetName" }


        if ($VTScanStatus) {
            # Section - URL
            if ($VTScanType -like "Url" -or $VTScanType -like "Hash") {
                if ($VTScanType -like "Hash") {
                    if (($null -ne $VTData.md5) -and ($VTData.md5 -ne $Hash)) {
                        $status += "`r`nMD5: $($VTData.md5)"
                    } 
                    if (($null -ne $VTData.sha1) -and ($VTData.sha1 -ne $Hash)) {
                        $status += "`r`nSHA1: $($VTData.sha1)"
                    } 
                    if (($null -ne $VTData.sha256) -and ($VTData.sha256 -ne $Hash)) {
                        $status += "`r`nSHA256: $($VTData.sha256)"
                    } 
                }
                $status += "`r`n`r`n-- $VTScanType - Threat Summary --"
                $status += "`r`nThreat Score: $($VTData.positives)"
                $status += "`r`nDetectors: $($VTData.total)"

                if ($VTData.positives -ge 1) {
                    $VTData.scans.psobject.properties | ForEach-Object {
                        $DetectionObject = [PSCustomObject]@{
                            Vendor = $_.Name
                            Value = $_.Value.detected
                            Note = $_.Value.result 
                            Detail = $_.Value.detail
                        }
                        if ($DetectionObject.Value -like "True") {
                            $PositiveScans.Add($DetectionObject)
                        }
                    }
                    $status += "`r`n`r`n-- Positive Scanners --"
                    ForEach ($PositiveScan in $PositiveScans) {
                        $status += "`r`nScanner: $($PositiveScan.vendor)"
                        $status += "`r`nNote: $($PositiveScan.Note)"
                        if ($PositiveScan.detail) {$status += "`r`nDetails: $($PositiveScan.Detail)"}
                        $status += "`r`n"
                    }
                    
                }



                # Add section for $VTData.filescan_id
                if ($($VTData.permalink)) {$status += "`r`n`r`nScan Report: $($VTData.permalink)"}
                if ($($VTData.scan_date)) {$status += "`r`nScan Date: $($VTData.scan_date)"}
            }

            # Section - IP 1
            if ($VTScanType -like "IP") {
                if ( $($VTData.asn) ) { $status += "`r`nASN: $($VTData.asn)"}
                if ( $($VTData.as_owner) ) { $status += "   ASN Owner: $($VTData.as_owner)"}
            }

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


            # Detected Downloaded Samples
            if ($($VTData.detected_downloaded_samples)) {
                if ($VTData.detected_downloaded_samples.count -ge 2) {
                    foreach ($VTDLData in $($VTData.detected_downloaded_samples)) {
                        $SplitValues = $VTDLData.date -split " "
                        $DetectionObject = [PSCustomObject]@{
                            Value = $VTDLData.sha256
                            Detections = $VTDLData.positives
                            Detectors = $VTDLData.total
                            Date = $SplitValues[0]
                            Time = $SplitValues[1]
                        }
                        if ($DetectedHashes -notcontains $DetectionObject) {
                            Write-Verbose "$(Get-Timestamp) - List: DetectedHashes  Adding value for Hash: $($DetectionObject.Value)"
                            $DetectedHashes.add($DetectionObject)
                        }
                    }
                } else {
                    $SplitValues = $($VTData.detected_downloaded_samples.date) -split " "
                    $DetectionObject = [PSCustomObject]@{
                        Value = $VTData.detected_downloaded_samples.sha256
                        Detections = $VTData.detected_downloaded_samples.positives
                        Detectors = $VTData.detected_downloaded_samples.total
                        Date = $SplitValues[0]
                        Time = $SplitValues[1]
                    }
                    if ($DetectedHashes -notcontains $DetectionObject) {
                        Write-Verbose "$(Get-Timestamp) - List: DetectedHashes  Adding value for Hash: $($DetectionObject.Value)"
                        $DetectedHashes.add($DetectionObject)
                    }
                }

                $DetectedHashCount = $DetectedHashes.count
                $DetectedHashDetectorAvg = $DetectedHashes | Measure-Object -Property Detectors -Average | Select-Object -ExpandProperty Average
                $DetectedHashDetectorAvg = [Math]::round($DetectedHashDetectorAvg)
                $DetectedHashDetectionAvg = $DetectedHashes | Measure-Object -Property Detections -Average | Select-Object -ExpandProperty Average
                $DetectedHashDetectionAvg = [Math]::round($DetectedHashDetectionAvg)
                $DetectedHashDetectionMax = $DetectedHashes | Measure-Object -Property Detections -Maximum | Select-Object -ExpandProperty Maximum
                $DetectedHashDetectionMin = $DetectedHashes | Measure-Object -Property Detections -Minimum | Select-Object -ExpandProperty Minimum

                $status += "`r`n`r`n-- File Hash Entries - Detected Threats --"
                $status += "`r`nTotal Hashes: $DetectedHashCount"
                $status += "`r`nTop Threat Score: $DetectedHashDetectionMax"
                $status += "`r`nBottom Threat Score: $DetectedHashDetectionMin"
                $status += "`r`nAverage Threat Score: $DetectedHashDetectionAvg"
                $status += "`r`nAverage Detector Count: $DetectedHashDetectorAvg"
            }


            # Undetected Downloaded Samples
            if ($($VTData.undetected_downloaded_samples)) {
                if ($VTData.undetected_downloaded_samples.count -ge 2) {
                    foreach ($VTDLData in $($VTData.undetected_downloaded_samples)) {
                        $SplitValues = $VTDLData.date -split " "
                        $DetectionObject = [PSCustomObject]@{
                            Value = $VTDLData.sha256
                            Detections = $VTDLData.positives
                            Detectors = $VTDLData.total
                            Date = $SplitValues[0]
                            Time = $SplitValues[1]
                        }
                        if ($UndetectedHashes -notcontains $DetectionObject) {
                            Write-Verbose "$(Get-Timestamp) - List: UndetectedHashes  Adding value for Hash: $($DetectionObject.Value)"
                            $UndetectedHashes.add($DetectionObject)
                        }
                    }
                } else {
                    $SplitValues = $($VTData.undetected_downloaded_samples.date) -split " "
                    $DetectionObject = [PSCustomObject]@{
                        Value = $VTData.undetected_downloaded_samples.sha256
                        Detections = $VTData.undetected_downloaded_samples.positives
                        Detectors = $VTData.undetected_downloaded_samples.total
                        Date = $SplitValues[0]
                        Time = $SplitValues[1]
                    }
                    if ($UndetectedHashes -notcontains $DetectionObject) {
                        Write-Verbose "$(Get-Timestamp) - List: UndetectedHashes  Adding value for Hash: $($DetectionObject.Value)"
                        $UndetectedHashes.add($DetectionObject)
                    }
                }

                $UndetectedHashCount = $UndetectedHashes.count
                $UndetectedHashDetectorAvg = $UndetectedHashes | Measure-Object -Property Detectors -Average | Select-Object -ExpandProperty Average
                $UndetectedHashDetectorAvg = [Math]::round($UndetectedHashDetectorAvg)
                $UndetectedHashDetectionAvg = $UndetectedHashes | Measure-Object -Property Detections -Average | Select-Object -ExpandProperty Average
                $UndetectedHashDetectionAvg = [Math]::round($UndetectedHashDetectionAvg)
                $UndetectedHashDetectionMax = $UndetectedHashes | Measure-Object -Property Detections -Maximum | Select-Object -ExpandProperty Maximum
                $UndetectedHashDetectionMin = $UndetectedHashes | Measure-Object -Property Detections -Minimum | Select-Object -ExpandProperty Minimum

                $status += "`r`n`r`n-- File Hash Entries - Zero Threats --"
                $status += "`r`nTotal Hashes: $UndetectedHashCount"
                $status += "`r`nTop Threat Score: $UndetectedHashDetectionMax"
                $status += "`r`nBottom Threat Score: $UndetectedHashDetectionMin"
                $status += "`r`nAverage Threat Score: $UndetectedHashDetectionAvg"
                $status += "`r`nAverage Detector Count: $UndetectedHashDetectorAvg"
            }


            ## Section - Domain
            if ($VTScanType -like "Domain") {
                $status += "`r`n`r`n-- $VTScanType `Category Info --"
                            
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

                if ($TargetName) {
                    $status += "`r`n`r`nScan Report: https://www.virustotal.com/gui/domain/$TargetName/detection"
                    $status += "`r`nCreation Date: $(Get-Date -Format `"yyyy/MM/dd HH:mm:ss`")"
                }
            }
            # Section - Domain

            # Section - IP 2
            if ($VTScanType -like "IP") {
                $status += "`r`n`r`nScan Report: https://www.virustotal.com/gui/ip-address/$TargetName/detection"
                $status += "`r`nCreation Date: $(Get-Date -Format `"yyyy/MM/dd HH:mm:ss`")"
            }
        } else {
            if ($($VTData.verbose_msg)) { $status += "`r`nStatus Details: $($VTData.verbose_msg)"}
            $status += "`r`n`r`nUnable to retrieve VirusTotal results."
        }

        return $status
    }
}
