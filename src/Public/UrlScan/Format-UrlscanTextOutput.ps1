
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

function Format-UrlscanTextOutput {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [object] $UrlscanData,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('detail', 'summary', ignorecase=$true)]
        [string] $Type = "Detail"
    )

    Begin {
    }

    Process {
        $DefangedUrl = $UrlscanData.task.url -replace "(?<tag1>http)((s)?://)", "hxxp://$0"
        #Host Details
        $status = "==== Urlscan.io - Summary Report ====`r`nLink: $DefangedUrl"

        if ($UrlscanData.verdicts.overall.score -ge 0) {
            $status += "`r`n`r`n-- Verdicts --"
            if ( $($UrlscanData.verdicts.overall.score) ) { $status += "`r`nScore: $($UrlscanData.verdicts.overall.score)"}
            if ( $($UrlscanData.verdicts.overall.Categories) ) { $status += "`r`nCategories: $($UrlscanData.verdicts.overall.categories)"}
            if ( $($UrlscanData.verdicts.overall.brands) ) { $status += "`r`nBrands: $($UrlscanData.verdicts.overall.brands)"}
            if ( $($UrlscanData.verdicts.overall.tags) ) { $status += "`r`nTags: $($UrlscanData.verdicts.overall.tags)"}
            if ( $($UrlscanData.verdicts.overall.Malicious.tostring()) ) { $status += "`r`nMalicious: $($UrlscanData.verdicts.overall.Malicious)"}
        }

        if ($Type -like "Detail") {
            if ($UrlscanData.meta.processors.asn.data) {
                $status += "`r`n`r`n-- Host Assets --"
                foreach ($AsnEntry in $($UrlscanData.meta.processors.asn.data)) {
                    if ( $($AsnEntry.ip) ) { $status += "`r`nIP: $($AsnEntry.ip)"}
                    if ( $($AsnEntry.asn) ) { $status += "`r`nASN: $($AsnEntry.asn)"}
                    if ( $($AsnEntry.name) ) { $status += "`r`nName: $($AsnEntry.name)"}
                    if ( $($AsnEntry.description) ) { $status += "`r`nDescription: $($AsnEntry.description)"}
                    if ( $($AsnEntry.registrar) ) { $status += "`r`nRegistrar: $($AsnEntry.registrar)"}
                    if ( $($AsnEntry.country) ) { $status += "`r`nCountry: $($AsnEntry.country)"}
                    if ( $($AsnEntry.route) ) { $status += "`r`nNetblock: $($AsnEntry.route)`r`n"}
                }
            }
        }

        if ($UrlscanData.meta.processors.download.data) {
            $status += "`r`n`r`n-- File Downloadable Assets --"
            foreach ($DataEntry in $($UrlscanData.meta.processors.download.data)) {
                if ( $($AsnEntry.filename) ) { $status += "`r`nName: $($AsnEntry.filename)"}
                if ( $($AsnEntry.sha256) ) { $status += "`r`nSHA256: $($AsnEntry.sha256)"}
                if ( $($AsnEntry.filesize) ) { $status += "`r`nFile size: $($AsnEntry.filesize)"}
                if ( $($AsnEntry.mimeType) ) { $status += "`r`nMIME Type: $($AsnEntry.mimeType)"}
                if ( $($AsnEntry.mimeDescription) ) { $status += "`r`nMIME Description: $($AsnEntry.mimeDescription)"}
            }
        }

        if ( $UrlscanData.task.screenshotURL ) {
            $status += "`r`n`r`n--- Screenshot Details ---"
            $status += "`r`nScreenshot URL: $($UrlscanData.task.screenshotURL)"
        }

        $status += "`r`n`r`nFull details available: $($UrlScanData.task.reportURL)`r`nLast scanned: $($UrlscanData.task.time)."

        return $status
    }
}
