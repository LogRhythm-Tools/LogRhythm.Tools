
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

function Format-ShodanTextOutput {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [object] $ShodanData,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $TargetName
    
    )

    Begin {
        # Analysis and Reporting
        $shodanHostDetails = $true
        $shodanSSLDetails = $true
        $shodanGameDetails = $true
    }

    Process {
        #Host Details
        $status = "==== Shodan.io - Host Summary Report ===="
        if ($TargetName) {
            $TargetIPStatus = Test-ValidIPv4Address $TargetName
            if ($TargetIPStatus.IsValid -eq $false) {
                $status += "`r`nReport summary for: $TargetName`:$($ShodanData.ip_str)"
            }
        } else {
            $status += "`r`nReport summary for: $($ShodanData.ip_str)"
        }
        
        if ( $($ShodanData.asn) ) { $status += "`r`nASN: $($ShodanData.asn)" }
        if ( $($ShodanData.tags) ) { $status += "`r`nDetected tags: $($ShodanData.tags)" }
        if ( $($ShodanData.os) ) { $status += "`r`nOperating System: $($ShodanData.os)" }
        if ( $($ShodanData.ports) ) { $status += "`r`nPorts: $($ShodanData.ports)" }

        if ( $shodanHostDetails ) {
            $status += "`r`n`r`n--- Host Details ---"
            $status += "`r`nCountry: $($ShodanData.country_name)"
            if ( $($ShodanData.city) ) { $status += "`r`nCity: $($ShodanData.city)" } 
            if ( $($ShodanData.region_code) ) { $status += "`r`nRegion: $($ShodanData.region_code)" }
            if ( $($ShodanData.postal_code) ) { $status += "`r`nPostal: $($ShodanData.postal_code)" }
            if ( $($ShodanData.org) ) { $status += "`r`nOrganization: $($ShodanData.org)" }
            if ( $($ShodanData.org) -ne $($ShodanData.isp) ) {
                if ( $($ShodanData.isp) ) { $status += "`r`nInternet Service Provider: $($ShodanData.isp)" }
            }
        }

        #Break out and report on Shodan data
        for($i=0; $i -le ($ShodanData.data.Length-1); $i++){
            $status += "`r`n`r`n--- Service $($ShodanData.data[$i]._shodan.module) ---"
            $status += "`r`nService Summary: $shodanIP`:$($ShodanData.data[$i].port) $($ShodanData.data[$i].transport.ToUpper())"
            if ( $($ShodanData.data[$i].tags) ) { $status += "`r`nReported Tags: $($ShodanData.data[$i].tags)" }
            if ( $($ShodanData.data[$i].product) ) { $status += "`r`nDetected Product: $($ShodanData.data[$i].product)" }
            if ( $($ShodanData.data[$i].http.server) ) { $status += "`r`nHTTP Server: $($ShodanData.data[$i].http.server)" }
            $SSLError = $($ShodanData.data[$i].data) | Select-String -Pattern "ssl error"
            if ( $SSLError ){
                $status += "`r`n$($ShodanData.data[$i].data)"
            }
            #Game Details
            if ( $shodanGameDetails ) {
            #Minecraft
                if ( $ShodanData.data[$i].product -eq "Minecraft" ) {
                $status += "`r`n-Minecraft Server Info-`r`n"
                    $status += "`r`nServer Version: $($ShodanData.data[$i].minecraft.version.name)"
                    $status += "`r`nServer Description: $($ShodanData.data[$i].minecraft.description)"
                    $status += "`r`nMax Players: $($ShodanData.data[$i].minecraft.players.max)"
                    $status += "`r`nCurrent Players: $($ShodanData.data[$i].minecraft.players.online)"
                }
            #Steam
                if ( $($ShodanData.data[$i]._shodan.module) -eq "steam-a2s" ) {
                    $status += "`r`n-Steam Server Info-`r`n"
                    $status += $ShodanData.data | Select-Object -ExpandProperty data
                }
            }
            #SSL
            if ( $ShodanData.data[$i].ssl ){
                $shodanCert = $ShodanData.data[$i] | Select-Object -ExpandProperty ssl
                if ( $shodanSSLDetails ) {
                    $status += "`r`n`r`n-- SSL Certificate Observed --"
                    $subject = $shodanCert.cert.subject -replace '[{}@]', ''
                    $status += "`r`nCertificate Subject: $subject"
                    $status += "`r`nCertificate SHA256: $($shodanCert.cert.fingerprint.sha256)"
                    $issuer = $shodanCert.cert.issuer -replace '[{}@]', ''
                    $status += "`r`nCertificate Issuer: $issuer"
                    $status += "`r`nCertificate Issue date: $($shodanCert.cert.issued)"
                    $status += "`r`nCertificate Expiration date: $($shodanCert.cert.expires)"
                    $ciphers = $shodanCert.cipher -replace '[{}@]', ''
                    $status += "`r`nSupported Ciphers: $ciphers`r`n"
                }
                if ( $($shodanCert.cert.expired) -eq $true ) {
                    $status += "`r`nALERT: Expired Certificate Detected!"
                    $threatScore += 1
                }
                if ( $($shodanCert.cert.issuer) -imatch "Let's Encrypt" ) {
                    $status += "`r`nALERT: Let's Encrypt Certificate Authority Detected!"
                    $threatScore += 1
                } elseif ( $($ShodanData.data[$i].tags) -imatch "self-signed" ) {
                    $status += "`r`nALERT: Self Signed Certificate Detected!"
                    $threatScore += 1
                }
            }
            #FTP
            if ( $ShodanData.data[$i]._shodan.module -eq "ftp" ) {
                $status += "`r`nAnonymous Login: $($ShodanData.data[$i].ftp.anonymous)"
                $threatScore += 1
            }   
        }
        $status += "`r`n`r`nFull details available: https://www.shodan.io/host/$($ShodanData.ip_str)`r`nLast scanned: $($ShodanData.last_update)."

        return $status
    }
}
