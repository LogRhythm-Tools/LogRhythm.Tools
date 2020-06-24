using namespace System
using namespace System.Collections.Generic

Function Get-VTUrlReport {
    <#
    .SYNOPSIS
        Get VirusTotal Url Report.
    .DESCRIPTION
        Get VirusTotal Url cmdlet retrieves summarized AntiVirus analysis results based on a Url.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.VirusTotal.VtApiToken
        with a valid Api Token.
    .PARAMETER Url
        URL
    .INPUTS
        System.String -> Url
    .OUTPUTS
        PSCustomObject representing the report results.
    .EXAMPLE
        PS C:\> Get-VtUrlReport -Credential $token -Url "https://logrhythm.com"
        ---
        scan_id       : 9270b9ee778eac9801b130221dda1eb37e68b676a310922cf2b62e63496da404-1570695201
        resource      : https://logrhythm.com
        url           : https://logrhythm.com/
        response_code : 1
        scan_date     : 2019-10-10 08:13:21
        permalink     : https://www.virustotal.com/url/9270b9ee778eac9801b130221dda1eb37e68b676a310922cf2b62e63496da404/analysis/1570695201/
        verbose_msg   : Scan finished, scan information embedded in this object
        filescan_id   : 
        positives     : 0
        total         : 71
        scans         : @{CLEAN MX=; DNS8=; VX Vault=; ZDB Zeus=; Tencent=; MalwarePatrol=; ZCloudsec=; PhishLabs=; Zerofox=; K7AntiVirus=; FraudSense=; Virusdie 
                        External Site Scan=; Spamhaus=; Quttera=; AegisLab WebGuard=; MalwareDomainList=; ZeusTracker=; zvelo=; Google Safebrowsing=; Kaspersky=; 
                        BitDefender=; Dr.Web=; G-Data=; Segasec=; OpenPhish=; Malware Domain Blocklist=; CRDF=; Trustwave=; Web Security Guard=; CyRadar=; 
                        desenmascara.me=; ADMINUSLabs=; Malwarebytes hpHosts=; Opera=; AlienVault=; Emsisoft=; Malc0de Database=; malwares.com URL checker=; 
                        Phishtank=; EonScope=; Malwared=; Avira=; NotMining=; CyberCrime=; Antiy-AVL=; Forcepoint ThreatSeeker=; SCUMWARE.org=; ESTsecurity-Threat 
                        Inside=; Comodo Site Inspector=; Yandex Safebrowsing=; Malekal=; ESET=; Sophos=; URLhaus=; SecureBrain=; Nucleon=; BADWARE.INFO=; Sucuri 
                        SiteCheck=; Blueliv=; Netcraft=; AutoShun=; ThreatHive=; FraudScore=; Rising=; URLQuery=; StopBadware=; Fortinet=; ZeroCERT=; Spam404=; 
                        securolytics=; Baidu-International=}
    .NOTES
        VirusTotal-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.VirusTotal.ApiKey,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [string] $Url
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.VirusTotal.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
    }

    Process {
        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "/url/report?apikey=$Token&resource=$Url"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        Try {
            $vtResponse = Invoke-RestMethod $RequestUrl -Method $Method 
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }
    }
 

    End {
        Return $vtResponse
    }
}