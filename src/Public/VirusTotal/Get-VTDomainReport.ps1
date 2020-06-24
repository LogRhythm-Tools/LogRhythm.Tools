using namespace System
using namespace System.Collections.Generic

Function Get-VTDomainReport {
    <#
    .SYNOPSIS
        Get VirusTotal Domain Report.
    .DESCRIPTION
        Get VirusTotal Url cmdlet retrieves summarized AntiVirus analysis results based on a Domain.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.VirusTotal.VtApiToken
        with a valid Api Token.
    .PARAMETER Domain
        Domain
    .INPUTS
        System.String -> Domain
    .OUTPUTS
        PSCustomObject representing the report results.
    .EXAMPLE
        PS C:\> Get-VtDomainReport -Credential $token -Url "logrhythm.com"
        ---
        BitDefender category             : computersandsoftware
        https_certificate_date           : 1576852588
        undetected_referrer_samples      : {@{date=2019-12-03 14:09:42; positives=0; total=72; 
                                           sha256=7a94e73ad647a13d0d8a00750bebea5940519c3fe5ff36bcd785941143911a6a}, @{date=2019-11-18 22:32:30; positives=0; 
                                           total=71; sha256=36e26bebe0efb0c0777c153117ade2a4e27a5ccec84fbfcac69bf68cc2fe27f8}, @{date=2019-11-04 23:56:02; 
                                           positives=0; total=72; sha256=bf445a91f7950d48d6aa44156e1b4860fa54182f781c5aafe7e3705cc8524f15}, @{date=2019-10-01 
                                           14:51:35; positives=0; total=70; sha256=5542a9bef46bb95fcd64d4dc8de5fa90614f4304b29e046800f7658371c06ed4}...}
        whois_timestamp                  : 1576171470
        domain_siblings                  : {}
        WOT domain info                  : @{Child safety=Excellent}
        detected_referrer_samples        : {@{date=2019-08-21 23:16:03; positives=10; total=69; 
                                           sha256=3e293f66162a6e909d41bfc31aed5c6373f501a64a07cdf91365a52c684aa40d}, @{date=2019-07-18 12:53:00; positives=1; 
                                           total=65; sha256=05df784c43f08b199760e15199551cc13422bf14547a1e05fd7be6519a2501e5}, @{date=2019-03-09 00:59:21; 
                                           positives=3; total=70; sha256=edd40d9106b50ea07864124f4d0c2a02bbf2fc307ae284fd1d8966fd25649e9d}, @{date=2019-03-01 
                                           07:07:47; positives=19; total=64; sha256=8c3e6fda275fe4bd8d659f56b0ea43b8094ed233ea39e85b0b42e5fc0a6af060}...}
        favicon                          : @{raw_md5=1215c6715102da01c470bb267b96238d; dhash=b2b0b296963232b2}
        Forcepoint ThreatSeeker category : business and economy
        undetected_downloaded_samples    : {@{date=2019-09-17 17:38:24; positives=0; total=36; 
                                           sha256=2068bd6313169d6c510ff350a51b7f05c9b2cbb4db0c67135d865283d4f7c341}, @{date=2019-07-30 11:48:04; positives=0; 
                                           total=55; sha256=cc7f95a6e4e690ee041fdc63b6b9f6ef0dd891510d82dd361ee045fcd2d7cbed}, @{date=2018-08-24 03:43:04; 
                                           positives=0; total=0; sha256=c40416d957d49a922641f59262ee776b579ebf5ba3fae1f16c2d36d20c7002c8}, @{date=2018-08-08 
                                           00:07:07; positives=0; total=24; sha256=ed6d1921a94e9095ee167b63c180f4b3b6b6572a6bdec7c50f3ac8f36bb8ef6c}...}
        resolutions                      : {@{last_resolved=2019-10-19 02:06:05; ip_address=13.225.54.115}, @{last_resolved=2019-10-19 02:06:05; 
                                           ip_address=13.225.54.123}, @{last_resolved=2019-10-19 02:06:05; ip_address=13.225.54.37}, @{last_resolved=2019-10-19 
                                           02:06:05; ip_address=13.225.54.56}...}
        subdomains                       : {info.logrhythm.com, onlinehelp72.logrhythm.com, community-staging.logrhythm.com, onlinehelp74.logrhythm.com...}
        last_https_certificate           : @{public_key=; thumbprint_sha256=bfcdea3ed499a62e0d4a39774acbe01903be5dd7f85be51b65bb3e1e0a55009d; tags=System.Object[]; 
                                           signature_algorithm=sha256RSA; subject=; validity=; version=V3; extensions=; cert_signature=; 
                                           serial_number=bc6ed4c5be0202f19ec37cf32955e0d; thumbprint=b32b852d0d1c303e3576e5c5973786c9c0f7cca3; issuer=; size=1381}
        dns_records                      : {@{type=A; value=13.227.101.19; ttl=59}, @{type=A; value=13.227.101.2; ttl=59}, @{type=TXT; 
                                           value=facebook-domain-verification=u3l3u12gt68p9k10438onz1yu9xp8s; ttl=59}, @{type=NS; value=ns-574.awsdns-07.net; 
                                           ttl=12389}...}
        categories                       : {computersandsoftware, business and economy}
        popularity_ranks                 : @{Majestic=; Alexa=; Cisco Umbrella=; Quantcast=}
        dns_records_date                 : 1576852588
        undetected_urls                  : {https://logrhythm.com/gartner-magic-quadrant-siem-report-2018/?utm_source=google 
                                           14d5c364d7ac0841bc8f6f044bec52c9183579b8ba45d49f773937e064c0e5e9 0 72 2019-12-12 04:23:49, 
                                           https://logrhythm.com/images/icons/email-icons/linkedin-icon-logrhythm.png 
                                           9d26fa2fe57b1a5e2a810539f28b1ae44fdf730de46115f4eac33f9b6d7f7134 0 72 2019-12-06 22:06:01, 
                                           https://logrhythm.com/use-cases/absence-of-an-event/ d5c0695de1146388976ccff0d2b7ed034f9517aeba108f5b8ac4f56dbecba303 0 71 
                                           2019-11-18 10:15:31, https://logrhythm.com/solutions/compliance/nerc-cip/?utm_source=google 
                                           e752156fd45c4c1fdf9b96d5fbad579b3f859747d63ad02cdf0baa57b937f75e 0 71 2019-11-18 08:46:09...}
        whois                            : Creation Date: 2003-12-27T18:38:12Z
                                           DNSSEC: unsigned
                                           Domain Name: LOGRHYTHM.COM
                                           Domain Status: clientDeleteProhibited http://www.icann.org/epp#clientDeleteProhibited
                                           Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
                                           Domain Status: clientRenewProhibited http://www.icann.org/epp#clientRenewProhibited
                                           Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
                                           Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited
                                           Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
                                           Domain Status: clientUpdateProhibited http://www.icann.org/epp#clientUpdateProhibited
                                           Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
                                           Name Server: NS-1321.AWSDNS-37.ORG
                                           Name Server: NS-143.AWSDNS-17.COM
                                           Name Server: NS-1923.AWSDNS-48.CO.UK
                                           Name Server: NS-574.AWSDNS-07.NET
                                           Registrant Country: US
                                           Registrant Email: 718b5941b617be80s@
                                           Registrant Organization: d7fb94c529d8abdc
                                           Registrant State/Province: 2745e750b3a0ac2a
                                           Registrar Abuse Contact Email: abuse@godaddy.com
                                           Registrar Abuse Contact Phone: +1.4806242505
                                           Registrar Abuse Contact Phone: 480-624-2505
                                           Registrar IANA ID: 146
                                           Registrar Registration Expiration Date: 2020-12-27T18:38:12Z
                                           Registrar URL: http://www.godaddy.com
                                           Registrar WHOIS Server: whois.godaddy.com
                                           Registrar: GoDaddy.com, LLC
                                           Registry Domain ID: 108932594_DOMAIN_COM-VRSN
                                           Registry Expiry Date: 2020-12-27T18:38:12Z
                                           Updated Date: 2018-12-28T15:46:09Z
                                           Updated Date: 2018-12-28T15:46:10Z
        response_code                    : 1
        Webutation domain info           : @{Verdict=safe; Adult content=no; Safety score=100}
        verbose_msg                      : Domain found in dataset
        Websense ThreatSeeker category   : business and economy
        detected_downloaded_samples      : {}
        detected_urls                    : {}
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
        [string] $Domain
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.VirusTotal.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
    }

    Process {
        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "/domain/report?apikey=$Token&domain=$Domain"
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