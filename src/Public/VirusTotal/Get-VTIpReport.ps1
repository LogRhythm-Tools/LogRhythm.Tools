using namespace System
using namespace System.Collections.Generic
Function Get-VTIPReport {
    <#
    .SYNOPSIS
        Get VirusTotal Ip Report.
    .DESCRIPTION
        Get VirusTotal Ip cmdlet retrieves summarized AntiVirus analysis results based on a Ip Address.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.VirusTotal.VtApiToken
        with a valid Api Token.
    .PARAMETER IpAddr
        Ipv4/Ipv6 Address
    .INPUTS
        System.String -> IpAddr
    .OUTPUTS
        PSCustomObject representing the report results.
    .EXAMPLE
        PS C:\> Get-VtIPReport -Credential $token -IpAddr "13.249.122.117"
        ---
        undetected_urls                  : {http://www.sozcu.com.tr/?gclid=EAIaIQobChMI0aHE_b-Z5gIVxo2yCh0_oQ4kEAAYASAAEgLFHfD_BwE 
                                           68ca8f8906554731273cbfd49e659258f2ce88793601c4159daaa1806a6f467b 0 72 2019-12-10 10:43:44, 
                                           https://www.aldi.es/content/dam/aldi/spain/magazine/aldi-folleto-juguetes-navidad-2019-peninsula/html5.html 
                                           ad0e7269a12b128e73d00dc10e722f95012e74a6167f1a8c9ccb90dc3a08d68b 0 72 2019-12-09 10:56:25, 
                                           https://manipal.edu/mu/lp/manipal-admissions-generic.html?utm_source=bing 
                                           a375386db192781bb0f028c5254967143f6e2bc092b805752bb6d0535f9a0fc4 0 71 2019-11-11 03:49:57, 
                                           https://admission.universityofcalifornia.edu/counselors/transfer/advising/igetc/ 
                                           6f832a74146b8bd277cfc08c3f8d62812054642239018c0d731416633636cbf5 0 71 2019-11-10 05:29:41...}
        undetected_downloaded_samples    : {@{date=2019-11-04 05:53:16; positives=0; total=71; 
                                           sha256=f249b63cb2fcb66b47e86f906c98f8fd912e82dd035b4e53d7e72fc1960cfd16}}
        whois                            : NetRange: 13.248.0.0 - 13.251.255.255
                                           CIDR: 13.248.0.0/14
                                           NetName: AT-88-Z
                                           NetHandle: NET-13-248-0-0-1
                                           Parent: NET13 (NET-13-0-0-0-0)
                                           NetType: Direct Allocation
                                           OriginAS: 
                                           Organization: Amazon Technologies Inc. (AT-88-Z)
                                           RegDate: 2016-08-09
                                           Updated: 2016-08-09
                                           Ref: https://rdap.arin.net/registry/ip/13.248.0.0
                                           OrgName: Amazon Technologies Inc.
                                           OrgId: AT-88-Z
                                           Address: 410 Terry Ave N.
                                           City: Seattle
                                           StateProv: WA
                                           PostalCode: 98109
                                           Country: US
                                           RegDate: 2011-12-08
                                           Updated: 2019-07-25
                                           Comment: All abuse reports MUST include:
                                           Comment: * src IP
                                           Comment: * dest IP (your IP)
                                           Comment: * dest port
                                           Comment: * Accurate date/timestamp and timezone of activity
                                           Comment: * Intensity/frequency (short log extracts)
                                           Comment: * Your contact details (phone and email) Without these we will be unable to identify the correct owner of the IP 
                                           address at that point in time.
                                           Ref: https://rdap.arin.net/registry/entity/AT-88-Z
                                           OrgRoutingHandle: IPROU3-ARIN
                                           OrgRoutingName: IP Routing
                                           OrgRoutingPhone: +1-206-266-4064 
                                           OrgRoutingEmail: aws-routing-poc@amazon.com
                                           OrgRoutingRef: https://rdap.arin.net/registry/entity/IPROU3-ARIN
                                           OrgAbuseHandle: AEA8-ARIN
                                           OrgAbuseName: Amazon EC2 Abuse
                                           OrgAbusePhone: +1-206-266-4064 
                                           OrgAbuseEmail: abuse@amazonaws.com
                                           OrgAbuseRef: https://rdap.arin.net/registry/entity/AEA8-ARIN
                                           OrgNOCHandle: AANO1-ARIN
                                           OrgNOCName: Amazon AWS Network Operations
                                           OrgNOCPhone: +1-206-266-4064 
                                           OrgNOCEmail: amzn-noc-contact@amazon.com
                                           OrgNOCRef: https://rdap.arin.net/registry/entity/AANO1-ARIN
                                           OrgTechHandle: ANO24-ARIN
                                           OrgTechName: Amazon EC2 Network Operations
                                           OrgTechPhone: +1-206-266-4064 
                                           OrgTechEmail: amzn-noc-contact@amazon.com
                                           OrgTechRef: https://rdap.arin.net/registry/entity/ANO24-ARIN
                                   
        whois_timestamp                  : 1575837022
        country                          : US
        response_code                    : 1
        detected_urls                    : {}
        verbose_msg                      : IP address in dataset
        detected_downloaded_samples      : {}
        resolutions                      : {@{last_resolved=2019-06-08 18:39:08; hostname=007s.jp}, @{last_resolved=2019-09-27 18:49:32; hostname=01to82.com}, 
                                           @{last_resolved=2019-06-08 18:44:32; hostname=09012018.com}, @{last_resolved=2019-06-08 12:50:47; 
                                           hostname=0xdeadbeef.us}...}
        detected_communicating_samples   : {@{date=2019-11-11 17:29:59; positives=1; total=67; 
                                           sha256=9b0fa7cce3dd92cb1c7e47d26750beb5e7a18514c59b777498348bca3e93aa2e}, @{date=2019-10-16 11:26:13; positives=1; 
                                           total=72; sha256=4298b17c1c4065422527abb590ed45917c1578558b7cd52a154926c98e8b807b}, @{date=2019-08-12 14:25:42; 
                                           positives=3; total=67; sha256=e72f5dadd701bd9a224b5a604839724934e6ca1a390adb2222c3bf04e45acdc7}, @{date=2019-02-28 
                                           01:18:43; positives=24; total=66; sha256=31c82dd5887f325b83ead4de2b5699f07398b4051e5575d67e825d16f29e4207}}
        undetected_communicating_samples : {@{date=2019-12-10 12:23:19; positives=0; total=73; 
                                           sha256=9d3093460a2fbf402c1984efd0dba5c51ac66dfac94d3875c998b6630bc2c4ef}, @{date=2019-10-24 22:10:52; positives=0; 
                                           total=71; sha256=eb96d3e2d78a61d5f69c01ca4b99f6c29962bb3bfb8686f2e7e3d1cfbc3d32ee}, @{date=2019-10-10 11:44:43; 
                                           positives=0; total=71; sha256=43e9e6a30f3307b415196ca6ab20a2016bdfb7ca178da579a510d3f0c277af2b}, @{date=2019-10-02 
                                           23:03:40; positives=0; total=72; sha256=87d1547f60b51e43db5e9dfeac2f8d2ae86e760cd6606373734b7086259fe612}...}
        continent                        : NA
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

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 1
        )]
        [string] $IpAddr
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.VirusTotal.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
    }

    Process {
        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "/ip-address/report?apikey=$Token&ip=$IpAddr"
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