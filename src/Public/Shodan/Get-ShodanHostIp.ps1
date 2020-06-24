<#
    .SYNOPSIS
        Submit a single or array of IPv4 addresse for IP address resolution.
    .DESCRIPTION
        Translates IP Addresses to hostnames.
    .PARAMETER ShodanAPI
        Shodan API Key
    .PARAMETER IPAddresses
        An array of IPv4 Addresses for reverse DNS lookup through Shodan.io.
    .PARAMETER ValuesOnly
        Switch to force output to return values only for hostname lookup.
    .OUTPUTS
        PSObject representing the object lookup.  
    .EXAMPLE
        PS C:\> Get-ShodanIPRes -IPAddresses 104.198.228.124
        ----
        region_code   : VA
        tags          : {cloud, database}
        ip            : 1757865084
        area_code     :
        domains       : {googleusercontent.com}
        hostnames     : {124.228.198.104.bc.googleusercontent.com}
        postal_code   :
        dma_code      :
        country_code  : US
        org           : Google Cloud
        data          : {@{product=nginx; hash=-505180571; tags=System.Object[]; ip=1757865084; org=Google Cloud; isp=Google Cloud; transport=tcp; cpe=System.Object[];
                        data=HTTP/1.1 404 Not Found
                        Server: nginx
                        Date: Thu, 09 Apr 2020 12:15:21 GMT
                        Content-Type: text/html
                        Content-Length: 5891
                        Connection: keep-alive
                        Keep-Alive: timeout=20
                        Vary: Accept-Encoding
                        Vary: Accept-Encoding
                        ETag: "5e714728-1703"

                        ; asn=AS15169; port=443; ssl=; hostnames=System.Object[]; location=; timestamp=4/9/2020 12:15:21 PM; domains=System.Object[]; http=; os=; _shodan=; opts=;   
                        ip_str=104.198.228.124}, @{product=nginx; hash=1575385205; tags=System.Object[]; ip=1757865084; org=Google Cloud; isp=Google Cloud; transport=tcp;
                        cpe=System.Object[]; data=HTTP/1.1 404 Not Found
                        Server: nginx
                        Date: Wed, 08 Apr 2020 02:57:17 GMT
                        Content-Type: text/html
                        Content-Length: 5891
                        Connection: keep-alive
                        Keep-Alive: timeout=20
                        Vary: Accept-Encoding
                        ETag: "5e714728-1703"

                        ; asn=AS15169; port=80; hostnames=System.Object[]; location=; timestamp=4/8/2020 2:57:18 AM; domains=System.Object[]; http=; os=; _shodan=; opts=;
                        ip_str=104.198.228.124}, @{info=protocol 2.0; hash=1240533130; tags=System.Object[]; ip=1757865084; org=Google Cloud; isp=Google Cloud; transport=tcp;       
                        data=SSH-2.0-mod_sftp/0.9.9
                        Key type: ssh-rsa
                        Key: AAAAB3NzaC1yc2EAAAADAQABAAABAQDA+6Q0KnKePyIrYJyfzf9saqPf5L8UFl1rZirVwKRYVnT0
                        eDs41QfWo6ubPtTRXgS/r7+TuaMgO9XGFx208TX21DCxTQWRuFHJ7s3lPYhSAWeAqad9G56+xbUj
                        wu4Yg26/DBucVwb59JT4uGUWU2gBc+sdT6UNVL/ckX9/b9m+sNTlrUInT5ELUAFxbxcXCq+W9aNA
                        AZztoCt7eK8AFlqFX1m8lVzXeWjGIHlQXgjfBrRRAU1oi9B2ZMVbKzG9imwjIuCqnNe+vtp6TCrE
                        kCbp6B7ENXNOIwM6eQ+3bqNRlKpAfxioQep43qLl/xfVpweJOYDn7ngk3Bqh4LplNr51
                        Fingerprint: 83:bb:68:28:df:c2:21:f6:65:01:95:95:4a:f2:de:63

                        Kex Algorithms:
                                ecdh-sha2-nistp256
                                ecdh-sha2-nistp384
                                ecdh-sha2-nistp521
                                diffie-hellman-group-exchange-sha256
                                diffie-hellman-group-exchange-sha1
                                diffie-hellman-group14-sha1
                                diffie-hellman-group1-sha1
                                rsa1024-sha1

                        Server Host Key Algorithms:
                                ssh-rsa

                        Encryption Algorithms:
                                aes128-ctr
                                aes192-ctr
                                aes256-ctr

                        MAC Algorithms:
                                hmac-sha2-256
                                hmac-sha2-512

                        Compression Algorithms:
                                zlib@openssh.com
                                zlib
                                none

                        ; asn=AS15169; port=2222; hostnames=System.Object[]; ssh=; timestamp=4/6/2020 7:21:10 AM; domains=System.Object[]; ip_str=104.198.228.124; os=; _shodan=;    
                        opts=; location=}, @{product=MySQL; hostnames=System.Object[]; hash=1363683603; tags=System.Object[]; ip=1757865084; isp=Google Cloud; transport=tcp;        
                        cpe=System.Object[]; data=5.7.28-31-log; asn=AS15169; port=3306; version=5.7.28-31-log; location=; timestamp=3/25/2020 12:01:13 PM;
                        domains=System.Object[]; org=Google Cloud; os=; _shodan=; opts=; ip_str=104.198.228.124}…}
        asn           : AS15169
        city          :
        latitude      : 38.6582
        isp           : Google Cloud
        longitude     : -77.2497
        last_update   : 4/9/2020 12:15:21 PM
        country_code3 : USA
        vulns         : {CVE-2018-15919, CVE-2017-15906}
        country_name  : United States
        ip_str        : 104.198.228.124
        os            :
        ports         : {80, 3306, 443, 22…}
    .NOTES
        Shodan-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-ShodanHostIp {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)]
        [string]$IPAddress,

        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=2)]
        [switch]$ValuesOnly
    )
    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.Shodan.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        $RequestUrl = $BaseUrl + "/shodan/host/"+$IPAddress+"?key="+$Token
    }

    Process {
        # Query DNS and obtain domain IP address
        try {
            $shodanDNSResults = Invoke-RestMethod $RequestUrl
        } catch {
            Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
        }
    }

    End {
        return $shodanDNSResults
    }
}