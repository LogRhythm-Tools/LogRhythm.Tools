using namespace System
using namespace System.Collections.Generic

Function Get-VTHashReport {
    <#
    .SYNOPSIS
        Get VirusTotal Hash Report.
    .DESCRIPTION
        Get VirusTotal Hash cmdlet retrieves summarized AntiVirus analysis results based on a file hash.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.VirusTotal.VtApiToken
        with a valid Api Token.
    .PARAMETER Hash
        MD5, SHA1 or SHA256
    .INPUTS
        System.String -> Hash
    .OUTPUTS
        PSCustomObject representing the report results.
    .EXAMPLE
        PS C:\> Get-VtHashReport -Credential $token -Hash b57d478a0673352579a8a0199d45e21dc1f7cdcc8fbe355daa9580e5e6b49b80
        ---
        scans         : @{Bkav=; MicroWorld-eScan=; CMC=; CAT-QuickHeal=; McAfee=; Cylance=; Zillya=; SUPERAntiSpyware=; Sangfor=; K7AntiVirus=; K7GW=; Arcabit=; 
                        Baidu=; Cyren=; Symantec=; ESET-NOD32=; TrendMicro-HouseCall=; Avast=; ClamAV=; Kaspersky=; BitDefender=; NANO-Antivirus=; ViRobot=; 
                        Tencent=; Ad-Aware=; Sophos=; Comodo=; F-Secure=; DrWeb=; VIPRE=; TrendMicro=; McAfee-GW-Edition=; FireEye=; Emsisoft=; F-Prot=; Jiangmin=; 
                        Avira=; Antiy-AVL=; Kingsoft=; Microsoft=; AegisLab=; ZoneAlarm=; Avast-Mobile=; GData=; TACHYON=; AhnLab-V3=; VBA32=; ALYac=; MAX=; 
                        Malwarebytes=; Zoner=; Rising=; Yandex=; Ikarus=; Fortinet=; BitDefenderTheta=; AVG=; Panda=; Qihoo-360=}
        scan_id       : b57d478a0673352579a8a0199d45e21dc1f7cdcc8fbe355daa9580e5e6b49b80-1576542022
        sha1          : f0c19594b6cbff80ecafcab0cbcbde660bba69c8
        resource      : b57d478a0673352579a8a0199d45e21dc1f7cdcc8fbe355daa9580e5e6b49b80
        response_code : 1
        scan_date     : 2019-12-17 00:20:22
        permalink     : https://www.virustotal.com/file/b57d478a0673352579a8a0199d45e21dc1f7cdcc8fbe355daa9580e5e6b49b80/analysis/1576542022/
        verbose_msg   : Scan finished, information embedded
        total         : 59
        positives     : 26
        sha256        : b57d478a0673352579a8a0199d45e21dc1f7cdcc8fbe355daa9580e5e6b49b80
        md5           : 408bf4a400fa46c705ea54f883f14e55
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
        [string] $Hash
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.VirusTotal.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
    }

    Process {
        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "/file/report?apikey=$Token&resource=$Hash"
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