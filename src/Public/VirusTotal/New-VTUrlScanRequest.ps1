using namespace System
using namespace System.Collections.Generic

Function New-VTUrlScanRequest {
    <#
    .SYNOPSIS
        Instantiate a new VirusTotal Url scan request.
    .DESCRIPTION
        This VirusTotal cmdlet posts a request for analysis from the Virus Total service.
        
        A successful request should be followed up with a Get-VTUrlReport after the scan has been completed.
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
        PS C:\> New-VTUrlScanRequest -Url https://github.com/Jt3kt/PIE/blob/3.1/Scripts/PIE_Message-Trace-Logging/Invoke-O365Trace.ps1
        ---
        permalink     : https://www.virustotal.com/gui/url/a5d73f6bc22f4db749bf25690c56af6a93bf4b0f68e4e75d9c2d707799235ff7/detection/u-a5d73f6bc22f4db749bf25690c56af6a93bf4b0f68e4e75d9c2d707799235 
                        ff7-1606787371
        resource      : https://github.com/Jt3kt/PIE/blob/3.1/Scripts/PIE_Message-Trace-Logging/Invoke-O365Trace.ps1
        url           : https://github.com/Jt3kt/PIE/blob/3.1/Scripts/PIE_Message-Trace-Logging/Invoke-O365Trace.ps1
        response_code : 1
        scan_date     : 2020-12-01 01:49:31
        scan_id       : a5d73f6bc22f4db749bf25690c56af6a93bf4b0f68e4e75d9c2d707799235ff7-1606787371
        verbose_msg   : Scan request successfully queued, come back later for the report
    .NOTES
        VirusTotal-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Url,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.VirusTotal.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.VirusTotal.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Url                   =   $Url
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
        }

        # Request URI   
        $Method = $HttpMethod.Post
        $RequestUrl = $BaseUrl + "/url/scan"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"
        $Body = @{ url = $Url; apikey = $Token}
        Write-Verbose "[$Me]: RequestBody: $Body"
        

        Try {
            $vtResponse = Invoke-RestMethod $RequestUrl -Method $Method -Body $Body
        }
        catch {
            return $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            return $ErrorObject
        }

        Return $vtResponse
    }
 

    End {}
}