using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaContextAttributes {
    <#
    .NOTES
        Exabeam-API 
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateSet('Other','User', 'TI_ips', 'TI_domains',  ignorecase=$true)]
        [string] $contextType,

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Exabeam.ApiKey
    )
                                                                    
    Begin {
        $Me = $MyInvocation.MyCommand.Name
        Set-LrtExaToken
        # Request Setup
        $BaseUrl = $LrtConfig.Exabeam.BaseUrl
        $Token = $LrtConfig.Exabeam.Token.access_token


        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        if ($contextType -like 'user') {
            $Type = 'User'
        }
        if ($contextType -like 'other') {
            $Type = 'Other'
        }
        if ($contextType -like 'ti_ips') {
            $Type = 'TI_ips'
        }
        if ($contextType -like 'ti_domains') {
            $Type = 'TI_domains'
        }
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "context-management/v1/attributes/" + $Type

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
        
        return $Response
    }

    End { }
}