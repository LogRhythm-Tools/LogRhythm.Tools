using namespace System
using namespace System.IO
using namespace System.Collections.Generic

function Get-LrThreatIntelligence
{
    <#
    .SYNOPSIS
        Retrieve the associated Threat Providers and Categories from the Threat Intelligence API
    .DESCRIPTION
        Get-LrThreatIntelligence returns information about the Threat Providers and categories the IoC is associated with
    .PARAMETER IoC
        An Indicator of Compromise (IoC) observed in a log.  This could be an IP address, URL, etc
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.String]       -> IoC
        [PSCredential]        -> Credential
    .OUTPUTS
        If successful, return a PSCustomObject in the format:
            "providers" : [{
                "name": "{Provider Name",
                "metadata" : {
                    "name" : "{Metadata name}",
                    "value" : "{Metadata value}"
                }
            }]
        Otherwise, returns $null

    .EXAMPLE
        PS C:\> Get-LrThreatIntelligence -IoC '37.34.58.210'

        id       : ACSC CTIS
        name     : ACSC CTIS
        url      :
        context  :
        feeds    :
        metaData : {@{name=Category; value=Suspicious}}
    .EXAMPLE
        Get-LRThreatIntelligence -IoC '0cl.sldov.ru'

        id       : Open Source
        name     : Open Source
        url      :
        context  :
        feeds    :
        metaData : {@{name=Category; value=Malware}, @{name=Category; value=URL}}
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
	[Parameter(Mandatory = $true, Position = 0)] 
        [string] $IoC,

	[Parameter(Mandatory=$false, Position = 1)] 
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
	)

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.ThreatIntelligenceBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy        
    }

    Process {
        # Search for the IoC
        $Body = [PSCustomObject]@{
            value = $IoC
        } | ConvertTo-Json -Depth 8

        # Define Query URL
        $RequestUrl = $BaseUrl + "/Observables/actions/search"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        if ($Response -and $Response.observables -and $Response.observables.length -gt 0) {
            return $Response.observables.providers
        } else {
            return $null
        }
    }

    End {}
}
