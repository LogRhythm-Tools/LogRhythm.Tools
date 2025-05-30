using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaSiteCollectors {
    <#
    .SYNOPSIS
        Get Site Collector list.
    .DESCRIPTION
        To monitor configuration and management changes, you can retrieve a list of all 
        Site Collector Core IDs with relevant details such as status, version, OS version, 
        hostname, and proxy hostname and port. You can obtain these details for Site 
        Collectors collectively or separately.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        The Name parameter can be provided via the PowerShell pipeline.
    .EXAMPLE
        PS C:\> Get-LrList -Name "LR Threat List : URL : Attack"
        ---
        id                  : 83045d2e-5555-5555-5555-b293be7810e8
        name                : Example
        deploymentHosts     : {host.example.com}
        egressFilter        :
        proxy               :
        status              : RUNNING
        collectorsCount     : 19
        createdDate         : 2024-12-05T16:40:10Z
        modifiedDate        : 2025-05-27T19:48:16Z
        heartbeat           : @{timestamp=2025-05-30T14:56:40Z; caExpirationDate=2048949684; certExpirationDate=1796488885}
        metadata            : @{timezoneOffset=-0500; timezoneName=New York City, Brooklyn, Queens, Philadelphia}
        currentVersion      : 2.9.1
        latestVersion       : 2.9.1
        coreVersions        : @{latestVersion=2.9.1; stableVersion=2.8.1}
        latestVersions      : @{msi=2.9.0; windowsFile=2.9.0; linuxFile=2.9.0; windowsArchive=2.9.0; linuxArchive=2.9.0}
        operationSystem     : @{ipAddress=10.1.1.55; name=Red Hat Enterprise Linux; version=9.4 (Plow)}
        systemConfiguration : @{cpu=4; memory=15GB}
        installationPath    : /opt
        extractionPath      : /tmp
        ngscdStatus         : RUNNING
        ngscdHeartbeat      : @{timestamp=1748617083}
    .NOTES
        Exabeam-API     
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
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
        $Headers.Add("accept", "application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Get
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "site-collectors/v1/cores"

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

        if ($Response.paging.next) {
            $Results = [list[object]]::new()
            $Results.add($Response.items)
            $Counter = 0
            DO {
                if ($Counter -eq 0) {
                    $RequestUrl = $Response.paging.next[0] -replace "^http:", "https:"
                } else {
                    $RequestUrl = $PaginationResults.paging.next[0] -replace "^http:", "https:"
                }
                Write-Verbose "[$Me]: Request URL: $RequestUrl"
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if (($null -ne $PaginationResults.Error) -and ($PaginationResults.Error -eq $true)) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Results.add($PaginationResults.items)
                $Counter += 1
            } While ($PaginationResults.paging.next)
            return $Results
        }
        
        if ($Response.items) {
            return $Response.items
        } else {
            return $Response
        }
    }

    End { }
}