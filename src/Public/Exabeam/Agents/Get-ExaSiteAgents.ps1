using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaSiteAgents {
    <#
    .SYNOPSIS
        Get a list of Site Collector agents.
    .DESCRIPTION
        To monitor configuration and management changes, you can retrieve a list of all Site Collector 
        agents with relevant details such as status. You can obtain these details for Site Collector 
        agents collectively or separately. Results are paginated.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        The Name parameter can be provided via the PowerShell pipeline.
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List and its contents.

        If parameter ListItemsOnly is specified, a string collection is returned containing the
        list's item values.
    .EXAMPLE
        PS C:\> Get-ExaSiteAgents
        ---
        id            : 82a96a97-90f8-4b32-8734-039edf7d54e6
        name          : Example
        type          : Ldap
        status        : RUNNING
        statusMessage : Collector hasn't been receiving heartbeats more than 10 minutes
        settings      : @{primaryHost=examplehost.example.com; secondaryHosts=System.Object[]; port=636; ssl=True; globalCatalog=False; baseDn=DC=example, DC=com; bindDn=exacct; pullFullContext=False; pollingInterval=3600}
        coreId        : e6696714-5555-5555-5555-6f68c675b2ea
        coreName      : Example Prod1
        heartbeat     : @{timestamp=2025-05-30T14:49:47Z}
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

        # Define HTTP Method
        $Method = $HttpMethod.Get
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "site-collectors/v1/collectors"

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
            ForEach($Item in $Response.items) {
                $Results.add($Item)
            }
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
                ForEach ($Item in $PaginationResults.items) {
                    $Results.add($Item)
                }
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