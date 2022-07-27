using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrAgentPending {
    <#
    .SYNOPSIS
        Update an existing Pending Agent entry.
    .DESCRIPTION
        Update-LrAgentPending returns a full LogRhythm Entity object, including details and list items if provided the passthru flag.
    .PARAMETER Guid

    .PARAMETER AcceptanceStatus
        Supply which status for updating a pending agent's status to.

        Valid options: Accept, Associate, or Reject
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        PSCustomObject representing the new LogRhythm Host and its contents.
    .EXAMPLE
        PS C:\> Update-LrAgentPending -Guid 'sma' -AcceptanceStatus 'reject'
        ---
        id                         : 11
        guid                       : c4a8a6a7-1c23-435e-b3a3-8c6342156e23
        name                       : SMA
        acceptanceStatus           : Rejected
        dateUpdated                : 7/22/2022 7:32:26 AM
        entityId                   : 1
        hostName                   : SMA
        resolvedHostId             : 0
        ipAddress                  : 10.43.30.236|192.168.1.3
        clientAddress              : 10.43.30.236
        clientPort                 : 0
        agentType                  : Windows
        version                    : 7.9.0.8001
        os                         : Win32NT
        osVersion                  : Microsoft Windows NT 10.0.17763.0
        osType                     : Server
        capabilities               : None
        agentConfigurationPolicyId : -1
    .EXAMPLE 
        PS C:\> Update-LrAgentPending -Guid 'sma' -AcceptanceStatus delete
        ---
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Guid,


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateSet('accept','associate', 'reject', ignorecase=$true)]
        [string] $AcceptanceStatus,

        [Parameter(Mandatory = $false, Position = 2)]
        [int] $AgentId,
        
        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        
        # Define HTTP Method
        $Method = $HttpMethod.Put

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Guid
            Raw                   =   $null
        }

        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7.[0-8].\d') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.9.0 and greater."

            return $ErrorObject
        }

        # Check if Guid value is a valid Guid
        if (Test-Guid $Guid) {
            Write-Verbose "[$Me]: Guid parses as valid guid."
        } else {
            Write-Verbose "[$Me]: Guid does not parse as guid.  Performing string lookup."
            $AgentLookup = Get-LrAgentsPending -Name $Guid -Exact
            if (!$AgentLookup) {
                $AgentLookup = Get-LrAgentsPending -Name $Guid -Exact -AcceptanceStatus 'rejected'
                if (!$AgentLookup) {
                    $ErrorObject.Error = $true
                    $ErrorObject.Code = 404
                    $ErrorObject.Raw = $Guid
                    $ErrorObject.Type = "Input.Validation.Lookup"
                    $ErrorObject.Note = "Guid String [$Guid] not found in Pending Agents."
                    return $ErrorObject
                } else {
                    $Guid = $AgentLookup.guid
                }
            } else {
                $Guid = $AgentLookup.guid
            }
        }

            
        if ($AcceptanceStatus -like 'reject') {
            # Define Query URL
            $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/" + $Guid + "/reject"
        } elseif ($AcceptanceStatus -like 'associate') {
            if (!$AgentId) {
                $ErrorObject.Error = $true
                $ErrorObject.Code = 404
                $ErrorObject.Raw = $AgentId
                $ErrorObject.Type = "Input.Validation.Lookup"
                $ErrorObject.Note = "Guid String [$AgentId] not found in Accepted Agents."
                return $ErrorObject
            }
            $Body  = [PSCustomObject]@{
                agentId = $AgentId
            } | ConvertTo-Json -Compress
    
            # Request URL
            $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/$Guid/associate"
        } else {
            # Define Query URL
            $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/" + $Guid + "/accept"
        }
        

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        if ($AcceptanceStatus -like "reject") {
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
            if ($Response.Error) {
                return $Response
            }
        } else {
            Write-Verbose "[$Me]: Request Body:`n$Body"
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
            if ($Response.Error) {
                return $Response
            }
        }
        
        if ($PassThru) {
            return $Response
        }
    }

    End { }
}