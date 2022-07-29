using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrAgentPendingDetails {
    <#
    .SYNOPSIS
        Retrieve the details from a LogRhythm System Monitor agent that is currently pending.
    .DESCRIPTION
        Get-LrAgentPendingDetails returns the details of the specified Agent.
    .PARAMETER Guid
        [System.String] (Name or Guid)
        Specifies a LogRhythm system monitor agent object by providing one of the following property values:
          + Name (as System.String), e.g. "SMA"
          + Guid (as System.String), e.g. c4a8a6a7-1c23-435e-b3a3-8c6342156e23

        Can be passed as ValueFromPipeline but does not support Arrays.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .OUTPUTS
        PSCustomObject representing LogRhythm Agent record and its contents.
    .EXAMPLE
        PS C:\> Get-LrAgentPendingDetails -Id c4a8a6a7-1c23-435e-b3a3-8c6342156e23
        ----
        
    .EXAMPLE 
        Get-LrAgentDetails -Guid "SMA"
        ---
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Guid,


        [Parameter(Mandatory = $false, Position = 1)]
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
        $Method = $HttpMethod.Get

        # Value Testing Paramater
        $_int = 0

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $Guid
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }
        
        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7\.[0-4]\.\d+') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.5.0 and greater."
            return $ErrorObject
        }

        # Check if Guid value is a valid Guid
        if (Test-Guid $Guid) {
            Write-Verbose "[$Me]: Guid parses as valid guid."
        } else {
            Write-Verbose "[$Me]: Guid does not parse as guid.  Performing string lookup."
            $AgentLookup = Get-LrAgentsPending -Name $Guid -Exact
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
        }
        
        $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/" + $Guid + "/"

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