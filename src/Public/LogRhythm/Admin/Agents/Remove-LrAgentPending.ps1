using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Remove-LrAgentPending {
    <#
    .SYNOPSIS
        Remove an existing Pending Agent entry.
    .DESCRIPTION
        Remove-LrAgentPending returns a full LogRhythm Entity object, including details and list items if provided the passthru flag.
    .PARAMETER Guid

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        This cmdlet produces no output if the operation is successful.
    .EXAMPLE 
        PS C:\> Remove-LrAgentPending -Guid 'sma'
        ---
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Guid,


        [Parameter(Mandatory = $false, Position = 8)]
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
        $Method = $HttpMethod.Delete

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

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/"
        $Body = "[`"$Guid`"]"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }
    }

    End { }
}