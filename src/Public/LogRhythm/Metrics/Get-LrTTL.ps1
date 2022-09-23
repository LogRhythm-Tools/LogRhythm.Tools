using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Get-LrTTL {
    <#
    .SYNOPSIS
        Retrieve a cluster-wide Time To Live detail indicating how many days are avaialble in a DX Cluster.
    .DESCRIPTION
        Get-LrEntities returns a full LogRhythm Entity object, including it's details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Cluster
        String representing the cluster name for which TTL details are required.
    .OUTPUTS
        PSCustomObject representing LogRhythm Entity objects and their contents.
    .EXAMPLE
        PS C:\> Get-LrTTL
        ----
        responseMessage : Success
        statusMessage   : Success
        statusCode      : 200
        grandTotal      : 136
        data            : {@{cluster=logrhythm; total=136; indicesInfo=}}

    .EXAMPLE
        PS C:\> Get-LrTTL -cluster 'Bob'
        ----
        responseMessage : No data found for the provided cluster name
        statusMessage   : Success
        statusCode      : 200
        grandTotal      : 0
        data            : 
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $Cluster,


        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Header
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

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
            Value                 =   $Id
            Raw                   =   $null
        }

        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7\.[0-9]\.\d+') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.10.0 and greater."
            return $ErrorObject
        }

        #region: Process Query Parameters
        $QueryParams = [Dictionary[string,string]]::new()

        # Filter by Cluster name
        if ($Cluster) {
            $QueryParams.Add("cluster", $Cluster)
        }

        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }
        #endregion

        # Define Search URL
        $RequestUrl = $BaseUrl + "/lr-metrics-api/ttl/" + $QueryString
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        return $Response
    }

    End {
     }
}