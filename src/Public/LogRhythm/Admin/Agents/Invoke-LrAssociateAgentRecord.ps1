using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Invoke-LrAssociateAgentRecord {
    <#
    .SYNOPSIS
        Returns details of all pending Agents that match the specified criteria.
        
        This cmdlet is only available for LogRhythm SIEM's with version 7.5.0 and greater.
    .DESCRIPTION
        Get-LrAgentsPending returns a list of pending Agents, including details.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER OrderBy
        Sorts records by name or Id.
    .PARAMETER Direction
        Sorts records by ascending or descending.

        Valid values: "asc" "desc"
    .PARAMETER Name
        String used to search records by Name.
    .PARAMETER AgentLicenseType
        Filter based by license type.

        Valid values: "None" "SystemMonitorBasic" "SystemMonitor"
    .PARAMETER SearchScope
        Filters by search scope.

        Valid values: "SystemMonitorSearch" "ParentEntitySearch" "GlobalSearch"
    .PARAMETER Entity
        Parameter for specifying the existing LogRhythm Entity for the new Host record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Entity object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Segment Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Version
        The deployment version of the component.

        Version schema: (\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})
    .PARAMETER AgentType
        Filter results by type of agent.

        Valid values: "None" "Windows" "Linux" "Solaris" "Aix" "Hpux" "All"
    .PARAMETER LoadBalanced
        Filters results by load balanced status of component.

        Valid values: true, false
    .PARAMETER RecordStatus
        Filter records by object Record Status.

        Valid values: "all" "active" "retired"
    .PARAMETER FetchAIERecords
        Filters results by whether AIE records should be fetched.

        Valud values: true, false
    .PARAMETER Exact,
        Switch used to specify Name is explicit.
    .INPUTS

    .OUTPUTS
        PSCustomObject representing Accepted Agents and their contents.
    .EXAMPLE
        PS C:\> Get-LrAgentsPending
        ----
        
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $Id,


        [Parameter(Mandatory = $false, Position = 14)]
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
        
        # Integer reference
        [int32] $_int = 0
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7.[0-4].\d') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.5.0 and greater."

            return $ErrorObject
        }


        # Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/agents/$Id/"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        return $Response
    }

    End {
    }
}