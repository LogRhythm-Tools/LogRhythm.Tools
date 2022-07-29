using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCaseLogsIndex {
    <#
    .SYNOPSIS
        Return a list log indexes associated with a specific LogRhythm Case.
    .PARAMETER Id
        The Id of the case for which to retrieve Case Log Indexes from.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        System.String -> [Name] Parameter
    .OUTPUTS
        System.Object[] representing the returned LogRhythm playbooks.
        Returns $null if no playbooks are found based on Name filter.
    .EXAMPLE 
        PS C:\> Get-LrCaseLogsIndex -Id 61         
        ---

        indexId       : FD2B3393-39FE-43FD-8FA6-F56CE4C5F901
        state         : ready
        message       : log evidence is available
        dateCreated   : 2021-01-30T15:09:17.1648851Z
        dateUpdated   : 2021-01-30T15:22:56.5175241Z
        dateRebuilt   :
        lastUpdatedBy : @{number=-100; name=LogRhythm Administrator; disabled=False}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
        
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        

        # Request Method
        $Method = $HttpMethod.Get
    }


    Process {
        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$Id/logs-index/"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Submit request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        return $Response
    }

    End { }
}