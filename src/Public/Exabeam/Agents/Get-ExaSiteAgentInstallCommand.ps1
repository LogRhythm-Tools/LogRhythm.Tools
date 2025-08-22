using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-ExaSiteAgentInstallCommand {
    <#
    .SYNOPSIS
        Get a Site Collector agent installation command.
    .DESCRIPTION
        Install command to install the Site Collector agent. The command is encoded in base64, necessitating a decoding step. 
        This encoding ensures the command's integrity during transmission, maintaining its format and preventing alterations. 
        
        For example, after you receive the response, you can decode the string using the command 
        base64 -d <<< "c3Vkb...............".

        After decoding the command from base64 to its original string format, you'll have the necessary shell commands to 
        install the Site Collector agent. The install command varies depending on the type of Site Collector agent as 
        defined in the Site Collector template. The command sequence downloads and runs a script to configure the agent 
        and passes in parameters (deploymentHosts, templateIds, and optionally fetchStartDate and fetchHistoricalData) that 
        affect how the script configures the Site Collector agent.
    .PARAMETER Type
        Type of Site Collector agent for which the template applies.
    .PARAMETER DeploymentHosts
        Hostname or IP address of the Site Collector Core for which you want to install the agent.
    .PARAMETER StartLogDate
        (Windows collectors only) The date after which you want the Site Collector agent to receive logs (ISO-8601 format).
    .PARAMETER FetchHistoricalData
        (FileWindows and FileLinux only) This flag is only applicable for Core version 2.3.0 or higher. 
        For Core versions lower than 2.3.0, this flag will always be set to true.
    .PARAMETER TemplateIDs
        You can assign multiple Template IDs to any collector.
    .PARAMETER Uninstall
        This changes the API call to the commands/uninstallation endpoint.

        Provide parameters: type, deploymentHosts.
    .PARAMETER Exact
        Switch to force PARAMETER Name to be matched explicitly.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        The Name parameter can be provided via the PowerShell pipeline.
    .OUTPUTS
        Base64 representing the install/uninstall command.
    .NOTES
        Exabeam-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet(
            'ArchiveLinux',
            'ArchiveWindows', 
            'FileLinux',
            'FileWindows',
            'Windows',
            ignorecase=$true
        )]
        [string] $Type,
        

        [Parameter(Mandatory = $true, Position = 1)]
        [string] $DeploymentHosts,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $Exact,

        
        [Parameter(Mandatory = $false, Position = 3)]
        [datetime] $StartLogDate,


        [Parameter(Mandatory = $false, Position = 4)]
        [bool] $FetchHistoricalData = $true,

        [Parameter(Mandatory = $true, Position = 5)]
        [string] $TemplateIDs,

        [Parameter(Mandatory = $false, Position = 6)]
        [switch] $Uninstall,

        [Parameter(Mandatory = $false, Position = 7)]
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
        $Headers.Add("content-type", "application/json")
        $Headers.Add("accept", "application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post
        
        # Define HTTP URI
        if ($Uninstall) {
            $RequestUrl = $BaseUrl + "site-collectors/v1/collectors/commands/uninstallation"
        } else {
            $RequestUrl = $BaseUrl + "site-collectors/v1/collectors/commands/installation"
        }
        

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        $Body = [PSCustomObject]@{
            type = $Type
            fetchHistoricalData = $FetchHistoricalData
            templateIds = @($TemplateIDs)
            startLogDate = $StartLogDate
            deploymentHosts = @($DeploymentHosts)
        } | ConvertTo-Json

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Body $Body -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        return $Response
    }

    End { }
}