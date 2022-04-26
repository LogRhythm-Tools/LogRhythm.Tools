using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace System.Security.Authentication

Function Get-LrtAtpAlerts {
    <#
    .SYNOPSIS
        Collect Microsoft Defender ATP detections using SIEM REST API.
    .DESCRIPTION
        The Get-ATPAlerts command utilizes the SIEM REST API to collect
        alert detections created since the previous invocation.

        ** ABOUT DATES **
        Get-LrtAtpAlerts uses the current culture and local time zone of
        the system on which it is run. To check the local time zone for,
        use the following command: 
        
        > [System.TimeZoneInfo]::Local

        If you'd like to explicitly use UTC instead of local time, include the 
        [UTC] switch in the command's parameters.
    .PARAMETER Region
        Specifies the two character region for your Azure subscription. By
        default, the value stored in $LrtConfig.DefenderATP.Region is used,
        so this parameter is optional.

        Accepted values: US, UK, EU
    .PARAMETER CreatedAfter
        ** NOTE ** The local time zone is used for all dates. See DESCRIPTION for
        additional information.

        Defines the lower time bound alerts from which alerts are retrieved, based
        on field [LastProcessedTime].
        
        The time range will be: [CreatedAfter] to [DateTime]::Now

        When not specified, all alerts generated in the last two hours are retrieved.
    .PARAMETER CreatedBefore
        ** NOTE ** The local time zone is used for all dates. See DESCRIPTION for
        additional information.
        
        Defines the upper time bound alerts are retrieved.
        The time range will be: from [CreatedAfter] time to [CreatedBefore] time.
        
        When not specified, the default value will be the current time.
    .PARAMETER Ago
        Pulls alerts in the following time range: ([DateTime]::Now - [Ago]) to [DateTime]:Now

        Value should be set according to ISO 8601 duration format
        E.g. ago=PT10M will pull alerts received in the last 10 minutes.
    .PARAMETER Limit
        Defines the number of alerts to be retrieved. Most recent alerts will be retrieved
        based on the number defined.

        When not specified, all alerts available in the time range will be retrieved.
    .PARAMETER MachineGroups
        Specifies device groups to pull alerts from.
        When not specified, alerts from all device groups will be retrieved.
    .PARAMETER DeviceCreatedMachineTags
        Single device tag from the registry.
    .PARAMETER CloudCreatedMachineTags
        Device tags that were created in Microsoft Defender Security Center.
    .INPUTS
        
    .OUTPUTS
        A collection (array) of Defender ATP alerts. For more information on
        the API fields and portal mapping, see:
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/api-portal-mapping
    .EXAMPLE
        PS > Get-ATPAlerts -
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("US","UK","EU")]
        [string] $Region = $LrtConfig.DefenderATP.Region,


        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNull()]
        [datetime] $CreatedAfter,


        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNull()]
        [datetime] $CreatedBefore,


        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [string] $Ago,


        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateRange(1,1000)]
        [int] $Limit,


        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [string] $MachineGroups,


        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [string] $DeviceCreatedMachineTags,


        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [string] $CloudCreatedMachineTags
    )


    #region: Setup                                                                                 
    # For info/error reporting w/ cmdlet name
    $Me = $MyInvocation.MyCommand.Name


    # Enable self-signed certificates and Tls1.2
    Enable-TrustAllCertsPolicy


    # Get a new token, if needed
    Set-LrtAzToken -ResourceName "DefenderATP"
    $ApiToken = $LrtConfig.DefenderATP.Token.access_token
    if ([string]::IsNullOrEmpty($ApiToken)) {
        throw [Exception] "[$Me]: Unable to retrieve a token from LrtConfig."
    }


    # RequestUri for configured region
    Write-Verbose "Region: $Region"
    $BaseRequestUri = $LrtConfig.DefenderATP.BaseRequestUri.$Region
    

    # Get OAuth2Url
    $OAuthUri = $LrtConfig.DefenderATP.OAuth2Url
    Write-Verbose "RequestUri: $BaseRequestUri"
    Write-Verbose "OAuthUri: $OAuthUri"
    #endregion



    #region: Format / Validate Parameters                                                          
    # Dictionary to contain requested query parameters
    $QueryParams = [Dictionary[string,string]]::new()


    # [CreatedAfter] - Format ISO 8601
    if ($CreatedAfter) {
        $QueryParams.Add('sinceTimeUtc', $CreatedAfter.ToString('o'))
    }
    

    # [CreatedBefore] - Format ISO 8601
    if ($CreatedBefore) {
        $QueryParams.Add('untilTimeUtc', $CreatedBefore.ToString('o'))
    }


    # [Ago] Regex from: https://stackoverflow.com/questions/32044846/regex-for-iso-8601-durations
    $RegexAgo = [regex]::new("^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?$")
    if ($Ago) {
        # Error if not valid ISO 8601 Duration
        if (! ($RegexAgo.Match($Ago))) {
            $Err = "Parameter 'Ago' does not match ISO 8601 duration format. "
            $Err += "For examples, see: https://en.wikipedia.org/wiki/ISO_8601#Durations"
            throw [ArgumentException] $Err
        }

        # Add to param dictionary
        $QueryParams.Add('ago', $Ago)
    }


    # [Limit]
    if ($Limit) {
        $QueryParams.Add('limit', $Limit)
    }


    # [MachineGroups]
    if ($MachineGroups) {
        $QueryParams.Add('machinegroups', $MachineGroups)
    }


    # [DeviceCreatedMachineTags]
    if ($DeviceCreatedMachineTags) {
        $QueryParams.Add('DeviceCreatedMachineTags', $DeviceCreatedMachineTags)
    }


    # [CloudCreatedMachineTags]
    if ($CloudCreatedMachineTags) {
        $QueryParams.Add('CloudCreatedMachineTags', $CloudCreatedMachineTags)
    }


    # Build QueryString
    if ($QueryParams.Count -gt 0) {
        $QueryString = $QueryParams | ConvertTo-QueryString
        Write-Verbose "[$Me]: QueryString is [$QueryString]"
    }
    #endregion
    


    #region: Send Request                                                                          
    # Request Headers
    $Headers = [Dictionary[string,string]]::new()
    $Headers.Add("Authorization", "Bearer $ApiToken")
    
    # Request URI
    $Method = $HttpMethod.Get
    $RequestUri = $BaseRequestUri + $QueryString


    # REQUEST
    try {
        $Response = Invoke-RestMethod -Uri $RequestUri -Headers $Headers -Method $Method
        Write-Verbose "Alert Count: $($Response.Count)"
    }
    catch {
        $Err = Get-RestErrorMessage $_
        throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
    }
    
    return $Response
    #endregion
}