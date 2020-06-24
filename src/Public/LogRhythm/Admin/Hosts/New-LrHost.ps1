using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrHost {
    <#
    .SYNOPSIS
        Create a new Host entry for the LogRhythm Entity structure.
    .DESCRIPTION
        New-LrHost returns a full LogRhythm Host object, including details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Entity
        Parameter for specifying the existing LogRhythm Entity for the new Host record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Entity object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Segment Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Name
        [System.String] Parameter for specifying a new host name.  
        
        Max length: 50 characters
    .PARAMETER ShortDescription
        A brief description of the host entity.

        Max length: 255 characters
    .PARAMETER LongDescription
        An extended description of the host entity.

        Max length: 2000 characters
    .PARAMETER RiskLevel
        Designated host Risk Level.

        Valid entries: "None" "Low-Low" "Low-Medium" "Low-High" "Medium-Low" "Medium-Medium" "Medium-High" "High-Low" "High-Medium" "High-High"
    .PARAMETER ThreatLevel
        Designated host Threat Level.

        Valid entries: "None" "Low-Low" "Low-Medium" "Low-High" "Medium-Low" "Medium-Medium" "Medium-High" "High-Low" "High-Medium" "High-High"
    .PARAMETER ThreatLevelComment
        Provide context to ThreatLevel score associted with Host Record.

    .PARAMETER RecordStatus
        String used to restrict results based on RecordStatus.
        Valid entries: "Active", "Retired"
    .PARAMETER HostZone
        Set host zone.  
        
        Valid entries: "Internal", "DMZ", "External"
    .PARAMETER Location
        Set the network's geographic location.

        This parameter will be enhanced with location lookup verification with LogRhythm 7.5 API.
    .PARAMETER OS
        Specify the OS type.

        Valid entries: "Unknown" "Other" "WindowsNT4" "Windows2000Professional" "Windows2000Server" "Windows2003Standard" "Windows2003Enterprise"
        "Windows95" "WindowsXP" "WindowsVista" "Linux" "Solaris" "AIX" "HPUX" "Windows"

    .PARAMETER OSVersion
        String description of the OS Version.

        Max length: 100 characters
    .PARAMETER UseEventLogCredentials
        Boolean expression that defines log collection.

        Default value is False for API use.
    .PARAMETER OSType
        String description for OS Type.

        Valid entries: "Server" "Desktop" "None"
    .OUTPUTS
        PSCustomObject representing the new LogRhythm Host and its contents.
    .EXAMPLE
        PS C:\> New-LrHost -Entity "Primary Site" -Name "Mynewhost" -ShortDesc "This is the short desc." -LongDesc "This is the killer long description for this host." -Zone "internal" -OS "Windows" -OSVersion "2008r2" -OSType "Server" -Verbose
        ---
        id                     : 3
        entity                 : @{id=1; name=Primary Site}
        name                   : Mynewhost
        shortDesc              : This is the short desc.
        longDesc               : This is the killer long description for this host.
        riskLevel              : None
        threatLevel            : None
        threatLevelComments    :
        recordStatusName       : Active
        hostZone               : Internal
        location               : @{id=-1}
        os                     : Windows
        osVersion              : 2008r2
        useEventlogCredentials : False
        osType                 : Server
        dateUpdated            : 6/18/2020 6:00:35 PM
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, Position = 1)]
        [string]$Entity,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, Position = 2)]
        [string]$Name,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true,  Position = 3)]
        [string]$ShortDesc,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 4)]
        [string]$LongDesc,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 5)]
        [ValidateSet('none','low-low','low-medium','low-high','medium-low','medium-medium','medium-high','high-low','high-medium','high-high', ignorecase=$true)]
        [string]$RiskLevel = "none",

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 6)]
        [ValidateSet('none','low-low','low-medium','low-high','medium-low','medium-medium','medium-high','high-low','high-medium','high-high', ignorecase=$true)]
        [string]$ThreatLevel = "none",

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 7)]
        [string]$ThreatLevelComment,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 8)]
        [ValidateSet('new', 'retired','active', ignorecase=$true)]
        [string]$RecordStatus = "new",

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 9)]
        [ValidateSet('unknown', 'internal','dmz','external', ignorecase=$true)]
        [string]$Zone="internal",

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 10)]
        [string]$Location,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 11)]
        [ValidateSet('unknown', 'other', 'windowsNT4', 'windows2000professional', 'windows2000server', 'windows2003standard', 'windows2003enterprise', `
         'windows95' ,'windowsxp' ,'windowsvista', 'linux', 'solaris', 'aix', 'hpux', 'windows', ignorecase=$true)]
        [string]$OS,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 12)]
        [string]$OSVersion,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 12)]
        [bool]$UseEventlogCredentials = $false,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 12)]
        [ValidateSet('server','none','desktop', ignorecase=$true)]
        [string]$OSType = "server"
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LRDeployment.Version
        
        # Integer Reference
        [int32]$_int = 1
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Name
        }

        # Lookup Entity By ID or Name
        if ($Entity) {
            if ([int]::TryParse($Entity, [ref]$_int)) {
                Write-Verbose "[$Me]: Entity parses as integer."
                $_entity = Get-LrEntityDetails -Id $Entity
            } else {
                Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                $EntityLookup = Get-LrEntities -Name $Entity -Exact
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    return $ErrorObject
                } else {
                    $_entity = $EntityLookup
                }
            }
        } else {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "Error"
            $ErrorObject.Code = 404
            $ErrorObject.Note = "Value for Entity (Name or ID) must be submitted.  To review entities run: get-lrentities"
            return $ErrorObject
        }
        Write-Verbose "Entity: $_entity"

        # TODO Location Lookup.  7.5 API

        # Ensure proper syntax
        if ($RecordStatus) {
            $ValidStatus = "new", "retired", "active"
            if ($ValidStatus.Contains($($RecordStatus.ToLower()))) {
                # Update RecordStatus for 7.5 API
                if ($LrVersion -ge 7.5.0) {
                    if ($RecordStatus -eq "new") {
                        $RecordStatus = "active"
                    }
                }
                $_recordStatus = (Get-Culture).TextInfo.ToTitleCase($RecordStatus)
            } else {
                throw [ArgumentException] "RecordStatus [$RecordStatus] must be: all, active, or retired."
            }
        }

        # Ensure proper syntax
        if ($RiskLevel) {
            $ValidStatus = @("none", "low-low", "low-medium", "low-high", "medium-low", "medium-medium", "medium-high", "high-low", "high-medium", "high-high")
            if ($ValidStatus.Contains($($RiskLevel.ToLower()))) {
                $_riskLevel = (Get-Culture).TextInfo.ToTitleCase($RiskLevel)
            } else {
                throw [ArgumentException] "RiskLevel [$RiskLevel] must be: none, low-low, low-medium, low-high, medium-low, medium-medium, medium-high, high-low, high-medium, high-high"
            }
        }

        # Ensure proper syntax
        if ($ThreatLevel) {
            $ValidStatus = @("none", "low-low", "low-medium", "low-high", "medium-low", "medium-medium", "medium-high", "high-low", "high-medium", "high-high")
            if ($ValidStatus.Contains($($ThreatLevel.ToLower()))) {
                $_threatLevel = (Get-Culture).TextInfo.ToTitleCase($ThreatLevel)
            } else {
                throw [ArgumentException] "ThreatLevel [$ThreatLevel] must be: none, low-low, low-medium, low-high, medium-low, medium-medium, medium-high, high-low, high-medium, high-high"
            }
        }

        # Ensure proper syntax
        if ($Zone) {
            $ValidStatus = @("unknown", "internal", "dmz", "external")
            if ($ValidStatus.Contains($($Zone.ToLower()))) {
                # Update RecordStatus for 7.5 API
                if ($LrVersion -ge 7.5) {
                    if ($Zone -eq "unknown") {
                        $Zone = "internal"
                    }
                }
                # Update Dmz for appropriate API Syntax
                if ($Zone -eq "Dmz") {
                    $_zone = "DMZ"
                } else {
                    $_zone = (Get-Culture).TextInfo.ToTitleCase($Zone)
                }
            } else {
                throw [ArgumentException] "Zone [$Zone] must be: unknown, dmz, external"
            }
        }

        # OS
        if ($Os) {
            $ValidStatus = @('unknown', 'other', 'windowsnt4', 'windows2000professional', 'windows2000server', 'windows2003standard', 'windows2003enterprise', `
            'windows95' ,'windowsxp' ,'windowsvista', 'linux', 'solaris', 'aix', 'hpux', 'windows')
            if ($ValidStatus.Contains($($Os.ToLower()))) {
                # Update for appropriate API Syntax
                switch ($Os) {
                    unknown { $_os = "Unknown" }
                    other { $_os  = "Other" }
                    windowsnt4 { $_os  = "WindowsNT4" }
                    windows2000professional { $_os = "Windows2000Professional" }
                    windows2000server { $_os = "Windows2000Server" }
                    windows2003standard { $_os = "Windows2003Standard" }
                    windows2003enterprise { $_os = "Windows2003Enterprise" }
                    windows95 { $_os = "Windows95" }
                    windowsxp { $_os = "WindowsXP" }
                    windowsvista { $_os = "WindowsVista" }
                    linux { $_os = "Linux" }
                    solaris { $_os = "Solaris" }
                    aix { $_os = "AIX" }
                    hpux { $_os = "HPUX" }
                    windows { $_os = "Windows" }
                    default { $_os = "Unknown" }
                }
            } else {
                throw [ArgumentException] "OS [$Os] must be: "
            }
        }

        # For future length check
        if ($OSVersion) {
            $_osVersion = $OSVersion
        }

        # Ensure proper syntax
        if ($OSType) {
            $ValidStatus = @("server", "none", "desktop")
            if ($ValidStatus.Contains($($OSType.ToLower()))) {
                $_osType = (Get-Culture).TextInfo.ToTitleCase($OSType)
            } else {
                throw [ArgumentException] "OS Type [$OSType] must be: server, none, or desktop"
            }
        }

        #>
        $BodyContents = [PSCustomObject]@{
            id = -1
            entity = [PSCustomObject]@{
                    id = $($_entity.Id)
                    name = $($_entity.Name)
            }
            name =  $Name
            shortDesc = $shortDesc
            longDesc = $longDesc
            riskLevel = $_riskLevel
            threatLevel = $_threatLevel
            threatLevelComments = $ThreatLevelComment
            recordStatusName = $_recordStatus
            hostZone = $_zone
            location = [PSCustomObject]@{
                name = $Location
            }
            os = $_os
            osVersion = $_osVersion
            eventlogUsername = ""
            eventlogPassword = ""
            useEventlogCredentials = $UseEventlogCredentials
            osType = $_osType
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json -Depth 3

        Write-Verbose "$Body"

        # Define Query URL
        $RequestUrl = $BaseUrl + "/hosts/"

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body 
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        }
        
        #>
        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($Exact) {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        } else {
            return $Response
        }
    }

    End { }
}