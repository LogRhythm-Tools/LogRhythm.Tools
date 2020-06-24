using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrNetwork {
    <#
    .SYNOPSIS
        Create a new Network entry for the LogRhythm Entity structure.
    .DESCRIPTION
        New-LrNetwork returns a full LogRhythm Host object, including details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Entity
        Parameter for specifying the existing LogRhythm Entity for the new Network record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Network object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Network Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Name
        [System.String] Parameter for specifying a new network name.  
        
        *If the Id parameter is not provided the Name paramater will be attempted to identify the appropraite record.
    .PARAMETER ShortDescription
        A brief description of the network entity.
    .PARAMETER LongDescription
        An extended description of the network entity.
    .PARAMETER RiskLevel
        Designated network segment Risk Level.

        Valid entries: "None" "Low-Low" "Low-Medium" "Low-High" "Medium-Low" "Medium-Medium" "Medium-High" "High-Low" "High-Medium" "High-High"
    .PARAMETER ThreatLevel
        Designated network segment Threat Level.

        Valid entries: "None" "Low-Low" "Low-Medium" "Low-High" "Medium-Low" "Medium-Medium" "Medium-High" "High-Low" "High-Medium" "High-High"
    .PARAMETER ThreatLevelComment
        Provide context to ThreatLevel score associted with Network Record.

    .PARAMETER RecordStatus
        String used to restrict results based on RecordStatus.
        Valid entries: "New", "Active", "Retired"
    .PARAMETER HostZone
        Set network zone.  
        
        Valid entries: "Unknown", "Internal", "DMZ", "External"
    .PARAMETER Location
        Set the network's geographic location.

        This parameter will be enhanced with location lookup verification with LogRhythm 7.5 API.
    .PARAMETER BeginIP
        IPv4 Network starting Address.
    .PARAMETER EndIP
        IPv4 Network ending Address.
    .PARAMETER Entity,
        String used to search Entity Host by Entity Name.
    .INPUTS
        [System.String] -> Name
        [System.String] -> Entity
        [System.String] -> RecordStatus
    .OUTPUTS
        PSCustomObject representing LogRhythm Network and its contents.
    .EXAMPLE
        PS C:\> New-LrNetwork
        ----
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
        [ValidateSet('retired','active', ignorecase=$true)]
        [string]$RecordStatus = "active",

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 9)]
        [ValidateSet('unknown','internal','dmz','external', ignorecase=$true)]
        [string]$Zone="unknown",

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 10)]
        [string]$Location,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, Position = 11)]
        [ipaddress]$Bip,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, Position = 12)]
        [ipaddress]$Eip
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
            throw [ArgumentException] "Entity [null] must be: Entity Name or Entity ID."
        }
        Write-Verbose "Entity: $_entity"

        # TODO Location Lookup.  7.5 API

        # Ensure proper syntax
        if ($RecordStatus) {
            $ValidStatus = "new", "retired", "active"
            if ($ValidStatus.Contains($($RecordStatus.ToLower()))) {
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
                if ($Zone -eq "Dmz") {
                    $_zone = "DMZ"
                } else {
                    $_zone = (Get-Culture).TextInfo.ToTitleCase($Zone)
                }
            } else {
                throw [ArgumentException] "Zone [$Zone] must be: unknown, dmz, external"
            }
        }

        #>
        $BodyContents = [PSCustomObject]@{
            entity = [PSCustomObject]@{
                    id = $($_entity.Id)
                    name = $($_entity.Name)
            }
            name =  $Name
            shortDesc = $shortDesc
            longDesc = $longDesc
            riskLevel = $_riskLevel
            threatLevel = $_threatLevel
            threatLevelComment = $ThreatLevelComment
            recordStatusName = $_recordStatus
            hostZone = $_zone
            location = [PSCustomObject]@{
                name = $Location
            }
            bip = $Bip.IPAddressToString
            eip = $Eip.IPAddressToString
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json -Depth 3

        Write-Verbose "$Body"

        # Define Query URL
        $RequestUrl = $BaseUrl + "/networks/"

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
            }
            catch [System.Net.WebException] {
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