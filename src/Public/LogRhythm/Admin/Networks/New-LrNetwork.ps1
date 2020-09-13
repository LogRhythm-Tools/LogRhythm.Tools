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
        Specifies a LogRhythm Entity object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Site Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER EntityId
        Parameter for specifying the existing LogRhythm Entity for the new Network record to be set to.  
        This parameter explicitly represents the Entity Id int32 value.

        [System.Int32]
        Specifies a LogRhythm Entity object by providing the value:
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Name
        [System.String] Parameter for specifying a new network name.  
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
    .PARAMETER Zone
        Set network zone.  
        
        Valid entries: "Unknown", "Internal", "DMZ", "External"
    .PARAMETER Location
        String value representing geographic location based on location name.  
        
        If no LocationId is provided in conjuction with Location it is recommended to pass the Switch Paramater -LocationLookup.
    .PARAMETER LocationId
        Int32 value representing the network's geographic location based on location ID.

        If no LocationName is provided in conjuction with LocationId it is recommended to pass the Switch Paramater -LocationLookup.
    .PARAMETER BIP
        IPv4 Network starting Address.
    .PARAMETER EIP
        IPv4 Network ending Address.
    .PARAMETER LocationLookup
        Performs a location lookup and verification.  This paramater increases the execution time of this cmdlet.

        For LogRhythm Versions 7.5.X and greater the lookup is performed via API.
        For LogRhythm Versions 7.4.X the lookup is performed via a local locations csv contained within LogRhyhtm.Tools.
    .INPUTS
        [System.String]    -> Name
        [System.String]    -> Entity
        [System.Int32]     -> EntityId
        [System.String]    -> ShortDesc
        [System.String]    -> LongDesc
        [System.String]    -> RiskLevel
        [System.String]    -> ThreatLevel
        [System.String]    -> ThreatLevelComment
        [System.String]    -> RecordStatus
        [System.String]    -> Zone
        [System.String]    -> Location
        [System.int32]     -> LocationId
        [System.IpAddress] -> Bip
        [System.IpAddress] -> Eip
        [System.Switch]    -> LocationLookup
    .OUTPUTS
        PSCustomObject representing the new LogRhythm Network and its contents.
    .EXAMPLE
        PS C:\> New-LrNetwork -name "DMZ Alpha" -Zone "dmz" -ShortDesc "Mature development applications for external testing." -RiskLevel "medium-medium" -ThreatLevel "medium-high" -ThreatLevelComment "Due to the development nature of the services in this zone the level has been elevated from our default DMZ value." -Bip 10.54.54.0 -Eip 10.54.54.255 -Entity "Secondary Site"
        ---
        entity             : @{id=5; name=Secondary Site}
        name               : DMZ Alpha
        shortDesc          : Mature development applications for external testing.
        riskLevel          : Medium-Medium
        threatLevel        : Medium-High
        threatLevelComment : Due to the development nature of the services in this zone the level has been elevated from our default DMZ value.
        recordStatusName   : Active
        hostZone           : DMZ
        location           : @{id=-1}
        bip                : 10.54.54.0
        eip                : 10.54.54.255
        dateUpdated        : 2020-07-23T12:56:32.087Z
        id                 : 6
    .EXAMPLE
        New-LrNetwork -name "DMZ Bravo" -Zone "dmz" -ShortDesc "Mature development applications for external testing." -RiskLevel "medium-medium" -ThreatLevel "medium-high" -ThreatLevelComment "Due to the development nature of the services in this zone the level has been elevated from our default DMZ value." -Bip 10.55.55.0 -Eip 10.55.55.255 -Entity "Secondary Site" -Location "Spartanburg" -LocationLookup
        ---
        entity             : @{id=5; name=Secondary Site}
        name               : DMZ Bravo
        shortDesc          : Mature development applications for external testing.
        riskLevel          : Medium-Medium
        threatLevel        : Medium-High
        threatLevelComment : Due to the development nature of the services in this zone the level has been elevated from our default DMZ value.
        recordStatusName   : Active
        hostZone           : DMZ
        location           : @{id=29929; name=Spartanburg}
        bip                : 10.55.55.0
        eip                : 10.55.55.255
        dateUpdated        : 2020-07-23T12:58:34.487Z
        id                 : 7
    .EXAMPLE
        PS C:\> New-LrNetwork -name "DMZ Alpha" -Zone "dmz" -ShortDesc "Mature development applications for external testing." -RiskLevel "medium-medium" -ThreatLevel "medium-high" -ThreatLevelComment "Due to the development nature of the services in this zone the level has been elevated from our default DMZ value." -Bip 10.54.54.0 -Eip 10.54.54.255
        ---
        Code  : 400
        Error : True
        Type  : NullValue
        Note  : Cmdlet must be provided EntityId or Entity paramater values.
        Value : DMZ Alpha
    .EXAMPLE 
        New-LrNetwork -name "DMZ Alpha" -Zone "dmz" -ShortDesc "Mature development applications for external testing." -RiskLevel "medium-medium" -ThreatLevel "medium-high" -ThreatLevelComment "Due to the development nature of the services in this zone the level has been elevated from our default DMZ value." -Bip 10.54.54.0 -Eip 10.54.54.255 -Entity "Secondary"
        ---
        Code  : 404
        Error : True
        Type  : NoRecordFound
        Note  : Unable to locate exact Entity: Secondary
        Value : DMZ Alpha
    .EXAMPLE
        New-LrNetwork -name "DMZ Bravo" -Zone "dmz" -ShortDesc "Mature development applications for external testing." -RiskLevel "medium-medium" -ThreatLevel "medium-high" -ThreatLevelComment "Due to the development nature of the services in this zone the level has been elevated from our default DMZ value." -Bip 10.54.54.0 -Eip 10.54.54.255 -Entity "Secondary Site"
        ---
        Code  : 400
        Error : True
        Type  : System.Net.WebException
        Note  : Network IP range is conflicting with IP range of other networks
        Value : DMZ Bravo
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Entity,


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Name,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string] $ShortDesc,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [string] $LongDesc,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [ValidateSet(
            'none',
            'low-low',
            'low-medium',
            'low-high',
            'medium-low',
            'medium-medium',
            'medium-high',
            'high-low',
            'high-medium',
            'high-high', 
            ignorecase=$true
        )]
        [string] $RiskLevel = "none",


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [ValidateSet(
            'none',
            'low-low',
            'low-medium',
            'low-high',
            'medium-low',
            'medium-medium',
            'medium-high',
            'high-low',
            'high-medium',
            'high-high', 
            ignorecase=$true
        )]
        [string] $ThreatLevel = "none",


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [string] $ThreatLevelComment,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 7)]
        [ValidateSet('retired','active', ignorecase=$true)]
        [string] $RecordStatus = "active",


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 8)]
        [ValidateSet('unknown','internal','dmz','external', ignorecase=$true)]
        [string] $Zone="unknown",


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 9)]
        [string] $Location,


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 10)]
        [ipaddress]$Bip,


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 11)]
        [ipaddress]$Eip,


        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
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
        [int32] $_int = 1
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
        if ($EntityId -or $Entity) {
            if ($EntityId) {
                Write-Verbose "[$Me]: Validating EntityId: $EntityId"
                $EntityLookup = Get-LrEntityDetails -Id $Entity
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    return $ErrorObject
                } else {
                    $_entity = $EntityLookup
                }
            } elseif ($Entity){
                if ([int]::TryParse($Entity, [ref]$_int)) {
                    Write-Verbose "[$Me]: Validating Entity as Int32.  EntityId: $Entity"
                    $EntityLookup = Get-LrEntityDetails -Id $Entity
                    if ($EntityLookup.Error -eq $true) {
                        $ErrorObject.Error = $EntityLookup.Error
                        $ErrorObject.Type = $EntityLookup.Type
                        $ErrorObject.Code = $EntityLookup.Code
                        $ErrorObject.Note = $EntityLookup.Note
                        return $ErrorObject
                    } else {
                        $_entity = $EntityLookup
                    }
                } else {
                    Write-Verbose "[$Me]: Validating Entity as String.  EntityName: $Entity"
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
            }
        } else {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "NullValue"
            $ErrorObject.Code = 400
            $ErrorObject.Note = "Cmdlet must be provided EntityId or Entity paramater values."
            return $ErrorObject
        }      

        Write-Verbose "Entity: $_entity"

        # Location lookup
        if ($LocationId -and $Location) {
            if ($LocationLookup) {
                if ($LrtConfig.LogRhythm.Version -notmatch '7.5.\d') {
                    $LocationStatus = Show-LrLocations -Id $LocationId
                    if ($LocationStatus) {
                        $_locationName = $LocationStatus.name
                        $_locationId = $LocationStatus.id
                    }
                } else {
                    $LocationStatus = Get-LrLocations -Id $LocationId
                    if ($LocationStatus) {
                        $_locationName = $LocationStatus.name
                        $_locationId = $LocationStatus.id
                    }
                }
            } else {
                $_locationName = $Location 
                $_locationId = $LocationId
            }
            $_location = [PSCustomObject][Ordered]@{
                id = $_locationId
                name = $_locationName
            }
        } elseif ($Location) {
            if ($LocationLookup) {
                if ($LrtConfig.LogRhythm.Version -notmatch '7.5.\d') {
                    $LocationStatus = Show-LrLocations -Name $Location -Exact
                    if ($LocationStatus) {
                        $_locationName = $LocationStatus.name
                        $_locationId = $LocationStatus.id
                    }
                } else {
                    $LocationStatus = Get-LrLocations -Name $Location -Exact
                    if ($LocationStatus) {
                        $_locationName = $LocationStatus.name
                        $_locationId = $LocationStatus.id
                    }
                }
                $_location = [PSCustomObject][Ordered]@{
                    id = $_locationId
                    name = $_locationName
                }
            } else {
                $_location = [PSCustomObject]@{
                    name = $Location
                }
            }
        } else {
            $_location = [PSCustomObject][Ordered]@{
                name = ""
            }
        }

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
            location = $_location
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