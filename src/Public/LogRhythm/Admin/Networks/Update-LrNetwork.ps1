using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrNetwork {
    <#
    .SYNOPSIS
        Update a Network entry for the LogRhythm Entity structure.
    .DESCRIPTION
        Update-LrNetwork updates a Network Entity record.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        Parameter for specifying object to be updated.  A network record's Id value cannot be changed.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Network object by providing one of the following property values:
          + Network Name (as System.String), e.g. "Network Bravo"
          + Network Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Name
        [System.String] Parameter for specifying a new network name.  
        
        *If the Id parameter is not provided the Name paramater will be attempted to identify the appropraite record.
    .PARAMETER Entity
        Parameter for specifying the existing or new Entity for the network record.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Network object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Network Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
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
        Valid entries: "Active", "Retired"
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
        [System.String] -> Id
    .OUTPUTS
        PSCustomObject representing LogRhythm Network Entity for the updated record.
    .EXAMPLE
        PS C:\> Update-LrNetwork 
        ----
        entity             : @{id=-100; name=Global Entity}
        name               : UberNet
        shortDesc          : My new network
        longDesc           : Really does rule.
        riskLevel          : Low-High
        threatLevel        : High-Low
        threatLevelComment : its secure
        recordStatusName   : Active
        hostZone           : Internal
        location           : @{id=-1}
        bip                : 10.7.1.1
        eip                : 10.7.2.2
        dateUpdated        : 2020-05-20T19:05:21.093Z
        id                 : 9
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
        
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position = 1)]
        [string]$Id,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 2)]
        [string]$Name,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 3)]
        [string]$Entity,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 4)]
        [int32]$EntityId,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 5)]
        [string]$ShortDesc,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 6)]
        [string]$LongDesc,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 7)]
        [ValidateSet('none','low-low','low-medium','low-high','medium-low','medium-medium','medium-high','high-low','high-medium','high-high', ignorecase=$true)]
        [string]$RiskLevel,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 8)]
        [ValidateSet('none','low-low','low-medium','low-high','medium-low','medium-medium','medium-high','high-low','high-medium','high-high', ignorecase=$true)]
        [string]$ThreatLevel,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 9)]
        [string]$ThreatLevelComment,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 10)]
        [ValidateSet('retired','active', ignorecase=$true)]
        [string]$RecordStatus,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 11)]
        [ValidateSet('unknown','internal','dmz','external', ignorecase=$true)]
        [string]$Zone="unknown",

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 12)]
        [string]$Location,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 13)]
        [int32]$LocationId,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 14)]
        [ipaddress]$Bip,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 15)]
        [ipaddress]$Eip,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 16)]
        [switch]$LocationLookup
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
        $Method = $HttpMethod.Put

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
        if ($EntityId) {
            Write-Verbose "[$Me]: Validating EntityId: $EntityId"
            $EntityLookup = Get-LrEntityDetails -Id $EntityId
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
                Write-Verbose "[$Me]: Validating Entity as Id.  EntityId: $Entity"
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
                Write-Verbose "[$Me]: Validating Entity as Name.  EntityName: $Entity"
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
            $ErrorObject.Type = "NullValue"
            $ErrorObject.Code = 404
            $ErrorObject.Note = "Cmdlet must be provided EntityId or Entity paramater values."
        }
        Write-Verbose "Entity: $_entity"

        # Lookup Network ID or Name to find Network ID
        if ($Id) {
            if ([int]::TryParse($Id, [ref]$_int)) {
                Write-Verbose "[$Me]: Network ID parses as integer. Id: $Id"
                $NetworkIdLookup = Get-LrNetworkDetails -Id $Id
                if ($NetworkIdLookup.Error -eq $true) {
                    $ErrorObject.Error = $NetworkIdLookup.Error
                    $ErrorObject.Type = $NetworkIdLookup.Type
                    $ErrorObject.Code = $NetworkIdLookup.Code
                    $ErrorObject.Note = $NetworkIdLookup.Note
                    return $ErrorObject  
                } else {
                    Write-Verbose "[$Me]: Matched network record: $($NetworkIdLookup.id)"
                    $_networkId = $NetworkIdLookup | Select-Object -ExpandProperty id
                }
            } else {
                Write-Verbose "[$Me]: Network ID parses as string.  Performing Network Name lookup.  Id: $Id."
                $NetworkLookup = Get-LrNetworks -Name $Id -Exact
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $NetworkLookup.Error
                    $ErrorObject.Type = $NetworkLookup.Type
                    $ErrorObject.Code = $NetworkLookup.Code
                    $ErrorObject.Note = $NetworkLookup.Note
                } else {
                    Write-Verbose "[$Me]: Matched network record: $($NetworkLookup.id)"
                    $_networkId = $NetworkLookup | Select-Object -ExpandProperty id
                }
            }
        } elseif ($Name) {
            Write-Verbose "[$Me]: Performing Network Name lookup.  Id: $Name."
            $NetworkLookup = Get-LrNetworks -Name $Name -Exact
            if ($EntityLookup.Error -eq $true) {
                $ErrorObject.Error = $NetworkLookup.Error
                $ErrorObject.Type = $NetworkLookup.Type
                $ErrorObject.Code = $NetworkLookup.Code
                $ErrorObject.Note = $NetworkLookup.Note
                return $ErrorObject
            } else {
                Write-Verbose "[$Me]: Matched network record: $($NetworkLookup.id)"
                $_networkId = $NetworkLookup | Select-Object -ExpandProperty id
            }
        } else {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "NullValue"
            $ErrorObject.Code = 404
            $ErrorObject.Note = "Cmdlet must be provided Id or Name paramater values."
        }


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
                Id = $_locationId
                #Name = $_locationName
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
                    Id = $_locationId
                    #Name = $_locationName
                }
            } else {
                $_location = [PSCustomObject]@{
                    Name = $Location
                }
            }
        } else {
            $_location = [PSCustomObject]@{
                Name = ""
            }
        }


        # Ensure proper syntax
        if ($RecordStatus) {
            $ValidStatus = "new", "retired", "active"
            if ($ValidStatus.Contains($($RecordStatus.ToLower()))) {
                $_recordStatus = (Get-Culture).TextInfo.ToTitleCase($RecordStatus)
            } else {
                throw [ArgumentException] "RecordStatus [$RecordStatus] must be: new, active, or retired."
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
        } else {
            Write-Verbose "No RiskLevel provided.  Looking up value from origin record."
            $_riskLevel = Get-LrNetworkDetails -Id $_networkId | Select-Object -ExpandProperty riskLevel
        }

        # Ensure proper syntax
        if ($ThreatLevel) {
            $ValidStatus = @("none", "low-low", "low-medium", "low-high", "medium-low", "medium-medium", "medium-high", "high-low", "high-medium", "high-high")
            if ($ValidStatus.Contains($($ThreatLevel.ToLower()))) {
                $_threatLevel = (Get-Culture).TextInfo.ToTitleCase($ThreatLevel)
            } else {
                throw [ArgumentException] "ThreatLevel [$ThreatLevel] must be: none, low-low, low-medium, low-high, medium-low, medium-medium, medium-high, high-low, high-medium, high-high"
            }
        } else {
            Write-Verbose "No ThreatLevel provided.  Looking up value from origin record."
            $_threatLevel = Get-LrNetworkDetails -Id $_networkId | Select-Object -ExpandProperty threatLevel
            Write-Verbose "ThreatLevel: $_threatLevel"
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
        $RequestUrl = $BaseUrl + "/networks/" + $_networkId + "/"

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