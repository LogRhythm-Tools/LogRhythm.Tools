using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrNetwork {
    <#
    .SYNOPSIS
        Update a Network entry for the LogRhythm Entity structure.
    .DESCRIPTION
        Update-LrNetwork updates a Network Entity record.
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
        String used to search Entity parent and child records by Entity Name and update a Network record's Entity value.
    .PARAMETER EntityId
        Int32 used to search Entity parent and child records by Entity Id and update a Network record's Entity value.
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
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.String]    -> Id
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
        PSCustomObject representing LogRhythm Network Entity for the updated record.
    .EXAMPLE
        PS C:\> Update-LrNetwork -Id 5 -Name "New Network" -Entity "Secondary Site" -ThreatLevel "medium-high" -EIP 10.77.21.255 -Zone dmz -RecordStatus active -ShortDesc "It's not really all that new." -LongDesc "This record was first created on January 5th 2007." -ThreatLevelComment "This comment describes the risks associated with this network if it were to be the origin of abnormal activity." -Location "Spartanburg" -LocationLookup -PassThru
        ----
        entity             : @{id=5; name=Secondary Site}
        name               : New Network
        shortDesc          : It's not really all that new.
        longDesc           : This record was first created on January 5th 2007.
        riskLevel          : None
        threatLevel        : Medium-High
        threatLevelComment : This comment describes the risks associated with this network if it were to be the origin of abnormal activity.
        recordStatusName   : Active
        hostZone           : DMZ
        location           : @{id=29929; name=Spartanburg}
        bip                : 10.77.20.1
        eip                : 10.77.21.255
        dateUpdated        : 2020-07-23T11:54:09.643Z
        id                 : 5
    .EXAMPLE
        PS C:\> Update-LrNetwork -Name "New Network" -BIP 10.77.18.0 -PassThru
        --- 
        entity             : @{id=5; name=Secondary Site}
        name               : New Network
        shortDesc          : It's not really all that new.
        longDesc           : This record was first created on January 5th 2007.
        riskLevel          : None
        threatLevel        : Medium-High
        threatLevelComment : This comment describes the risks associated with this network if it were to be the origin of abnormal activity.
        recordStatusName   : Active
        hostZone           : DMZ
        location           : @{id=29929; name=Spartanburg}
        bip                : 10.77.18.0
        eip                : 10.77.21.255
        dateUpdated        : 2020-07-23T11:55:37.247Z
        id                 : 5
    .EXAMPLE
        PS C:\> Update-LrNetwork -Id 5 -Name "Older Network" -PassThru
        ---
        entity             : @{id=5; name=Secondary Site}
        name               : Older Network
        shortDesc          : It's not really all that new.
        longDesc           : This record was first created on January 5th 2007.
        riskLevel          : None
        threatLevel        : Medium-High
        threatLevelComment : This comment describes the risks associated with this network if it were to be the origin of abnormal activity.
        recordStatusName   : Active
        hostZone           : DMZ
        location           : @{id=29929; name=Spartanburg}
        bip                : 10.77.18.0
        eip                : 10.77.21.255
        dateUpdated        : 2020-07-23T11:56:22.327Z
        id                 : 5
    .EXAMPLE
        PS C:\> Update-LrNetwork -Name "Older Network" -Entity "Primary Site" -PassThru
        ---
        entity             : @{id=1; name=Primary Site}
        name               : Older Network
        shortDesc          : It's not really all that new.
        longDesc           : This record was first created on January 5th 2007.
        riskLevel          : None
        threatLevel        : Medium-High
        threatLevelComment : This comment describes the risks associated with this network if it were to be the origin of abnormal activity.
        recordStatusName   : Active
        hostZone           : DMZ
        location           : @{id=29929; name=Spartanburg}
        bip                : 10.77.18.0
        eip                : 10.77.21.255
        dateUpdated        : 2020-07-23T11:56:56.323Z
        id                 : 5
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [string] $Id,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Name,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string] $Entity,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [string] $ShortDesc,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [string] $LongDesc,


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
        [string] $RiskLevel = "none",


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
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
        [string] $ThreatLevel,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 7)]
        [string] $ThreatLevelComment,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 8)]
        [ValidateSet('retired','active', ignorecase=$true)]
        [string] $RecordStatus,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 9)]
        [ValidateSet('unknown','internal','dmz','external', ignorecase=$true)]
        [string] $Zone="unknown",


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 10)]
        [string] $Location,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 11)]
        [int32]$LocationId,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 13)]
        [ipaddress]$Bip,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 14)]
        [ipaddress]$Eip,

                                
        [Parameter(Mandatory = $false, Position = 15)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 16)]
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
        $Method = $HttpMethod.Put

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

        # Lookup Network ID or Name to find Network ID
        if ($Id) {
            if ([int]::TryParse($Id, [ref]$_int)) {
                Write-Verbose "[$Me]: Network ID parses as integer. Id: $Id"
                $NetworkLookup = Get-LrNetworkDetails -Id $Id
                if ($NetworkLookup.Error -eq $true) {
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
        } else {
            $_entity = $NetworkLookup.entity
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
            if ($NetworkLookup.location.id -eq -1) {
                $_location = [PSCustomObject]@{
                    name = ""
                }
            } else {
                $_location = $NetworkLookup.location
            }
        }

        # Name - Check for update or keep existing value
        if ($Name) {
            $_name = $Name
        } else {
            $_name = $NetworkLookup.name
        }

        # ShortDesc - Check for update or keep existing value
        if ($ShortDesc) {
            $_shortDesc = $ShortDesc
        } else {
            if ($NetworkLookup.shortDesc) {
                $_shortDesc = $NetworkLookup.shortDesc
            } else {
                $_shortDesc = ""
            }
        }

        # LongDesc - Check for update or keep existing value
        if ($LongDesc) {
            $_longDesc = $LongDesc
        } else {
            if ($NetworkLookup.longDesc) {
                $_longDesc = $NetworkLookup.longDesc
            } else {
                $_longDesc = ""
            }
        }

        # ThreatLevelComment - Check for update or keep existing value
        if ($ThreatLevelComment) {
            $_threatLevelComment = $ThreatLevelComment
        } else {
            Write-Verbose "No ThreatLevelComment provided.  Retaining value from origin record.  Value: $($NetworkLookup.threatLevelComment)"
            if ($NetworkLookup.threatLevelComment) {
                $_threatLevelComment = $NetworkLookup.threatLevelComment
            } else {
                $_threatLevelComment = ""
            }
        }

        # RecordStatus - Check for update or keep existing value
        if ($RecordStatus) {
            $_recordStatus = (Get-Culture).TextInfo.ToTitleCase($RecordStatus)
        } else {
            Write-Verbose "No RecordStatus provided.  Retaining value from origin record.  Value: $($NetworkLookup.recordStatusName)"
            $_recordStatus = $NetworkLookup.recordStatusName 
        }

        # RiskLevel - Check for update or keep existing value
        if ($RiskLevel) {
            $_riskLevel = (Get-Culture).TextInfo.ToTitleCase($RiskLevel)
        } else {
            Write-Verbose "No RiskLevel provided.  Retaining value from origin record.  Value: $($NetworkLookup.riskLevel)"
            $_riskLevel = $NetworkLookup.riskLevel
        }

        # ThreatLevel - Check for update or keep existing value
        if ($ThreatLevel) {
            $_threatLevel = (Get-Culture).TextInfo.ToTitleCase($ThreatLevel)
        } else {
            Write-Verbose "No ThreatLevel provided.  Retaining value from origin record.  Value: $($NetworkLookup.threatLevel)"
            $_threatLevel = $NetworkLookup.threatLevel
        }

        # Zone - Check for update or keep existing value
        if ($Zone) {
            if ($Zone -like "dmz") {
                $_zone = "DMZ"
            } else {
                $_zone = (Get-Culture).TextInfo.ToTitleCase($Zone)
            }
        } else {
            Write-Verbose "No Zone provided.  Retaining value from origin record.  Value: $($NetworkLookup.hostZone)"
            $_zone = $NetworkLookup.hostZone
        }

        # BIP - Check for update or keep existing value
        if ($BIP) {
            $_bIP = $BIP.IPAddressToString
        } else {
            Write-Verbose "No BIP provided.  Retaining value from origin record.  Value: $($NetworkLookup.bip)"
            $_bIP = $NetworkLookup.BIP
        }

        # EIP - Check for update or keep existing value
        if ($EIP) {
            $_eIP = $EIP.IPAddressToString
        } else {
            Write-Verbose "No EIP provided.  Retaining value from origin record.  Value: $($NetworkLookup.eip)"
            $_eIP = $NetworkLookup.EIP
        }

        #>
        $BodyContents = [PSCustomObject]@{
            entity = [PSCustomObject]@{
                    id = $($_entity.Id)
                    name = $($_entity.Name)
            }
            name =  $_name
            shortDesc = $_shortDesc
            longDesc = $_longDesc
            riskLevel = $_riskLevel
            threatLevel = $_threatLevel
            threatLevelComment = $_threatLevelComment
            recordStatusName = $_recordStatus
            hostZone = $_zone
            location = $_location
            bip = $_bIP
            eip = $_eIP
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json -Depth 3

        Write-Verbose "$Body"

        # Define Query URL
        $RequestUrl = $BaseUrl + "/networks/" + $_networkId + "/"

        # Send Request
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

        # Return output object
        if ($ErrorObject.Error -eq $true) {
            return $ErrorObject
        }
        if ($PassThru) {
            return $Response
        }
    }

    End { }
}