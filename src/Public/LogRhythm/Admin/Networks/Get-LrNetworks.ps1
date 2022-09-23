using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrNetworks {
    <#
    .SYNOPSIS
        Retrieve a list of Networks from the LogRhythm Entity structure.
    .DESCRIPTION
        Get-LrNetworks returns a full LogRhythm Network object, including details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Name
        String used to search Entity Network records by Name.
    .PARAMETER Entity,
        String used to search Entity Network by Entity Name.
    .PARAMETER RecordStatus,
        String used to restrict results based on RecordStatus.
        Valid entries: All, Active, Retired
    .PARAMETER Exact
        Switch used to specify Name search for Entity Network record is explicit.
    .INPUTS
        [System.Int]    -> PageCount
        [System.String] -> Name
        [System.String] -> Entity
        [System.String] -> RecordStatus
        [System.Switch] -> Exact
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        PS C:\> Get-LrNetworks
        ----
        entity             : @{id=5; name=Secondary Site}
        name               : Network a
        riskLevel          : None
        threatLevel        : None
        threatLevelComment :
        recordStatusName   : Active
        hostZone           : Internal
        location           : @{id=-1}
        bip                : 192.168.1.1
        eip                : 192.168.1.255
        dateUpdated        : 2020-07-20T22:50:57.433Z
        id                 : 1

        entity             : @{id=1; name=Primary Site}
        name               : Network Alpha
        shortDesc          : Brief description value.
        longDesc           : Additional details note.
        riskLevel          : Medium-Medium
        threatLevel        : None
        threatLevelComment :
        recordStatusName   : Active
        hostZone           : Internal
        location           : @{id=-1}
        bip                : 192.168.20.1
        eip                : 192.168.20.255
        dateUpdated        : 2020-07-21T13:42:33.253Z
        id                 : 3

        entity             : @{id=1; name=Primary Site}
        name               : Network Beta
        riskLevel          : None
        threatLevel        : None
        threatLevelComment :
        recordStatusName   : Active
        hostZone           : Internal
        location           : @{id=-1}
        bip                : 172.16.20.1
        eip                : 172.16.21.255
        dateUpdated        : 2020-07-21T11:40:26.367Z
        id                 : 4
    .EXAMPLE
        PS C:\> Get-LrNetworks -Entity "Secondary Site"
        ---
        entity             : @{id=5; name=Secondary Site}
        name               : Network a
        riskLevel          : None
        threatLevel        : None
        threatLevelComment :
        recordStatusName   : Active
        hostZone           : Internal
        location           : @{id=-1}
        bip                : 192.168.1.1
        eip                : 192.168.1.255
        dateUpdated        : 2020-07-20T22:50:57.433Z
        id                 : 1
    .EXAMPLE
        PS C:\> Get-LrNetworks -Entity "Secondary Site" -RecordStatus "retired"
        --- 
        entity             : @{id=5; name=Secondary Site}
        name               : Network a
        riskLevel          : None
        threatLevel        : None
        threatLevelComment :
        recordStatusName   : Retired
        hostZone           : Internal
        location           : @{id=-1}
        bip                : 192.168.1.1
        eip                : 192.168.1.255
        dateUpdated        : 2020-07-23T12:33:37.153Z
        id                 : 1

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Name,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Entity,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidateSet('asc','desc', ignorecase=$true)]
        [string] $Direction,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateSet('all','active','retired', ignorecase=$true)]
        [string] $RecordStatus = "active",


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [ipaddress] $BIP,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [ipaddress] $EIP,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [ValidateSet('name','bip','eip','entity', ignorecase=$true)]
        [string] $OrderBy = "Entity",

        
        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 8)]
        [int] $PageValuesCount = 1000,


        [Parameter(Mandatory = $false, Position = 9)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 10)]
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
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Integer Reference
        [int32]$_int = 1
    }

    Process {
        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # PageCount
        if ($PageValuesCount) {
            $_pageValueCount = $PageValuesCount
        } else {
            $_pageValueCount = 1000
        }
        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $_pageValueCount)

        # Query Offset - PageCount
        $Offset = $PageCount - 1
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if ($Name) {
            $_name = $Name
            $QueryParams.Add("name", $_name)
        }

        # Filter by Object Entity Name
        if ($Entity) {
            # Lookup Entity By ID or Name
            if ([int]::TryParse($Entity, [ref]$_int)) {
                Write-Verbose "[$Me]: Validating Entity as Int32.  EntityId: $Entity"
                $EntityLookup = Get-LrEntityDetails -Id $Entity
                if ($EntityLookup.Error -eq $true) {
                    return $EntityLookup
                } else {
                    $_entity = $EntityLookup
                }
            } else {
                Write-Verbose "[$Me]: Validating Entity as String.  EntityName: $Entity"
                $EntityLookup = Get-LrEntities -Name $Entity -Exact
                if ($EntityLookup.Error -eq $true) {
                    return $EntityLookup
                } else {
                    $_entity = $EntityLookup
                }
            }

            $_entityName = $_entity.Name
            $QueryParams.Add("Entity", $_entityName)
        }

        # Return results direction, ascending or descending
        if ($Direction) {
            # Apply formatting based on Lr Version
            if ($LrtConfig.LogRhythm.Version -notmatch '7\.[0-4]\.\d+') {
                if($Direction.ToUpper() -eq "ASC") {
                    $_direction = "ascending"
                } else {
                    $_direction = "descending"
                }
            } else {
                $_direction = $Direction.ToUpper()
            }
            $QueryParams.Add("dir", $_direction)
        }

        # Filter by Begin IP Address
        if ($BIP) {
            $_bIP = $BIP.IPAddressToString
            $QueryParams.Add("BIP", $_bIP)
        }

        # Filter by End IP Address
        if ($EIP) {
            $_eIP = $EIP.IPAddressToString
            $QueryParams.Add("EIP", $_eIP)
        }

        # RecordStatus
        if ($RecordStatus) {
            $_recordStatus = $RecordStatus.ToLower()
            $QueryParams.Add("recordStatus", $_recordStatus)
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/networks/" + $QueryString

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Check if pagination is required, if so - paginate!
        if ($Response.Count -eq $PageValuesCount) {
            Write-Verbose "[$Me]: Begin Pagination"
            DO {
                # Increment Page Count / Offset
                #$PageCount = $PageCount + 1
                $Offset += $PageValuesCount
                # Update Query Paramater
                $QueryParams.offset = $Offset
                # Apply to Query String
                $QueryString = $QueryParams | ConvertTo-QueryString
                # Update Query URL
                $RequestUrl = $BaseUrl + "/lr-admin-api/networks/" + $QueryString
                Write-Verbose "[$Me]: Request URL: $RequestUrl"

                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if (($null -ne $PaginationResults.Error) -and ($PaginationResults.Error -eq $true)) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $PageValuesCount)
            $Response = $Response | Sort-Object -Property Id -Unique
            Write-Verbose "[$Me]: End Pagination"
        }

        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($Exact) {
            $Pattern1 = "^$Name$"
            $Pattern2 = "^$BIP$"
            $Pattern3 = "^$EIP$"
            $Response | ForEach-Object {
                if ($Name) {
                    if(($_.name -match $Pattern1) -or ($_.name -eq $Name)) {
                        Write-Verbose "[$Me]: Exact list name match found."
                        $NameMatch = $_
                    }
                }
                if ($BIP) {
                    if(($_.name -match $Pattern2) -or ($_.BIP -eq $BIP)) {
                        Write-Verbose "[$Me]: Exact list Beginning IP match found."
                        $BIPMatch = $_
                    }
                }
                if ($EIP) {
                    if(($_.name -match $Pattern3) -or ($_.EIP -eq $EIP)) {
                        Write-Verbose "[$Me]: Exact list Ending IP match found."
                        $EIPMatch = $_
                    }
                }
            }
            if ($EIP -and $BIP -and $Name) {
                if (($NameMatch -eq $EIPMatch) -and ($NameMatch -eq $BIPMatch)) {
                    Write-Verbose "[$Me]: All matched criteria are identical.  Returning result."
                    return $NameMatch
                }
            } elseif ( $EIP -and $BIP) {
                if ($EIPMatch -eq $BIPMatch) {
                    Write-Verbose "[$Me]: All matched criteria are identical.  Returning result."
                    return $EIPMatch
                }
            } elseif ( $EIP -and $Name) {
                if ($NameMatch -eq $EIPMatch) {
                    Write-Verbose "[$Me]: All matched criteria are identical.  Returning result."
                    return $NameMatch
                }
            } elseif ( $BIP -and $Name) {
                if ($NameMatch -eq $BIPMatch) {
                    Write-Verbose "[$Me]: All the individuals match are identical.  Returning result."
                    return $NameMatch
                }
            } elseif ($BIP) {
                return $BIPMatch
            } elseif ($EIP) {
                return $EIPMatch
            } elseif ($Name) {
                return $NameMatch
            }
        } else {
            return $Response
        }
    }

    End {
    }
}