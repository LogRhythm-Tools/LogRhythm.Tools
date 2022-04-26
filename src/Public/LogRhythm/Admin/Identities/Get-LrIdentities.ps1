using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrIdentities {
    <#
    .SYNOPSIS
        Retrieve a list of Identities from TrueIdentity.
    .DESCRIPTION
        Get-LrIdentities returns a full LogRhythm List object, including it's details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Name
        Filters Identity Display Names. Requires a three character minimum.
    .PARAMETER DisplayIdentifier
        Filters Identity Display Ids. Requires a three character minimum.
    .PARAMETER Entity
        Filters Identity Entities. Requires a three character minimum.
    .PARAMETER Identifier
        Filters Identity Ids. Requires a three character minimum.
    .PARAMETER RecordStatus
        Filters values based on current status.  
        
        Valid Status: Active, Retired
    .PARAMETER OrderBy
        Sorts record by displayName, recordStatus, Entity, or Displayidentifier.
    .PARAMETER Direction
        Sorts records by ascending or descending.

        Valid values: "asc" "desc"
    .PARAMETER DateUpdated
        Returns results having dateupdated greater or equal to than the one provided in query parameter
    .PARAMETER ShowRetired
        Switch used to filter records by retired status.  
        
        Defaults to returning only active Identities.
    .PARAMETER Exact
        Switch used to specify Name and Identifier fields, if submitted, are explicit.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        PS C:\> Get-LrIdentities -Name "bobby jones"
        ----
        identityID        : 1217
        nameFirst         : Bobby
        nameMiddle        : K
        nameLast          : Jones
        displayIdentifier : Bobby.Jones@example.com
        company           : LogRhythm
        department        : Sales
        title             : Sales Engineer
        manager           : Susan Smith
        addressCity       :
        domainName        :
        entity            : @{entityId=1; rootEntityId=0; path=Primary Site; name=Primary Site}
        dateUpdated       : 2019-12-25T00:29:58.95Z
        recordStatus      : Active
        identifiers       : {@{identifierID=5555; identifierType=Login; value=bobby.j; recordStatus=Active; source=}, @{identifierID=5556; identifierType=Login; value=bobby.j@example.com;
                            recordStatus=Active; source=}, @{identifierID=5557; identifierType=Login; value=bobby.j@demo.example.com; recordStatus=Active; source=}, @{identifierID=5558;
                            identifierType=Email; value=bobby.j@exampele.com; recordStatus=Active; source=}...}
        groups            : {@{name=Users}}
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $DisplayIdentifier,


        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Entity,


        [Parameter(
            Mandatory = $false, 
            ValueFromPipeline = $true, 
            Position = 3
        )]
        [string] $Identifier,


        [Parameter(Mandatory = $false, Position = 4)]
        [string] $RecordStatus,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('displayname','recordstatus', 'entity', 'displayidentifier', ignorecase=$true)]
        [string] $OrderBy = "Displayidentifier",


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet('asc','desc', ignorecase=$true)]
        [string] $Direction = "asc",


        [Parameter(Mandatory = $false, Position = 7)]
        [datetime] $DateUpdated,


        [Parameter(Mandatory = $false, Position = 8)]
        [switch] $ShowRetired = $false,


        [Parameter(Mandatory = $false, Position = 9)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 10)]
        [int] $PageValuesCount = 1000,


        [Parameter(Mandatory = $false, Position = 11)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 12)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Header
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            Code                  =   $null
            Type                  =   $null
            Raw                   =   $null
        }

        #region: Process Query Parameters
        $QueryParams = [Dictionary[string,string]]::new()

        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $PageValuesCount)

        # Query Offset - PageCount
        $Offset = ($PageCount -1) * $PageValuesCount
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if ($Name) {
            $QueryParams.Add("name", $Name)
        }

        # Filter Order of returned Object
        if ($OrderBy) {
            $QueryParams.Add("orderBy", $OrderBy)
        }

        # Filter by Object Display Identifier
        if ($DisplayIdentifier) {
            $QueryParams.Add("displayIdentifier", $DisplayIdentifier)
        }

        # Filter by Object Entity Id
        if ($Entity) {
            $QueryParams.Add("entity", $Entity)
        }

        # Filter by Object Identifier
        if ($Identifier) {
            $QueryParams.Add("identifier", $Identifier)
        }

        # Return results direction, ascending or descending
        if ($Direction) {
            $ValidStatus = "ASC", "DESC"
            if ($ValidStatus.Contains($($Direction.ToUpper()))) {
                if ($LrtConfig.LogRhythm.Version -match '7.[0-4].\d') {
                    if($Direction.ToUpper() -eq "ASC") {
                        $_direction = "asc"
                    } else {
                        $_direction = "desc"
                    }
                } else {
                    if($Direction.ToUpper() -eq "ASC") {
                        $_direction = "ascending"
                    } else {
                        $_direction = "descending"
                    }
                }
                $QueryParams.Add("dir", $_direction)
            }
        }


        # RecordStatus
        if ($RecordStatus) {
            $_recordStatus = $RecordStatus.ToLower()
            $QueryParams.Add("recordStatus", $_recordStatus)
        }

        if ($ShowRetired) {
            $QueryParams.Add("showRetired", $ShowRetired)
        }



        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }
        #endregion



        # Define Search URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/identities/" + $QueryString

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }


        # Check if pagination is required, if so - paginate!
        if ($Response.Count -eq $PageValuesCount) {
            DO {
                # Increment Page Count / Offset
                $PageCount = $PageCount + 1
                $Offset = ($PageCount -1) * $PageValuesCount
                # Update Query Paramater
                $QueryParams.offset = $Offset
                # Apply to Query String
                $QueryString = $QueryParams | ConvertTo-QueryString
                # Update Query URL
                $RequestUrl = $BaseUrl + "/lr-admin-api/identities/" + $QueryString
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if ($PaginationResults.Error) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $PageValuesCount)
        }

        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($Exact) {
            if ($Name) {
                $Pattern = "^$Name$"
                $Response | ForEach-Object {
                    if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                        Write-Verbose "[$Me]: Exact name match found."
                        return $_
                    }
                }
            }
            if ($Identifier) {
                $Pattern = "^$Identifier$"
                $Response | ForEach-Object {
                    ForEach ($IdIdentifier in $_.identifiers) {
                        if(($IdIdentifier.value -match $Pattern) -or ($IdIdentifier.value -eq $Identifier)) {
                            Write-Verbose "[$Me]: Exact identifier match found."
                            return $_
                        }
                    } 
                }
            }
        } else {
            return $Response
        }
    }

    End {
     }
}