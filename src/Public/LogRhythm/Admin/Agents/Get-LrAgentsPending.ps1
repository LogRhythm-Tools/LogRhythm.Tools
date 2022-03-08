using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrAgentsPending {
    <#
    .SYNOPSIS
        Returns details of all pending Agents that match the specified criteria.
        
        This cmdlet is only available for LogRhythm SIEM's with version 7.5.0 and greater.
    .DESCRIPTION
        Get-LrAgentsPending returns a list of pending Agents, including details.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER OrderBy
        Sorts records by name or Id.
    .PARAMETER Direction
        Sorts records by ascending or descending.

        Valid values: "asc" "desc"
    .PARAMETER Name
        String used to search records by Name.
    .PARAMETER AgentLicenseType
        Filter based by license type.

        Valid values: "None" "SystemMonitorBasic" "SystemMonitor"
    .PARAMETER SearchScope
        Filters by search scope.

        Valid values: "SystemMonitorSearch" "ParentEntitySearch" "GlobalSearch"
    .PARAMETER Entity
        Parameter for specifying the existing LogRhythm Entity for the new Host record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Entity object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Segment Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Version
        The deployment version of the component.

        Version schema: (\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})
    .PARAMETER AgentType
        Filter results by type of agent.

        Valid values: "None" "Windows" "Linux" "Solaris" "Aix" "Hpux" "All"
    .PARAMETER LoadBalanced
        Filters results by load balanced status of component.

        Valid values: true, false
    .PARAMETER RecordStatus
        Filter records by object Record Status.

        Valid values: "all" "active" "retired"
    .PARAMETER FetchAIERecords
        Filters results by whether AIE records should be fetched.

        Valud values: true, false
    .PARAMETER Exact,
        Switch used to specify Name is explicit.
    .INPUTS

    .OUTPUTS
        PSCustomObject representing Accepted Agents and their contents.
    .EXAMPLE
        PS C:\> Get-LrAgentsPending
        ----
        
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
        [string] $Entity,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet('asc','desc', 'ascending', 'descending', ignorecase=$true)]
        [string] $Direction = "ascending",


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('name','id', ignorecase=$true)]
        [string] $OrderBy = "name",


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('all','pending','rejected', ignorecase=$true)]
        [string] $RecordStatus = "pending",


        [Parameter(Mandatory = $false, Position = 7)]
        [string] $Version,


        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateSet('none','windows', 'linux', 'solaris', 'aix', 'hpux', 'all', ignorecase=$true)]
        [string] $AgentType,
        

        [Parameter(Mandatory = $false, Position = 11)]
        [switch] $Exact,

                
        [Parameter(Mandatory = $false, Position = 12)]
        [int] $PageValuesCount = 1000,

        [Parameter(Mandatory = $false, Position = 13)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 14)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
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
        
        # Integer reference
        [int32] $_int = 0
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Verify version
        if ($LrtConfig.LogRhythm.Version -notmatch '7.[5-9].\d') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.5.0 and greater."

            return $ErrorObject
        }

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
        $Offset = ($PageCount -1) * $_pageValueCount
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
                Write-Verbose "[$Me]: Entity parses as integer."
                $EntityLookup = Get-LrEntityDetails -Id $Entity
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    $ErrorObject.Raw = $_
                    return $ErrorObject
                } else {
                    $_entity = $EntityLookup
                }
            } else {
                Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                $EntityLookup = Get-LrEntities -Name $Entity -Exact
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    $ErrorObject.Raw = $_
                    return $ErrorObject
                } else {
                    $_entity = $EntityLookup
                }
            }
            $QueryParams.Add("entity", $($_entity.Name))
        }

        # Return results direction, ascending or descending
        if ($Direction) {
            if($Direction.ToUpper() -eq "ASC") {
                $_direction = "ascending"
            } else {
                $_direction = "descending"
            }
            $QueryParams.Add("dir", $_direction)
        }

        # RecordStatus
        if ($AgentType) {
            $_agentType = (Get-Culture).TextInfo.ToTitleCase($AgentType)
            $QueryParams.Add("agentType", $_agentType)
        }

        # RecordStatus
        if ($RecordStatus) {
            $_recordStatus = $RecordStatus.ToLower()
            $QueryParams.Add("recordStatus", $_recordStatus)
        }

        # Version
        if ($Version) {
            [regex]$ValidStatus = "(\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})"
            if ($Version -match $ValidStatus) {
                $_version = $Version
                $QueryParams.Add("version", $_version)
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Type = "Format Error"
                $ErrorObject.Code = -1
                $ErrorObject.Note = "Provide version that meets regex: (\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})"
                $ErrorObject.Raw = "Provide version that meets regex: (\d[6-9]?).?((\d[0-9]?).?){0,2}(\d[0-9]{0,4})"
                return $ErrorObject
            }
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/agents-request/" + $QueryString

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
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
                $RequestUrl = $BaseUrl + "/lr-admin-api/agents/" + $QueryString
                # Retrieve Query Results
                try {
                    $PaginationResults = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
                } catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Code = $($Err.statusCode)
                    $ErrorObject.Note = $($Err.message)
                    $ErrorObject.Raw = $_
                    return $ErrorObject
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $PageValuesCount)
            $Response = $Response | Sort-Object -Property Id -Unique
        }

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

    End {
    }
}