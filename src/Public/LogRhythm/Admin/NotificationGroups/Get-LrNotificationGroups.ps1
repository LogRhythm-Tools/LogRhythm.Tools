using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrNotificationGroups {
    <#
    .SYNOPSIS
        Retrieve a list of Notification Groups based on filter criteria provided.
    .DESCRIPTION
        Get-LrNotificationGroups returns a full LogRhythm Notification Group object, including details and content items.
    .PARAMETER Name
        Filter to return contents for Notification Groups where the name contains the value provided by this property.  

        To enable this property to only provide results on explicit name matches please include the -exact paramater switch.
    .PARAMETER Id
        Filter to return contents for Notification Group(s) based on the Notification Group ID #.    

        This paramater supports a single or array of integer values.
    .PARAMETER OrderBy
        Sorts records by Name or Id #.

        Default behavior is to OrderBy Id #.
    .PARAMETER Direction
        Sorts records by ascending or descending.
    .PARAMETER Exact
        Switch used to specify Name value is explicit.  Only exact matches will be returned.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        Type                       Paramater Name
        [System.String]            Name 
        [System.Int32[Array]]      Id
        [System.String]            OrderBy
        [System.String]            Direction
        [System.Switch]            Exact
        [System.Int32]             PageCount
    .OUTPUTS
        System.Object

        Returns one or more LogRhythm Notification Group Objects.

        [LogRhythm.User]
        ---------------------------------------------------
        FieldName             Type               Description
        ---------------------------------------------------
        id                    [System.Int32]     The Notification Group ID #
        name                  [System.String]    The Notification Group Name
        dateUpdated           [System.Date]      Date/timestamp the Notification Group was last updated.
        shortDescription      [System.String]    The description field for a given Notification Group.
        recordStatusName      [System.String]    Current status of the Notification Group object.
        totalUsers            [System.Int32]     Total number of User Records associated with the Notification Group.
    .EXAMPLE
        Get-LrNotificationGroups

        name             : LRC Users
        id               : 3
        dateUpdated      : 5/10/2021 1:32:09 PM
        recordStatusName : Active
        totalUsers       : 1

        name             : Role Notification Group
        shortDescription : Global Administrators for Deployment.
        id               : 2
        dateUpdated      : 5/10/2021 1:20:52 PM
        recordStatusName : Active
        totalUsers       : 1

        name             : TAM Team
        shortDescription : The TAM team.
        id               : 1
        dateUpdated      : 5/10/2021 1:20:13 PM
        recordStatusName : Active
        totalUsers       : 6
    .EXAMPLE
        Get-LrNotificationGroups -Name "TAM Team" -Exact

        name             : TAM Team
        shortDescription : The TAM team.
        id               : 1
        dateUpdated      : 5/10/2021 1:20:13 PM
        recordStatusName : Active
        totalUsers       : 6
    .EXAMPLE
        Get-LrNotificationGroups -Id @(1, 2)

        name             : Role Notification Group
        shortDescription : Global Administrators for Deployment.
        id               : 2
        dateUpdated      : 5/10/2021 1:20:52 PM
        recordStatusName : Active
        totalUsers       : 1

        name             : TAM Team
        shortDescription : The TAM team.
        id               : 1
        dateUpdated      : 5/10/2021 1:20:13 PM
        recordStatusName : Active
        totalUsers       : 6
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
        [int[]] $Id,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidateSet('asc', 'desc', 'ascending', 'descending', ignorecase=$true)]
        [string] $Direction,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateSet('name','id', ignorecase=$true)]
        [string] $OrderBy = "id",

        
        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 5)]
        [int] $PageValuesCount = 1000,


        [Parameter(Mandatory = $false, Position = 6)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 7)]
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

        if ($Id) {
            $_id = [string]::Join(',', $Id)
            $QueryParams.Add("id", $_id)
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


        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/notification-groups/" + $QueryString

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Check if pagination is required, if so - paginate!
        if ($Response.Count -eq $PageValuesCount) {
            DO {
                # Increment Page Count / Offset
                #$PageCount = $PageCount + 1
                $Offset = $Offset + 1
                # Update Query Paramater
                $QueryParams.offset = $Offset
                # Apply to Query String
                $QueryString = $QueryParams | ConvertTo-QueryString
                # Update Query URL
                $RequestUrl = $BaseUrl + "/lr-admin-api/notification-groups/" + $QueryString

                Write-Verbose "[$Me]: Request URL: $RequestUrl"

                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if ($PaginationResults.Error) {
                    return $PaginationResults
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
            $Pattern1 = "^$Name$"
            $Response | ForEach-Object {
                if ($Name) {
                    if(($_.name -match $Pattern1) -or ($_.name -eq $Name)) {
                        Write-Verbose "[$Me]: Exact list name match found."
                        return $_
                    }
                }
            }
        } else {
            return $Response
        }
    }

    End { }
}