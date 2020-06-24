using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrEntities {
    <#
    .SYNOPSIS
        Retrieve a list of Entities from LogRhythm's Entity structure.
    .DESCRIPTION
        Get-LrEntities returns a full LogRhythm Entity object, including it's details and list items.
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
    .PARAMETER ParentEntityId
        Filter results by ParentEntityId value.

        Int32
    .PARAMETER Exact
        Filter name results with explicit match.
    .OUTPUTS
        PSCustomObject representing LogRhythm Entity objects and their contents.
    .EXAMPLE
        PS C:\> Get-LrEntities
        ----
        id               : 3
        name             : EchoTestEntity
        fullName         : EchoTestEntity
        recordStatusName : Active
        shortDesc        : LogRhythm ECHO
        dateUpdated      : 2020-05-04T18:51:50.05Z

        id               : 6
        name             : ECTest1
        fullName         : ECTest1
        recordStatusName : Active
        shortDesc        : LogRhythm ECHO
        dateUpdated      : 2020-05-06T16:31:26.51Z
    .EXAMPLE
        PS C:\> Get-LrEntities -name "EchoTestEntity" -Exact
        ----
        id               : 3
        name             : EchoTestEntity
        fullName         : EchoTestEntity
        recordStatusName : Active
        shortDesc        : LogRhythm ECHO
        dateUpdated      : 2020-05-04T18:51:50.05Z
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

        [Parameter(Mandatory = $false, Position = 1)]
        [int]$PageValuesCount = 1000,

        [Parameter(Mandatory = $false, Position = 2)]
        [int]$PageCount = 1,

        [Parameter(Mandatory = $false, Position = 3)]
        [string]$Name,

        [Parameter(Mandatory = $false, Position = 4)]
        [int32]$ParentEntityId,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('name','id', ignorecase=$true)]
        [string]$OrderBy = "name",

        [Parameter(Mandatory = $false, Position = 11)]
        [ValidateSet('asc','desc', ignorecase=$true)]
        [string]$Direction = "asc",

        [Parameter(Mandatory = $false, Position = 12)]
        [switch]$Exact
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Header
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LogRhythm.Version

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Id
        }

        #region: Process Query Parameters
        $QueryParams = [Dictionary[string,string]]::new()

        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $PageValuesCount)

        # Query Offset - PageCount
        $Offset = ($PageCount -1) * $PageValuesCount
        $QueryParams.Add("offset", $Offset)

        # Direction
        if ($Direction) {
            $ValidStatus = "ASC", "DESC"
            if ($ValidStatus.Contains($($Direction.ToUpper()))) {
                if ($LrVersion -like "7.5.*") {
                    if($Direction.ToUpper() -eq "ASC") {
                        $_direction = "ascending"
                    } else {
                        $_direction = "descending"
                    }
                } else {
                    $_direction = $Direction.ToUpper()
                }
                $QueryParams.Add("dir", $_direction)
            } else {
                throw [ArgumentException] "Direction [$Direction] must be: asc or desc."
            }
        }

        # Filter by Object Name
        if ($Name) {
            $QueryParams.Add("name", $Name)
        }

        # Filter by Object Entity Id
        if ($ParentEntityId) {
            $QueryParams.Add("parentEntityId", $ParentEntityId)
        }

        # OrderBy
        if ($OrderBy) {
            $ValidStatus = "name", "id"
            if ($ValidStatus.Contains($($OrderBy.ToLower()))) {
                $_orderBy = $OrderBy.ToLower()
                $QueryParams.Add("orderBy", $_orderBy)
            } else {
                throw [ArgumentException] "OrderBy [$OrderBy] must be: name or id."
            }
        }


        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }
        #endregion



        # Define Search URL
        $RequestUrl = $BaseUrl + "/entities/" + $QueryString




        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
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
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
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
    }

    End {
        if ($Response.Count -eq $PageValuesCount) {
            # Need to get next page results
            $CurrentPage = $PageCount + 1
            #return 
            Return $Response + (Get-LrIdentities -PageCount $CurrentPage) 
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
            if (!$List) {
                $ErrorObject.Error = $true
                $ErrorObject.Type = "NoRecordFound"
                $ErrorObject.Code = 404
                $ErrorObject.Note = "Unable to locate exact Entity: $Name"
                $ErrorObject.Value = $Name
                return $ErrorObject
            }
        } else {
            return $Response
        }
     }
}