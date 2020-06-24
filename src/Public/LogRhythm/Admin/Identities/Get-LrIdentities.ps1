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
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $false, Position = 1)]
        [int]$PageValuesCount = 1000,

        [Parameter(Mandatory = $false, Position = 2)]
        [int]$PageCount = 1,

        [Parameter(Mandatory = $false, Position = 3)]
        [string]$Name,

        [Parameter(Mandatory = $false, Position = 4)]
        [string]$DisplayIdentifier,

        [Parameter(Mandatory = $false, Position = 5)]
        [string]$EntityId,

        [Parameter(Mandatory = $false, Position = 6)]
        [string]$Identifier,

        [Parameter(Mandatory = $false, Position = 7)]
        [string]$RecordStatus,

        [Parameter(Mandatory = $false, Position = 8)]
        [string]$OrderBy = "Displayidentifier",

        [Parameter(Mandatory = $false, Position = 9)]
        [datetime]$UpdatedBefore,

        [Parameter(Mandatory = $false, Position = 10)]
        [datetime]$UpdatedAfter,

        [Parameter(Mandatory = $false, Position = 11)]
        [switch]$ShowRetired = $false,

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

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
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
        if ($EntityId) {
            $QueryParams.Add("entity", $EntityId)
        }

        # Filter by Object Identifier
        if ($Identifier) {
            $QueryParams.Add("identifier", $Identifier)
        }


        # RecordStatus
        if ($RecordStatus) {
            $ValidStatus = "active", "retired"
            if ($ValidStatus.Contains($($RecordStatus.ToLower()))) {
                $_recordStatus = $RecordStatus.ToLower()
                $QueryParams.Add("recordStatus", $_recordStatus)
            } else {
                throw [ArgumentException] "RecordStatus [$RecordStatus] must be: active or retired."
            }
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
        $RequestUrl = $BaseUrl + "/identities/" + $QueryString

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $false
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
            }
            catch [System.Net.WebException] {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $false
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
        } else {
            return $Response
        }
     }
}