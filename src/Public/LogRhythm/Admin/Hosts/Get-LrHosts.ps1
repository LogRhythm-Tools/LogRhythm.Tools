using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrHosts {
    <#
    .SYNOPSIS
        Retrieve a list of Hosts from the LogRhythm Entity structure.
    .DESCRIPTION
        Get-LrHosts returns a full LogRhythm Host object, including details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Name
        String used to search Entity Host records by Name.
    .PARAMETER Entity
        String used to search Entity Host by Entity Name.
    .PARAMETER RecordStatus
        String used to restrict results based on RecordStatus.
        Valid entries: All, Active, Retired
    .PARAMETER HostIdentifier
        Array of strings used to search for Host records based on Identifiers.

        Common Identifiers: IP Address, DNS Name, Hostname
    .PARAMETER Exact,
        Switch used to specify Name search for Entity Host record is explicit.
    .INPUTS
        [System.Int]           -> PageCount
        [System.String]        -> Name
        [System.String]        -> Entity
        [System.String]        -> RecordStatus
        [System.String[array]] -> HostIdentifier
        [System.Switch]        -> Exact
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        PS C:\> Get-LrHosts
        ---
        id                     : 2656
        entity                 : @{id=22; name=Primary Site}
        name                   : 10.5.5.20
        riskLevel              : None
        threatLevel            : None
        threatLevelComments    :
        recordStatusName       : Active
        hostZone               : Internal
        location               : @{id=-1}
        os                     : Unknown
        osVersion              : 0
        useEventlogCredentials : False
        osType                 : Other
        dateUpdated            : 2019-09-13T21:12:33.48Z

        id                     : 2657
        entity                 : @{id=22; name=Primary Site}
        name                   : MYSECRETHOST
        riskLevel              : Medium-High
        threatLevel            : High-Low
        threatLevelComments    :
        recordStatusName       : Active
        hostZone               : Internal
        location               : @{id=17813; name=New Mexico}
        os                     : Windows
        osVersion              : Microsoft Windows NT 10.0.14393.0
        useEventlogCredentials : False
        osType                 : Other
        dateUpdated            : 2019-12-02T18:25:28.203Z
    .EXAMPLE
        Get-LrHosts -name "windows"
        ---

        id                     : 2
        entity                 : @{id=1; name=Primary Site}
        name                   : WINdows-A10PJE5DII3.example.local
        riskLevel              : None
        threatLevel            : High-Low
        threatLevelComments    :
        recordStatusName       : Active
        hostZone               : Internal
        location               : @{id=29929; name=Spartanburg}
        os                     : Windows
        osVersion              : Microsoft Windows NT 10.0.14393.0
        useEventlogCredentials : False
        osType                 : Server
        dateUpdated            : 2020-06-18T23:10:55.1Z
        hostRoles              : {}
        hostIdentifiers        : {@{type=WindowsName; value=WIN-A10PJE5DII3; dateAssigned=2020-06-02T17:55:37.19Z}, @{type=IPAddress; value=192.168.2.127;
                                dateAssigned=2020-06-02T17:55:37.19Z}}
    .EXAMPLE
        Get-LrHosts -name "windows" -Exact 
        ---
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
        [string] $RecordStatus,


        [Parameter(Mandatory = $false, Position = 3)]
        [string[]] $HostIdentifier,


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
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
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
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
        }

        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $PageValuesCount)

        # Query Offset - PageCount
        $Offset = ($PageCount -1) * $PageValuesCount
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if ($Name) {
            $_name = $Name
            $QueryParams.Add("name", $_name)
        }



        # Filter by Object Entity Name
        if ($Entity) {
            $_entityName = $Entity
            $QueryParams.Add("entity", $_entityName)
        }

        if ($HostIdentifier) {
            ForEach ($Identifier in $HostIdentifier) {
                [string[]] $_hostIdentifier += $Identifier
            }
            if ($_hostIdentifier) {
                $QueryParams.Add("hostIdentifier", $_hostIdentifier)
            }
        }


        # RecordStatus
        if ($RecordStatus) {
            $ValidStatus = "all", "active", "retired"
            if ($ValidStatus.Contains($($RecordStatus.ToLower()))) {
                $_recordStatus = $RecordStatus.ToLower()
                $QueryParams.Add("recordStatus", $_recordStatus)
            } else {
                throw [ArgumentException] "RecordStatus [$RecordStatus] must be: all, active, or retired."
            }

        }



        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }
        #endregion

        $RequestUrl = $BaseUrl + "/hosts/" + $QueryString

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $ExceptionMessage
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
            } catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        }

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
                $RequestUrl = $BaseUrl + "/hosts/" + $QueryString
                # Retrieve Query Results
                try {
                    $PaginationResults = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
                } catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Code = $($Err.statusCode)
                    $ErrorObject.Note = $($Err.message)
                    return $ErrorObject
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $PageValuesCount)
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