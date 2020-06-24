using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrLogSources {
    <#
    .SYNOPSIS
        Retrieve a list of accepted Log Sources from the LogRhythm.
    .DESCRIPTION
        Get-LrLogSources returns a list of accepted Log Sources, including details.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Name
        String used to search Entity Host records by Name.
    .PARAMETER Exact,
        Switch used to specify Name search for Entity Host record is explicit.
    .INPUTS

    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        PS C:\> Get-LrLogSources
        ----
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
        [ValidateSet('asc','desc', ignorecase=$true)]
        [string]$Direction,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('name','id', ignorecase=$true)]
        [string]$OrderBy = "name",

        [Parameter(Mandatory = $false, Position = 4)]
        [string]$Name,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('all','active','retired', ignorecase=$true)]
        [string]$RecordStatus = "active",

        [Parameter(Mandatory = $false, Position = 6)]
        [string]$Description,

        [Parameter(Mandatory = $false, Position = 7)]
        [Int32]$SystemMonitorId,

        [Parameter(Mandatory = $false, Position = 8)]
        [string]$Entity,

        [Parameter(Mandatory = $false, Position = 9)]
        [string]$MessageSourceTypeId,
        
        [Parameter(Mandatory = $false, Position = 10)]
        [bool]$Virtual = $false,

        [Parameter(Mandatory = $false, Position = 11)]
        [bool]$LoadBalanced = $false,

        [Parameter(Mandatory = $false, Position = 12)]
        [Int32]$HostId = $false,

        [Parameter(Mandatory = $false, Position = 13)]
        [switch]$Exact
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
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
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
            $_entityName = $Entity
            $QueryParams.Add("entity", $_entityName)
        }

        # Return results direction, ascending or descending
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
                    return "$(Get-Timestamp) Function Get-LrLogSources requires LogRhythm version 7.5.0+.  Set LogRhythm version in LR Tools Preferences."
                }
                $QueryParams.Add("dir", $_direction)
            } else {
                throw [ArgumentException] "Direction [$Direction] must be: asc or desc."
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

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/logsources/" + $QueryString

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch [System.Net.WebException] {
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
        if ($Response.Count -eq $_pageValueCount) {
            # Need to get next page results
            $CurrentPage = $PageCount + 1
            #return 
            Return $Response + (Get-LrLogSources -PageCount $CurrentPage) 
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