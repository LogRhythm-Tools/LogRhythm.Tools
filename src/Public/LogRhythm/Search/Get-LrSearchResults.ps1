using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrSearchResults {
    <#
    .SYNOPSIS
        Retrieve search results from the LogRhythm SIEM environment.  Requires LogRhythm 7.5.0+.
    .DESCRIPTION
        Create-LrNetwork returns a full LogRhythm Host object, including details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Entity
        Parameter for specifying the existing LogRhythm Entity for the new Network record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Network object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Network Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Name
        [System.String] Parameter for specifying a new network name.  
        
        *If the Id parameter is not provided the Name paramater will be attempted to identify the appropraite record.
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

    .INPUTS
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        PS C:\> New-LrSearch
        ----
        StatusCode      : 200
        StatusMessage   : Success
        ResponseMessage : Success
        TaskStatus      : Searching
        TaskId          : efaa62ab-84ed-4d9e-96a9-c280973c3307
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
        [string]$SearchGuid,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$Sort,

        [Parameter(Mandatory = $false,  Position = 3)]
        [string]$GroupBy = "",

        [Parameter(Mandatory = $false,  Position = 4)]
        [string]$Fields,

        [Parameter(Mandatory = $false,  Position = 5)]
        [string]$PageOrigin = 1,

        [Parameter(Mandatory = $false, Position = 6)]
        [string]$PageSize = 100
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.SearchBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post

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
            ResponseUrl           =   $null
            Value                 =   $Name
        }

        if ($QueryRawLog -eq $true) {
            $_queryRawLog = "true"
        } else {
            $_queryRawLog = "false"
        }

        if ($QueryEventManager -eq $true) {
            $_queryEventManager = "true"
        } else {
            $_queryEventManager = "false"
        }

        # Establish Body Contents
        $BodyContents = [PSCustomObject]@{
            data = @{
                searchGuid = $SearchGuid
                search = @{
                    sort = @()
                    groupBy = $GroupBy
                    fields = @()
                }
                paginator = @{
                    origin = $PageOrigin
                    page_size = $PageSize
                }
            }
        } | ConvertTo-Json -Depth 3

        Write-Host $BodyContents


        # Define Query URL
        $RequestUrl = $BaseUrl + "/actions/search-result"

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
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