using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrSearchResults {
    <#
    .SYNOPSIS
        Retrieve search results from the LogRhythm SIEM environment.  Requires LogRhythm 7.5.0+.
    .DESCRIPTION
        Get-LrSearchResults retrieves the search results from a previously submitted search request.

        To submit a new search request reference cmdlet: New-LrSearch.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.

        Note: You can bypass the need to provide a Credential by setting the preference 
        variable $LrtConfig.LogRhythm.ApiKey with a valid Api Token.
    .PARAMETER TaskId
        [System.String] Parameter for specifying the Search GUID returned from a successful New-LrSearch. 
    .PARAMETER Sort
        Currently not supported.  Cmdlet currently under development.
    .PARAMETER GroupBy
        Currently not supported.  Cmdlet currently under development.
    .PARAMETER Fields
        Currently not supported.  Cmdlet currently under development.
    .PARAMETER PageOrigin
        PageOrigin is utilized for paginating results.  Specifies the starting point for result retrieval.
    .PARAMETER PageSize
        PageSize is utilized as a part of paginating results.  Specifies the number of results returned per page.
    .OUTPUTS
        PSCustomObject representing the search request and the retrieved log results.
    .EXAMPLE
        PS C:\> Get-LrSearchResults -TaskId efaa62ab-84ed-4d9e-96a9-c280973c3307
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
        [string] $TaskId,

        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Sort,

        [Parameter(Mandatory = $false,  Position = 3)]
        [string] $GroupBy = "",

        [Parameter(Mandatory = $false,  Position = 4)]
        [string] $Fields,

        [Parameter(Mandatory = $false,  Position = 5)]
        [string] $PageOrigin = 1,

        [Parameter(Mandatory = $false, Position = 6)]
        [string] $PageSize = 100
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

        # Establish Body Contents
        $BodyContents = [PSCustomObject]@{
            data = @{
                searchGuid = $TaskId
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

        Write-Verbose $BodyContents


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