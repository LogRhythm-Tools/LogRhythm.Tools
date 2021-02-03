using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrLists {
    <#
    .SYNOPSIS
        Retrieve a list of lists from LogRhythm.
    .DESCRIPTION
        Get-LrList returns a full LogRhythm List object, including it's details and list items.

        [NOTE]: Due to the way LogRhythm REST API is built, if the specified MaxItemsThreshold
        is less than the number of actual items in the list, this cmdlet will return an http 400 error.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Name
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER MaxItemsThreshold
        The maximum number of list items to retrieve from LogRhythm.
        The default value for this parameter is set to 1001.
    .PARAMETER Exact
        Switch to force PARAMETER Name to be matched explicitly.
    .INPUTS
        The Name parameter can be provided via the PowerShell pipeline.
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List and its contents.

        If parameter ListItemsOnly is specified, a string collection is returned containing the
        list's item values.
    .EXAMPLE
        PS C:\> Get-LrList -Name "LR Threat List : URL : Attack"
        ---
        listType         : GeneralValue
        status           : Active
        name             : LR Threat List : URL : Attack
        useContext       : {URL, DomainImpacted}
        autoImportOption : @{enabled=False; usePatterns=False; replaceExisting=False}
        id               : -2208
        guid             : 7A5C7812-0BA9-4C9F-B4D3-09DC5FA79ACA
        dateCreated      : 2014-06-04T20:10:09.3Z
        dateUpdated      : 2020-07-23T19:47:12.61Z
        readAccess       : PublicAll
        writeAccess      : PublicGlobalAdmin
        restrictedRead   : False
        entityName       : Global Entity
        entryCount       : 0
        needToNotify     : False
        doesExpire       : False
        owner            : -1000000
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Name,

        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet(
            'application',
            'classification', 
            'commonevent',
            'host',
            'location',
            'msgsource',
            'msgsourcetype',
            'mperule',
            'network',
            'user',
            'generalvalue',
            'entity',
            'rootentity',
            'ip',
            'iprange',
            'identity',
            'none',
            ignorecase=$true
        )]
        [string] $ListType,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $Exact,

        
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(1,1000)]
        [int] $PageSize = 1000,


        [Parameter(Mandatory = $false, Position = 4)]
        [int] $PageNumber = 1,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )
                                                                    
    Begin {
        # Request Setup
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Validate ListType
        if ($ListType) {
            $ListTypeInfo = Test-LrListType -Id $ListType
            if ($ListTypeInfo.IsValid -eq $true) {
                $ListTypeValid = $ListTypeInfo.Value
            } else {
                throw [ArgumentException] 'Parameter [ListType] must be a valid LogRhythm List type.'
            }
        }

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Number of Results returned per API Call
        if ($PageSize) {
            $Headers.Add("pageSize", $PageSize)
        }

        # Page requested for Results from API
        if ($PageNumber) {
            $Headers.Add("PageNumber", $PageNumber)
        }

        if ($ListTypeValid) { 
            $Headers.Add("listType", $ListTypeValid)
        }

        # Define HTTP Method
        $Method = $HttpMethod.Get
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "/lists/"

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Define ErrorObject
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }


        if ($Name) {
            $Headers.Add("name", $Name)
        }

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

        # Pagination
        if ($Response.Count -eq $PageSize) {
            DO {
                # Increment Page Count / Offset
                $PageNumber = $PageNumber + 1
                $Offset = ($PageNumber -1) * $PageSize
                # Update Header Pagination Paramater
                $Headers.PageNumber = $Offset
                
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
            } While ($($PaginationResults.Count) -eq $PageSize)
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

    End { }
}