using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrUsers {
    <#
    .SYNOPSIS
        Return a list of users.
    .DESCRIPTION
        The Get-LrUser cmdlet returns a list of LogRhythm users that are
        referenced as collaborators or for notifications.  Results will be sorted
        alphabetically ascending, unless the OrderBy parameter is set to "desc".

        Note: This cmdlet does not support pagination.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Name
        Filter results that have a user name that contains the specified string value.
        Use the -Exact switch for an explicit filter.
    .PARAMETER OnlyUsers
        Filter results to only users that have a login.
    .PARAMETER Sort
        Sort the results in ascending (asc) or descending (desc) order.
    .PARAMETER Exact
        Only return tags that match the provided tag name exactly.
    .INPUTS
        System.String value -> Name parameter
    .OUTPUTS
        System.Object

        Returns one or more LogRhythm User Objects.

        [LogRhythm.User]
        ---------------------------------------------------
        FieldName       Type                Description
        ---------------------------------------------------
        number          [System.Int32]      User ID
        name            [System.String]     User Full Name
        disabled        [System.Boolean]    True if user is disabled
    .EXAMPLE
        PS C:\> 
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $OnlyUsers,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet('asc','desc')]
        [string] $Direction = "asc",


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 3)]
        [int] $Count = 500,


        [Parameter(Mandatory = $false, Position = 4)]
        [int] $PageNumber = 1,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        
        
        # Maximum results returned per API call before pagination required
        if ($Count) {
            $Headers.Add("count", $Count)
        } else {
            $Headers.Add("count", 500)
        }

        # Page requested via Offset for Results from API
        if ($PageNumber) {
            $Offset = ($PageNumber -1) * $Count
            $Headers.Add("offset", $Offset)
        }

        if ($Direction) {
            $Headers.Add("direction", $Direction)
        }


        # Request Method
        $Method = $HttpMethod.Get
    }


    Process {
        # Transform OnlyUsers switch into a boolean
        # Note: Omitting OnlyUsers is the same as setting OnlyUsers to "false" as 
        # far as the LogRhythm API handles it.
        $OnlyUsers = $false
        if ($PSBoundParameters.ContainsKey("OnlyUsers")) {
            $OnlyUsers = $true
        }


        # Form Query String
        $Params = [PSCustomObject]@{
            name = $Name
            onlyUsers = $OnlyUsers
        } | ConvertTo-QueryString


        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/persons/" + $Params

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # REQUEST
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }


        # Pagination
        if ($Response.Count -eq $Count) {
            Write-Verbose "[$Me]: Begin Pagination"
            DO {
                # Increment Page Count / Offset
                $PageNumber = $PageNumber + 1
                $Offset = ($PageNumber -1) * $Count
                # Update Header Pagination Paramater
                $Headers.offset = $Offset
                Write-Verbose "[$Me]: Request URL: $RequestUrl"
                
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if (($null -ne $PaginationResults.Error) -and ($PaginationResults.Error -eq $true)) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $Count)
            Write-Verbose "[$Me]: End Pagination"
        }


        # [Exact] Parameter
        # Search "Smith, Bob" normally returns both "Smith, Bob" and "Smith, Bob Admin".
        if ($Exact) {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if($_.name -match $Pattern) {
                    return $_
                }
            }
            # No exact matches found
            return $null
        }

        # Return all responses.
        return $Response
    }


    End { }
}