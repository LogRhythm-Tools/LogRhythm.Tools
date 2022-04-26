using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCollaborators {
    <#
    .SYNOPSIS
        Return a list of collaborators.
    .DESCRIPTION
        The Get-LrCasePlaybooks cmdlet returns an object containing all the playbooks
        that has been assigned to a specific case.

        If a match is not found, this cmdlet will return null.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $SrfPreferences.LrDeployment.LrApiToken
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .INPUTS
        [System.Object]   ->  Id
    .OUTPUTS
        System.Object representing the returned LogRhythm playbooks on the applicable case.

        If a match is not found, this cmdlet will throw exception
        [System.Collections.Generic.KeyNotFoundException]
    .EXAMPLE
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
            Position = 0
        )]
        [ValidateNotNull()]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 2)]
        [int] $Count = 500,


        [Parameter(Mandatory = $false, Position = 3)]
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
        $Headers.Add("Content-Type","application/json")
        $Headers.Add("count", $Count)

        # Page requested via Offset for Results from API
        if ($PageNumber) {
            $Offset = ($PageNumber -1) * $Count
            $Headers.Add("offset", $Offset)
        }

        # Request Method
        $Method = $HttpMethod.Get
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # DueBefore
        if ($Name) {
            $_name = $Name
            $QueryParams.Add("name", $_name)
        }

        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }
        #endregion

        
        $RequestUrl = $BaseUrl + "/lr-case-api/collaborators/$QueryString"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # REQUEST
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        # Pagination
        if ($Response.Count -eq $Count) {
            DO {
                # Increment Page Count / Offset
                $PageNumber = $PageNumber + 1
                $Offset = ($PageNumber -1) * $Count
                # Update Header Pagination Paramater
                $Headers.offset = $Offset
                
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if ($PaginationResults.Error) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $Count)
        }

        # Return all responses.
        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($Exact) {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    return $_
                }
            }
        } else {
            return $Response
        }
    }


    End { }
}