using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCaseHistory {
    <#
    .SYNOPSIS
        Return history for a specific case. 
    .DESCRIPTION
        The Get-LrCaseHistory cmdlet returns the LogRhythm Case history of actions taken specified by the ID parameter.  
        
        Supports pagination.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER CreatedAfter
        Filter results that were created after the specified date.
    .PARAMETER CreatedBefore
        Filter results that were created before the specified date.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        System.Object -> Id
    .OUTPUTS
        PSCustomObject representing the LogRhythm Case History.
    .EXAMPLE
        PS C:\> Get-LrCaseHistory -Id 1785

        id        : 0897FB33-7833-4DB4-8AB3-C706E5176262
        date      : 2021-05-26T18:16:39.8498425Z
        actor     : @{number=6; name=Hart, Eric AD; disabled=False}
        action    : AddCollaborators
        resources : {@{id=73AF2C25-2C92-46D8-9BB5-D743490A8DB2; type=Case; displayName=AIE: Test Rule - Calc.exe (scott@mdstainless.com, bad password, external); properties=System.Object[]}, @{id=Person:1; type=Person; displayName=Hart, Eric;
                    properties=System.Object[]}}

        id        : 990019B1-F31B-4254-99BA-25935622C91F
        date      : 2021-05-26T18:16:39.7778227Z
        actor     : @{number=6; name=Hart, Eric AD; disabled=False}
        action    : AddPlaybook
        resources : {@{id=73AF2C25-2C92-46D8-9BB5-D743490A8DB2; type=Case; displayName=AIE: Test Rule - Calc.exe (scott@mdstainless.com, bad password, external); properties=System.Object[]}, @{id=6F0A00CD-E03E-4552-B04F-BCDDD4DB60A1; type=PlaybookOnCase;
                    displayName=Unauthorized Access; properties=System.Object[]}}

        id        : 50F9803D-4783-4FA4-BFE7-E3C8EE42EE09
        date      : 2021-05-26T18:16:39.722798Z
        actor     : @{number=6; name=Hart, Eric AD; disabled=False}
        action    : AddPlaybook
        resources : {@{id=73AF2C25-2C92-46D8-9BB5-D743490A8DB2; type=Case; displayName=AIE: Test Rule - Calc.exe (scott@mdstainless.com, bad password, external); properties=System.Object[]}, @{id=ECD8E71E-D439-4604-8D96-8C0EEDFEE154; type=PlaybookOnCase;
                    displayName=Phishing; properties=System.Object[]}}

        id        : D2453902-1B3D-4DE0-81E7-9976EA2C3A8B
        date      : 2021-05-26T18:16:39.6277454Z
        actor     : @{number=6; name=Hart, Eric AD; disabled=False}
        action    : CreateAlarmEvidence
        resources : {@{id=73AF2C25-2C92-46D8-9BB5-D743490A8DB2; type=Case; displayName=AIE: Test Rule - Calc.exe (scott@mdstainless.com, bad password, external); properties=System.Object[]}, @{id=Evidence:584; type=AlarmEvidence; displayName=; retired=False;
                    properties=System.Object[]}}

        id        : 3BA17320-D652-422B-8423-C6FE57C1B9E8
        date      : 2021-05-26T18:16:39.563742Z
        actor     : @{number=6; name=Hart, Eric AD; disabled=False}
        action    : CreateCase
        resources : {@{id=73AF2C25-2C92-46D8-9BB5-D743490A8DB2; type=Case; displayName=AIE: Test Rule - Calc.exe (scott@mdstainless.com, bad password, external); properties=System.Object[]}, @{id=Entity:-100; type=Entity; displayName=Global Entity;
                    properties=System.Object[]}}
            
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 0
        )]
        [ValidateNotNull()]
        [object] $Id,

        [Parameter(Mandatory = $false,Position = 1)]
        [DateTime] $CreatedAfter,


        [Parameter(Mandatory = $false,Position = 2)]
        [DateTime] $CreatedBefore,

        [Parameter(Mandatory = $false,Position = 3)]
        [ValidateSet("asc","desc")]
        [string] $Direction = "desc",


        [Parameter(Mandatory = $false, Position = 4)]
        [int] $Count = 500,


        [Parameter(Mandatory = $false, Position = 5)]
        [int] $PageNumber = 1,


        [Parameter(Mandatory = $false, Position = 6)]
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

        $Headers.Add("direction", $Direction)


        # Request URI
        $Method = $HttpMethod.Get

        # https://docs.microsoft.com/en-us/dotnet/api/system.int32.tryparse
        $_int = 0
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Id
            Raw                   =   $null
        }

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
        } elseif (($Id -Is [System.Guid]) -Or (Test-Guid $Id)) {
            Write-Verbose "[$Me]: Id parses as GUID."
        } else {
            $ErrorObject.Error = $true
            $ErrorObject.Type  = "DataType"
            $ErrorObject.Note  = "Id does not parse as integer or GUID."
            return $ErrorObject
        }

        # Update / Create DateTimes
        if ($UpdatedAfter) {
            $_updatedAfter = $UpdatedAfter | ConvertTo-Rfc3339
            $Headers.Add("updatedAfter", $_updatedAfter)
        }
        if ($UpdatedBefore) {
            $_updatedBefore = $UpdatedBefore | ConvertTo-Rfc3339
            $Headers.Add("updatedBefore", $_updatedBefore)
        }
        if ($CreatedAfter) {
            $_createdAfter = $CreatedAfter | ConvertTo-Rfc3339
            $Headers.Add("createdAfter", $_createdAfter)
        }
        if ($CreatedBefore) {
            $_createdBefore = $CreatedBefore | ConvertTo-Rfc3339
            $Headers.Add("createdBefore", $_createdBefore)
        }
        #endregion
        
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$Id/history/"

        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            switch ($Err.statusCode) {
                "404" {
                    $ErrorObject.Type = "KeyNotFoundException"
                    $ErrorObject.Code = 404
                    $ErrorObject.Note = "Value not found, or you do not have permission to view it."
                    }
                    "401" {
                    $ErrorObject.Type = "UnauthorizedAccessException"
                    $ErrorObject.Code = 401
                    $ErrorObject.Note = "Credential '$($Credential.UserName)' is unauthorized to access 'lr-case-api'"
                    }
                Default {
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Note = $Err.message
                }
            }
            $ErrorObject.Raw = $_
            return $ErrorObject
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
            } While ($($PaginationResults.Count) -eq $Count)
        }

        return $Response
    }


    End { }
}