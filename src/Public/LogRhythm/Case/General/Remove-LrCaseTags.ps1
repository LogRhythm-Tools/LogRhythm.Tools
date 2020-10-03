using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Remove-LrCaseTags {
    <#
    .SYNOPSIS
        Remove tags to a LogRhythm case.
    .DESCRIPTION
        The Remove-LrCaseTags cmdlet removes tags to an existing case.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER Tags
        List of numeric tag identifiers.
    .INPUTS
        [System.Object]     ->  Id
        [System.Int32[]]  ->  TagNumbers
    .OUTPUTS
        PSCustomObject representing the modified LogRhythm Case.
    .EXAMPLE
        PS C:\> Remove-LrCaseTags -Id 2 -Tags Alpha
        ---

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T21:00:33.8159Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Mock case
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-10-20T14:22:11Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Mock case summary for automation validation.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {}

    .EXAMPLE
        PS C:\> Remove-LrCaseTags -Id "Mock case" -Tags Alpha
        ---

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T21:00:33.8159Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Mock case
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-10-20T14:22:11Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Mock case summary for automation validation.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {}
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

        
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Tags,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )


    Begin {
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")


        # Request URI
        $Method = $HttpMethod.Put
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            ResponseUrl           =   $null
            Tags                  =   $Tags
            Case                  =   $Id
        }
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]: Case Id: $Id"

        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }                                                  

        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/actions/removeTags/"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]: RequestUrl: $RequestUrl"
        #endregion



        #region: Process Tags                                                            
        # Request Body - Tags
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]: Validating Tags"

        # Convert / Validate Tags to Tag Numbers array
        $_tagNumbers = $Tags | Get-LrTagNumber
        if ($_tagNumbers.Error -eq $true) {
            return $_tagNumbers
        }

        # Create request body with tag numbers
        if (! ($_tagNumbers -Is [System.Array])) {
            # only one tag, use simple json
            $Body = "{ `"numbers`": [$_tagNumbers] }"
        } else {
            # multiple values, create an object
            $Body = ([PSCustomObject]@{ numbers = $_tagNumbers }) | ConvertTo-Json
        }
        #endregion



        #region: Make Request                                                            
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]: request body is:`n$Body"

        # Make Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
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
        
        return $Response
        #endregion
    }


    End { }
}