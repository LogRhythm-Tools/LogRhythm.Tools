using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrCaseTags {
    <#
    .SYNOPSIS
        Add tags to a LogRhythm case.
    .DESCRIPTION
        The Add-LrTagsToCase cmdlet adds tags to an existing case.
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
        PS C:\> Add-LrCaseTags -Id "alpha case" -Tags Alpha

    .EXAMPLE
        PS C:\> Add-LrCaseTags -Id "alpha case" -Tags Alpha -PassThru

        id                      : 56C2007B-4E8D-41C8-95C8-4F91346EC727
        number                  : 1
        externalId              :
        dateCreated             : 2020-07-16T16:46:48.3522746Z
        dateUpdated             : 2020-07-16T16:53:46.0262639Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Alpha Case
        status                  : @{name=Created; number=1}
        priority                : 4
        dueDate                 : 2020-07-17T16:46:48.3362732Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Alpha case is the first case created through API.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {@{number=2; text=Alpha}}
    .EXAMPLE
        PS C:\> Add-LrCaseTags -Id 2 -Tags Alpha -PassThru

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T16:56:27.8545625Z
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
        tags                    : {@{number=2; text=Alpha}}
    .EXAMPLE
        PS C:\> Add-LrCaseTags -Id 5 -Tags Alpha -PassThru

        Code        : 404
        Error       : True
        Type        : WebException
        Note        : Not Found
        ResponseUrl : https://127.0.0.1:8501/lr-case-api/cases//actions/addTags/
        Tags        : {Alpha}
        Case        : 5
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


        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNull()]
        [object] $Id,

        
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNull()]
        [string[]] $Tags,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
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
        Write-Verbose "[$Me]: Case Id: $Id"

# Get Case Id
        # Test CaseID Format
        $IdFormat = Test-LrCaseIdFormat $Id
        if ($IdFormat.IsGuid -eq $True) {
            # Lookup case by GUID
            try {
                $Case = Get-LrCaseById -Id $Id
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
            # Set CaseNum
            $CaseNumber = $Case.number
        } elseif(($IdFormat.IsGuid -eq $False) -and ($IdFormat.ISValid -eq $true)) {
            # Lookup case by Number
            try {
                $Case = Get-LrCaseById -Id $Id
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
            # Set CaseNum
            $CaseNumber = $Case.number
        } else {
            # Lookup case by Name
            try {
                $Case = Get-LrCases -Name $Id -Exact
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
            # Set CaseNum
            $CaseNumber = $Case.number
        }                                                      

        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/actions/addTags/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"
        #endregion



        #region: Process Tags                                                            
        # Request Body - Tags
        Write-Verbose "[$Me]: Validating Tags"

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
        Write-Verbose "[$Me]: request body is:`n$Body"

        # Make Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
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
        }
        
        # Only return the case if PassThru was requested.
        if ($PassThru) {
            return $Response    
        }
        #endregion
    }


    End { }
}