using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrCaseTags {
    <#
    .SYNOPSIS
        Add tags to a LogRhythm case.
    .DESCRIPTION
        The Add-LrTagsToCase cmdlet adds tags to an existing case.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER Tags
        List of numeric tag identifiers.
    .PARAMETER Force
        Switch paramater that will force the creation of tags that have not been created before attempting to add to case.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
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
        RequestUrl : https://127.0.0.1:8501/lr-case-api/cases//actions/addTags/
        Tags        : {Alpha}
        Case        : 5
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
        [ValidateNotNullOrEmpty()]
        [switch] $Force,
        

        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru,


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
        

        $_int = 1

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
            Value                 =   $Tags
            Case                  =   $Id
        }
        Write-Verbose "[$Me]: Case Id: $Id"

        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }                                                   

        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/actions/addTags/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"
        #endregion



        #region: Process Tags                                                            
        # Request Body - Tags
        Write-Verbose "[$Me]: Validating Tags"
        $_tagNumbers = [list[int]]::new()
        # Convert / Validate Tags to Tag Numbers array
        ForEach ($CaseTag in $Tags) {
            $TagStatus = Get-LrTagNumber -Tag $CaseTag
            if (($Null -eq $TagStatus) -or ($TagStatus.Error -eq $true)) {
                # If force is enabled, create the tag
                if ($Force) {
                    Write-Verbose "$(Get-TimeStamp) Force Set - Creating Tag"
                    if (!([int]::TryParse($CaseTag, [ref]$_int))) {
                        $NewTagResults = New-LrTag -Tag $CaseTag -PassThru
                        if (($null -eq $NewTagResults.Error) -or ($NewTagResults.Error -eq "")) {
                            Write-Verbose "$(Get-TimeStamp) Adding new tag number: $($NewTagResults.number) to variable: _tags"
                            if ($_tagNumbers -notcontains $NewTagResults.number) {
                                $_tagNumbers.add($NewTagResults.number)
                            }
                        }
                    } else {
                        $ErrorObject.Code = "Value"
                        $ErrorObject.Error = $true
                        $ErrorObject.Type = "Type mismatch"
                        $ErrorObject.Note = "Request tag is integer.  New tags must be type String."
                        $ErrorObject.Value = $CaseTag
                        return $ErrorObject
                    }
                } else {
                    $ErrorObject.Code = "Value"
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "Missing tag"
                    $ErrorObject.Note = "Request tag does not exist.  Create tag or re-run with -force."
                    $ErrorObject.Value = $CaseTag
                    return $ErrorObject
                }
            } else {
                if ($_tagNumbers -notcontains $NewTagResults.number) {
                    $_tagNumbers.add($TagStatus)
                }
            }
        }
        

        # Create request body with tag numbers
        if (! ($_tagNumbers -Is [System.Array])) {
            # only one tag, use simple json
            $Body = ([PSCustomObject]@{ numbers = @($_tagNumbers) }) | ConvertTo-Json
        } else {
            # multiple values, create an object
            $Body = ([PSCustomObject]@{ numbers = $_tagNumbers }) | ConvertTo-Json
        }
        #endregion



        #region: Make Request                                                            
        Write-Verbose "[$Me]: request body is:`n$Body"

        # Make Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }
        
        # Only return the case if PassThru was requested.
        if ($PassThru) {
            return $Response    
        }
        #endregion
    }


    End { }
}