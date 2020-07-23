using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Remove-LrTagsFromCase {
    <#
    .SYNOPSIS
        Remove tags to a LogRhythm case.
    .DESCRIPTION
        The Remove-LrTagsToCase cmdlet removes tags to an existing case.
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
        PS C:\> 
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
        [string[]] $Tags
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
        $IdInfo = Test-LrCaseIdFormat $Id
        if (! $IdInfo.IsValid) {
            throw [ArgumentException] "Parameter [Id] should be an RFC 4122 formatted string or an integer."
        }                                                        

        $RequestUrl = $BaseUrl + "/cases/$Id/actions/removeTags/"
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
            catch [System.Net.WebException] {
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
        
        return $Response
        #endregion
    }


    End { }
}