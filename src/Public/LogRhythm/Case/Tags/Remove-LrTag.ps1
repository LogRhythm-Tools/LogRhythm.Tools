using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Remove-LrTag {
    <#
    .SYNOPSIS
        Removes and deletes a tag for LogRhythm case use.  Tag will be removed from any case which it has been added.
    .DESCRIPTION
        The Remove-LrTag cmdlet deletes a tag from LogRhythm case management entirely.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        [String]   -> Tag
    .OUTPUTS
        PSCustomObject representing the modified LogRhythm Case.
    .EXAMPLE
        PS C:\> Remove-LrTag -Tag Peaches

    .EXAMPLE
        PS C:\> Remove-LrTag -Tag 1
        
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
            ValueFromPipeline = $true,
            Position = 1
        )]
        [ValidateNotNull()]
        [string] $Tag
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
        $Method = $HttpMethod.delete

        # Value Testing Paramater
        $_int = 0
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            ResponseUrl           =   $null
            Tag                   =   $Tag
        }
        #region: Process Tags                                                            
        # Request Body - Tags
        Write-Verbose "[$Me]: Validating Tags"


        if ([int]::TryParse($Tag, [ref]$_int)) {
            $_tagNumber = $Tag | Get-LrTag 
            if ($_tagNumber.number) {
                $_tagNumber = $_tagNumber | Select-Object -ExpandProperty number
            }
        } else {
            # Convert / Validate Tags to Tag Numbers array
            $_tagNumber = Get-LrTags -Name $Tag -Exact
            if ($_tagNumber.number) {
                $_tagNumber = $_tagNumber | Select-Object -ExpandProperty number
            }
        }

        if ($_tagNumber.error -eq $true) {
            Return $_tagNumber
        }

        # Create Body
        $Body = ([PSCustomObject]@{ number = $_tagNumber }) | ConvertTo-Json

        # Request URI
        $RequestUrl = $BaseUrl + "/tags/$_tagNumber/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"
        

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
        
        return $Response
        #endregion
    }

    End { }
}