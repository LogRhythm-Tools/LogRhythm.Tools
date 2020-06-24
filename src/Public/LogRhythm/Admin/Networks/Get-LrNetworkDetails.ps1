using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrNetworkDetails {
    <#
    .SYNOPSIS
        Retrieve the Network Details from the LogRhythm Entity structure.
    .DESCRIPTION
        Get-LrNetworkDetails returns a full LogRhythm Host object, including details.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [System.String] (Name or Int)
        Specifies a LogRhythm host object by providing one of the following property values:
          + List Name (as System.String), e.g. "MYSECRETHOST"
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .OUTPUTS
        PSCustomObject representing LogRhythm Entity Network record and its contents.
    .EXAMPLE
        PS C:\> Get-LrNetworkDetails -Credential $MyKey -Id "2657"
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

        [Parameter(Mandatory = $true, ValueFromPipeline=$true, Position = 1)]
        [ValidateNotNull()]
        [object] $Id
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Value Testing Paramater
        $_int = 0

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
            Value                 =   $Id
        }
        

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $Guid = $Id
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $NetworkLookup = Get-LrNetworks -Name $Id -Exact
            if ($NetworkLookup.Error -eq $true) {
                $ErrorObject.Error = $NetworkLookup.Error
                $ErrorObject.Type = $NetworkLookup.Type
                $ErrorObject.Code = $NetworkLookup.Code
                $ErrorObject.Note = $NetworkLookup.Note
                return $ErrorObject
            } else {
                $Guid = $NetworkLookup | Select-Object -ExpandProperty id
            }
        }

        
        $RequestUrl = $BaseUrl + "/networks/" + $Guid + "/"
        # Error Output - Used to support Pipeline Paramater ID
        Write-Verbose "[$Me]: Id: $Id - Guid: $Guid - ErrorStatus: $($ErrorObject.Error)"
        if ($ErrorObject.Error -eq $false) {
            # Send Request
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
                }
                catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Code = $($Err.statusCode)
                    $ErrorObject.Note = $($Err.message)
                    return $ErrorObject
                }
            } else {
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
                }
                catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Code = $($Err.statusCode)
                    $ErrorObject.Note = $($Err.message)
                    return $ErrorObject
                }
            }
        } else {
            return $ErrorObject
        }

        return $Response
    }

    End { }
}