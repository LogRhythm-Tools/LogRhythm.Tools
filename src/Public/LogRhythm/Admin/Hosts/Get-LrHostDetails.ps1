using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrHostDetails {
    <#
    .SYNOPSIS
        Retrieve the Host Details from the LogRhythm Entity structure.
    .DESCRIPTION
        Get-LrHostDetails returns a full LogRhythm Host object, including details..
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [System.String] (Name or Int)
        Specifies a LogRhythm host object by providing one of the following property values:
          + List Name (as System.String), e.g. "MYSECRETHOST"
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .OUTPUTS
        PSCustomObject representing LogRhythm Entity Host record and its contents.
    .EXAMPLE
        PS C:\> Get-LrHostDetails -Credential $MyKey -Id "2657"
        ----
        id                     : 2657
        entity                 : @{id=22; name=Primary Site}
        name                   : MYSECRETHOST
        riskLevel              : Low-High
        threatLevel            : None
        threatLevelComments    :
        recordStatusName       : Active
        hostZone               : Internal
        location               : @{id=14813; name=New Mexico}
        os                     : Linux
        osVersion              : CentOS 6
        useEventlogCredentials : False
        osType                 : Other
        dateUpdated            : 2018-12-28T20:44:20.77Z
        hostRoles              : {}
        hostIdentifiers        : {@{type=IPAddress; value=10.1.1.5; dateAssigned=2019-12-28T19:59:28.56Z}}
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
            Error                 =   $false
            Value                 =   $Id
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
        }
        

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $Guid = $Id
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $Guid = Get-LrHosts -Name $Id -Exact | Select-Object -ExpandProperty id
            if (!$Guid) {
                $ErrorObject.Error = $true
                $ErrorObject.Note = "Id String [$Id] not found in LrHosts List."
            }
        }

        
        $RequestUrl = $BaseUrl + "/hosts/" + $Guid + "/"
        # Error Output - Used to support Pipeline Paramater ID
        Write-Verbose "[$Me]: Id: $Id - Guid: $Guid - ErrorStatus: $($ErrorObject.Error)"
        if ($ErrorObject.Error -eq $false) {
            # Send Request
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck 
                }
                catch {
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