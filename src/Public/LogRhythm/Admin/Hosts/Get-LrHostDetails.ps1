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
        PS C:\> Get-LrHostDetails -Id "2657"
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
    .EXAMPLE
        Get-LrHostDetails -Id "windows-a10pje5dii3.example.local"
        ---

        id                     : 2
        entity                 : @{id=1; name=Primary Site}
        name                   : WINdows-A10PJE5DII3.example.local
        riskLevel              : None
        threatLevel            : High-Low
        threatLevelComments    :
        recordStatusName       : Active
        hostZone               : Internal
        location               : @{id=29929; name=Spartanburg}
        os                     : Windows
        osVersion              : Microsoft Windows NT 10.0.14393.0
        useEventlogCredentials : False
        osType                 : Server
        dateUpdated            : 2020-06-18T23:10:55.1Z
        hostRoles              : {}
        hostIdentifiers        : {@{type=WindowsName; value=WIN-A10PJE5DII3; dateAssigned=2020-06-02T17:55:37.19Z}, @{type=IPAddress; value=192.168.2.127; 
                                dateAssigned=2020-06-02T17:55:37.19Z}}
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

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
            Raw                   =   $null
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
                $ErrorObject.Code = 404
                $ErrorObject.Raw = $Guid
                $ErrorObject.Note = "Id String [$Id] not found in LrHosts List."
                return $ErrorObject
            }
        }

        
        $RequestUrl = $BaseUrl + "/lr-admin-api/hosts/" + $Guid + "/"

        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        return $Response
    }

    End { }
}