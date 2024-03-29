using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrEntityDetails {
    <#
    .SYNOPSIS
        Retrieve the Entity Details for a specific LogRhythm Entity record.
    .DESCRIPTION
        Get-LrEntityDetails returns a full LogRhythm Entity object, including details.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [System.String] (Name or Int)
        Specifies a LogRhythm host object by providing one of the following property values:
          + List Name (as System.String), e.g. "MYSECRETHOST"
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .OUTPUTS
        PSCustomObject representing LogRhythm Entity record and its contents.
    .EXAMPLE
        PS C:\> Get-LrEntityDetails -Id 1      
        ---

        id               : 1
        name             : Primary Site
        fullName         : Primary Site
        recordStatusName : Active
        shortDesc        : This entity was created by the deployment wizard as a default Entity.  The name and properties can be changed.
        dateUpdated      : 2020-06-18T18:54:59.353Z
        childEntities    : {}
    .EXAMPLE
        Get-LrEntityDetails -Id "primary site"
        ---

        id               : 1
        name             : Primary Site
        fullName         : Primary Site
        recordStatusName : Active
        shortDesc        : This entity was created by the deployment wizard as a default Entity.  The name and properties can be changed.
        dateUpdated      : 2020-06-18T18:54:59.353Z
        childEntities    : {}
    .EXAMPLE
        Get-LrEntityDetails -Id "Primary ite"
        ---

        Code  : 404
        Error : True
        Type  : NoRecordFound
        Note  : Unable to locate exact Entity: Primary ite
        Value : Primary ite
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
            Raw                   =   $null
        }

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $Guid = $Id
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $EntityLookup = Get-LrEntities -Name $Id -Exact
            if ($EntityLookup.Error -eq $true) {
                $ErrorObject.Error = $EntityLookup.Error
                $ErrorObject.Type = $EntityLookup.Type
                $ErrorObject.Code = $EntityLookup.Code
                $ErrorObject.Note = $EntityLookup.Note
                return $ErrorObject
            } else {
                $Guid = $EntityLookup | Select-Object -ExpandProperty id
            }
        }

        
        $RequestUrl = $BaseUrl + "/lr-admin-api/entities/" + $Guid + "/"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Error Output - Used to support Pipeline Paramater ID
        Write-Verbose "[$Me]: Id: $Id - Guid: $Guid - ErrorStatus: $($ErrorObject.Error)"
        if ($ErrorObject.Error -eq $false) {
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
            if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
                return $Response
            }
        } else {
            return $ErrorObject
        }

        return $Response
    }

    End { }
}