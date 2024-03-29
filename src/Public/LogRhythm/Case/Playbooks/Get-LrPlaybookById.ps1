using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrPlaybookById {
    <#
    .SYNOPSIS
        Get a LogRhythm playbook by its Id.
    .DESCRIPTION
        The Get-LrPlaybookById cmdlet returns a playbook by its Guid (RFC 4122)

        If a match is not found, this cmdlet will throw exception
        [System.Collections.Generic.KeyNotFoundException]
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the playbook, as an RFC 4122 formatted string.
    .INPUTS
        System.String -> [Id] Parameter
    .OUTPUTS
        System.Object representing the returned LogRhythm playbook.

        If a match is not found, this cmdlet will throw exception
        [System.Collections.Generic.KeyNotFoundException]
    .EXAMPLE
        PS C:\> Get-LrPlaybookById -Credential $Token -Id "F47CF405-CAEC-44BB-9FDB-644C33D58F2A"
        ---

        id            : F47CF405-CAEC-44BB-9FDB-644C33D58F2A
        name          : Testing
        description   : Test Playbook
        permissions   : @{read=privateOwnerOnly; write=privateOwnerOnly}
        owner         : @{number=35; name=Smith, Bob; disabled=False}
        retired       : False
        entities      : {@{number=1; name=Primary Site}}
        dateCreated   : 2019-10-11T08:46:25.9861938Z
        dateUpdated   : 2019-10-11T08:46:25.9861938Z
        lastUpdatedBy : @{number=35; name=Smith, Bob; disabled=False}
        tags          : {@{number=5; text=Malware}}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string] $Id,


        [Parameter(Mandatory = $false, Position = 1)]
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
        

        # Request Method
        $Method = $HttpMethod.Get
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Name
            Raw                   =   $null
        }
        
        # Validate Playbook Id
        if (! (Test-Guid $Id)) {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "TypeMismatch"
            $ErrorObject.Note = "Id should be an RFC 4122 formatted string."
            $ErrorObject.Value = $Id
            return $ErrorObject
        }

        
        $RequestUrl = $BaseUrl + "/lr-case-api/playbooks/$Id/"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # REQUEST
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Return all responses.
        return $Response
    }


    End { }
}