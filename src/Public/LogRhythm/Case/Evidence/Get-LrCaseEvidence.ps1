using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCaseEvidence {
    <#
    .SYNOPSIS
        Return a list of playbooks.
    .DESCRIPTION
        The Get-LrPlaybooks cmdlet returns a list of playbooks, optionally filtered by 
        Playbook name. Resulted can be sorted by Creation Date, Updated Date, or Name, 
        in a Ascending or Descending order.
        If no playbooks are found, this cmdlet will return $null, not throw an exception.
        Note: This cmdlet does not support pagination.
    .PARAMETER Id
        The Id of the case for which to retrieve Case Evidence from.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        System.String -> [Name] Parameter
    .OUTPUTS
        System.Object[] representing the returned LogRhythm playbooks.
        Returns $null if no playbooks are found based on Name filter.
    .EXAMPLE
        PS C:\> Get-LrPlaybooks -Name "Newer"
        ---

        id            : 23F49972-166C-4B9E-9232-352FF16ACE0C
        name          : Newer Playbook
        description   : Its pretty good.
        permissions   : @{read=privateOwnerOnly; write=privateOwnerOnly}
        owner         : @{number=-100; name=LogRhythm Administrator; disabled=False}
        retired       : False
        entities      : {@{number=1; name=Primary Site; fullName=Primary Site}}
        dateCreated   : 2020-06-07T12:50:58.4124223Z
        dateUpdated   : 2020-06-07T12:50:58.4124223Z
        lastUpdatedBy : @{number=-100; name=LogRhythm Administrator; disabled=False}
        tags          : {@{number=9; text=abc}}
    .EXAMPLE
        PS C:\> @("Testing","Malware") | Get-LrPlaybooks
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

        id            : BC3B367A-28CB-4E65-BE74-3B4ED5077976
        name          : Malware Incident
        description   : Use this Playbook when responding to malicious events that use an exploit.
        permissions   : @{read=publicAllUsers; write=publicGlobalAdmin}
        owner         : @{number=35; name=Smith, Bob; disabled=False}
        retired       : False
        entities      : {@{number=1; name=Primary Site}}
        dateCreated   : 2019-04-10T15:27:54.1499666Z
        dateUpdated   : 2019-09-11T14:30:53.1726298Z
        lastUpdatedBy : @{number=35; name=Smith, Bob; disabled=False}
        tags          : {@{number=66; text=ATP}, @{number=5; text=Malware}}
    .EXAMPLE 
        PS C:\> @("Testing","Malware") | Get-LrPlaybooks | Select-Object -ExpandProperty name
        --- 

        Testing
        Malware
        Malware 2
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
            Position = 0)]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(
            Mandatory = $false, 
            ValueFromPipeline = $true,
            Position = 1)]
        [ValidateSet('alarm', 'userEvents', 'log', 'note', 'file', ignorecase=$true)]
        [string[]] $Type,


        [Parameter(
            Mandatory = $false, 
            ValueFromPipeline = $true,
            Position = 2)]
        [ValidateSet('pending', 'completed', 'failed', ignorecase=$true)]
        [string[]] $Status,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
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

        # Request Method
        $Method = $HttpMethod.Get
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Case                  =   $Id
            Code                  =   $null
            Error                 =   $false
            Note                  =   $null
            Type                  =   $null
            Raw                   =   $null
        }

        $QueryParams = [Dictionary[string,string]]::new()

        # Type
        if ($Type) {
            $QueryParams.Add("type", $Type)
        }

        # Status
        if ($Status) {
            $QueryParams.Add("status", $Status)
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/cases/$Id/evidence/" + $QueryString


        # REQUEST
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Error = $true
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        
        return $Response   

    }


    End { }
}