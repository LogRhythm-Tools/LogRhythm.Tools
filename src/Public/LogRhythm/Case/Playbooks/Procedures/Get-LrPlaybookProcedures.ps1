using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrPlaybookProcedures {
    <#
    .SYNOPSIS
        Return a list of playbook procedures.
    .DESCRIPTION
        The Get-LrPlaybooks cmdlet returns a list of playbooks, optionally filtered by 
        Playbook name. Resulted can be sorted by Creation Date, Updated Date, or Name, 
        in a Ascending or Descending order.
        If no playbooks are found, this cmdlet will return $null, not throw an exception.
        Note: This cmdlet does not support pagination.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Name
        Filter results that have a playbook name that contain the specified string.
        Use the -Exact switch to specify an explicit filter.
    .PARAMETER OrderBy
        Sorts the returned results by the specified field. Valid fields are 'dateCreated',
        'dateUpdated', and 'name'.
    .PARAMETER Sort
        Sort the returned playbooks ascending (asc) or descending (desc).
    .PARAMETER Exact
        Only return playbooks that match the provided playbook name exactly.
    .INPUTS
        System.String -> [Name] Parameter
    .OUTPUTS
        System.Object[] representing the returned LogRhythm playbooks.
        Returns $null if no playbooks are found based on Name filter.
    .EXAMPLE
        PS C:\> @("Testing","Malware") | Get-LrPlaybooks -Credential $Token
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
        PS C:\> @("Testing","Malware") | Get-LrPlaybooks -Credential $Token | Select-Object -ExpandProperty name
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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [string] $Name,


        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [ValidateSet('dateCreated','dateUpdated','name')]
        [string] $OrderBy = "dateCreated",


        [Parameter(
            Mandatory = $false,
            Position = 3
        )]
        [ValidateSet('asc','desc')]
        [string] $Sort = "asc",


        [Parameter(
            Mandatory = $false,
            Position = 4
        )]
        [switch] $Exact
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
        $Headers.Add("count", 500)
        $Headers.Add("orderBy", $OrderBy)
        $Headers.Add("direction", $Sort)
        

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
            ResponseUrl           =   $null
            Playbook              =   $Name
        }


        # Validate Playbook Id
        # Validate Playbook Ref
        $Guid = Test-Guid -Guid $Name
        if ($Guid -eq $true) {
            $Pb = Get-LrPlaybookById -Id $Name
            if ($Pb.Error -eq $true) {
                return $Pb
            }
        } else {
            $Pb = Get-LrPlaybooks -Name $Name -Exact
            if (!$Pb.Name -eq $Id) {
                $ErrorObject.Code = "404"
                $ErrorObject.Error = $true
                $ErrorObject.Type = "Null"
                $ErrorObject.Note = "Playbook does not exist."
                $ErrorObject.ResponseUrl = "$BaseUrl/playbooks/$($Pb.id)/"
                return $ErrorObject
            }
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/playbooks/$($Pb.id)/procedures/"


        # REQUEST
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
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
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
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
        
        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        # Note: Multiple exact matches would not be supported with this code.
        if ($Exact) {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact playbook name match found."
                    $Playbook = $_
                    return $Playbook
                }
            }
        }

        # for some reason, even if an exact playbook match is found, the function
        # will return it but KEEP RUNNING.
        if ($Exact -and (! $Playbook)) {
            $ErrorObject.Code = 404
            $ErrorObject.Type = "Object not found"
            $ErrorObject.Note = "Playbook not found"
            $ErrorObject.ResponseUrl = $RequestUrl
            $ErrorObject.Error = $true
            return $ErrorObject
        }

        # Return all responses.
        if (! $Playbook) {
            return $Response   
        }
    }


    End { }
}