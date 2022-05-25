using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrPlaybooks {
    <#
    .SYNOPSIS
        Return a list of playbooks.
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
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('dateCreated','dateUpdated','name')]
        [string] $OrderBy = "dateCreated",


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet('asc','desc')]
        [string] $Direction = "asc",


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 3)]
        [int] $Count = 500,


        [Parameter(Mandatory = $false, Position = 4)]
        [int] $PageNumber = 1,


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
        

        # Maximum results returned per API call before pagination required
        if ($Count) {
            $Headers.Add("count", $Count)
        } else {
            $Headers.Add("count", 500)
        }

        # Page requested via Offset for Results from API
        if ($PageNumber) {
            $Offset = ($PageNumber -1) * $Count
            $Headers.Add("offset", $Offset)
        }

        # Sort results by direction
        if ($Direction) {
            $Headers.Add("direction", $Direction)
        }

        # Arrange results by field
        if ($OrderBy) {
            $Headers.Add("orderBy", $OrderBy)
        }

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
            Playbook              =   $Name
            Raw                   =   $null
        }

        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/playbooks/?playbook=$Name"


        # REQUEST
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        # Pagination
        if ($Response.Count -eq $Count) {
            DO {
                # Increment Page Count / Offset
                $PageNumber = $PageNumber + 1
                $Offset = ($PageNumber -1) * $Count
                # Update Header Pagination Paramater
                $Headers.offset = $Offset
                
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if ($PaginationResults.Error) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $Count)
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