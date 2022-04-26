using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrList {
    <#
    .SYNOPSIS
        Retrieve the specified list from LogRhythm.
    .DESCRIPTION
        Get-LrList returns a full LogRhythm List object, including it's details and list items.
        [NOTE]: Due to the way LogRhythm REST API is built, if the specified MaxItemsThreshold
        is less than the number of actual items in the list, this cmdlet will return an http 400 error.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Name
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER MaxItemsThreshold
        The maximum number of list items to retrieve from LogRhythm.
        The default value for this parameter is set to 1001.
    .PARAMETER Exact
        Switch to force PARAMETER Name to be matched explicitly.
    .INPUTS
        The Name parameter can be provided via the PowerShell pipeline.
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List and its contents.
        If parameter ListItemsOnly is specified, a string collection is returned containing the
        list's item values.
    .EXAMPLE
        PS C:\> Get-LrList -Name "edea82e3-8d0b-4370-86f0-d96bcd4b6c19"
    .EXAMPLE
        PS C:\> Get-LrList -Name "Privileged Users: Local System Administrators" -Exact
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(1,10000000)]
        [int] $MaxItemsThreshold = 10000000,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $ValuesOnly,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 4)]
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
        $Headers.Add("maxItemsThreshold", $MaxItemsThreshold)

        # Define HTTP Method
        $Method = $HttpMethod.Get
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Value                 =   $Name
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Process Name Object
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
            $Guid = $Name.ToString()
        } else {
            if ($Exact) {
                $Guid = Get-LRListGuidByName -Name $Name.ToString() -Exact
            } else {
                $Guid = Get-LRListGuidByName -Name $Name.ToString()
            }
            if ($null -eq $Guid) {
                Return $null
            } elseif ($Guid.count -ge 2) {
                $ErrorObject.Error = $true
                $ErrorObject.Note = "List lookup returned an array of values.  Ensure the list referenced is unique."
                $ErrorObject.Raw = $Guid
                return $ErrorObject
            }
        }

        # Define HTTP URI
        $RequestUrl = $BaseUrl + "/lr-admin-api/lists/$Guid/"


        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }


        # Process Results
        if ($ValuesOnly) {
            $ReturnList = [List[string]]::new()
            $Response.items | ForEach-Object {
                $ReturnList.Add($_.value)
            }
            return $ReturnList
        }
        return $Response
    }

    End { }
}