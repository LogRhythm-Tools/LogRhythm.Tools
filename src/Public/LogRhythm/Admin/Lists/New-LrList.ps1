using namespace System
using namespace System.IO
using namespace System.Net
using namespace System.Collections.Generic

Function New-LrList {
    <#
    .SYNOPSIS
        Create a new List in the LogRhythm SIEM.
    .DESCRIPTION
        New-LrList creates a new list based on the paramaters provided.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Identity
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER Value
        The value to be added to the specified LogRhythm List Identity.
    .PARAMETER ItemType
        For use with Lists that support multiple item types.  Add-LrListItem will attempt to auto-define
        this value.  This parameter enables setting the ItemType.
    .PARAMETER LoadListItems
        LoadListItems adds the Items property to the return of the PSCustomObject representing the 
        specified LogRhythm List when an item is successfully added.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .INPUTS
        [System.Object] -> Name
        [System.String] -> Value     The Value parameter can be provided via the PowerShell pipeline.
        [System.String] -> ItemType
        [System.Switch] -> LoadListItems
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List.

        If a Value parameter error is identified, a PSCustomObject is returned providing details
        associated to the error.
    .EXAMPLE
       
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Name,


        [Parameter(Mandatory = $True, Position = 2)]
        [ValidateSet(
            'application',
            'classification', 
            'commonevent', 
            'host', 
            'location', 
            'msgsource', 
            'msgsourcetype', 
            'mperule', 
            'network', 
            'user', 
            'generalvalue', 
            'entity', 
            'rootentity', 
            'ip', 
            'iprange', 
            'identity', 
            'none', 
            ignorecase=$true
        )]
        [string] $ListType,


        [Parameter(Mandatory = $false, Position = 3)]
        [string] $ShortDescription,


        [Parameter(Mandatory = $false, Position = 4)]
        [string] $LongDescription,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet(
            'None', 
            'Address', 
            'DomainImpacted', 
            'Group', 
            'HostName', 
            'Message', 
            'Object', 
            'Process', 
            'Session', 
            'Subject', 
            'URL', 
            'User', 
            'VendorMsgID', 
            'DomainOrigin', 
            'Hash', 
            'Policy', 
            'VendorInfo', 
            'Result', 
            'ObjectType', 
            'CVE', 
            'UserAgent', 
            'ParentProcessId', 
            'ParentProcessName', 
            'ParentProcessPath', 
            'SerialNumber', 
            'Reason', 
            'Status', 
            'ThreatId', 
            'ThreatName', 
            'SessionType', 
            'Action', 
            'ResponseCode',
            'MACAddress',
            "ObjectName", 
            "UserAgent", 
            "Command",
            ignorecase=$true
        )]
        [string[]] $UseContext,


        [Parameter(Mandatory = $false, Position = 6)]
        [bool] $AutoImport = $false,


        [Parameter(Mandatory = $false, Position = 7)]
        [bool] $AutoImportPatterns = $false,


        [Parameter(Mandatory = $false, Position = 8)]
        [bool] $AutoImportReplaceExisting = $false,


        [Parameter(Mandatory = $false, Position = 9)]
        [string] $AutoImportFileName,

        [Parameter(Mandatory=$false, Position=11)]
        [ValidateSet('private','publicall', 'publicglobaladmin', 'publicglobalanalyst', 'publicrestrictedadmin', `
        'publicrestrictedanalyst', ignorecase=$true)]
        [string] $ReadAccess = "PublicGlobalAnalyst",

        [Parameter(Mandatory=$false, Position=12)]
        [ValidateSet('private','publicall', 'publicglobaladmin', 'publicglobalanalyst', 'publicrestrictedadmin', `
        'publicrestrictedanalyst', ignorecase=$true)]
        [string] $WriteAccess = "PublicGlobalAdmin",


        [Parameter(Mandatory = $false, Position = 12)]
        [bool] $RestrictedRead = $false,


        [Parameter(Mandatory = $false, Position = 13)]
        [ValidateLength(1,200)]
        [string] $EntityName = "Primary Site",


        [Parameter(Mandatory = $false, Position = 14)]
        [ValidateRange(1, 7862400)]
        [int] $TimeToLiveSeconds = $null,


        [Parameter(Mandatory = $false, Position = 15)]
        [bool] $NeedToNotify = $false,


        [Parameter(Mandatory = $false, Position = 16)]
        [bool] $DoesExpire = $false,


        [Parameter(Mandatory = $false, Position = 17)]
        [int64] $Owner,

                                
        [Parameter(Mandatory = $false, Position = 18)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 19)]
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
        

        # Request Setup
        $Method = $HttpMethod.Post
        $RequestUrl = $BaseUrl + "/lr-admin-api/lists/"

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Process Identity Object
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
            $Guid = $Name.ToString()
        } else {
            $GuidResults = Get-LRListGuidByName -Name $Name -Exact
            if ($GuidResults.Error -eq $true) {
                return $GuidResults
            } elseif ($GuidResults) {
                if (($GuidResults.GetType() -eq [System.Guid]) -Or (Test-Guid $GuidResults)) {
                    $Guid = $GuidResults.ToString()
                }
            }
        }

        # Validate List Type
        $ListTypes = @("Application", "Classification", "CommonEvent", "Host", "Location", "MsgSource", "MsgSourceType", "MPERule", "Network", "User", "GeneralValue", "Entity", "RootEntity", "IP", "IPRange", "Identity")
        if ($ListTypes -contains $ListType) {
            ForEach ($Type in $ListTypes) {
                if ($ListType -like $Type) {
                    # Set ListType to stored definition
                    $ListType = $Type
                }
            }
        }


        if ($UseContext) {
            $ValidContexts = @("None", "Address", "DomainImpacted", "Group", "HostName", "Message", "MACAddress", "Object", "Process", "Session", "Subject", "URL", "User", "VendorMsgID", "DomainOrigin", "Hash", "Policy", "VendorInfo", "Result", "ObjectType", "CVE", "UserAgent", "ParentProcessId", "ParentProcessName", "ParentProcessPath", "SerialNumber", "Reason", "Status", "ThreatId", "ThreatName", "SessionType", "Action", "ResponseCode", "ObjectName", "UserAgent", "Command")
            [string[]] $FinalContext = @()
            
            ForEach ($Context in $UseContext) {
                ForEach ($ValidContext in $ValidContexts) {
                    if ($Context -like $ValidContext) {
                        $FinalContext += $ValidContext
                    }
                }
            }
        }

        $ReadAccessLevels = @("Private", "PublicAll", "PublicGlobalAdmin", "PublicGlobalAnalyst", "PublicRestrictedAnalyst", "PublicRestrictedAdmin")
        if ($ReadAccessLevels -contains $ReadAccess) {
            ForEach ($AccessLevel in $ReadAccessLevels) {
                if ($ReadAccess -like $AccessLevel) {
                    # Set ReadAccess to stored definition
                    $ReadAccess = $AccessLevel
                }
            }
        }

        $WriteAccessLevels = @("Private", "PublicAll", "PublicGlobalAdmin", "PublicGlobalAnalyst", "PublicRestrictedAnalyst", "PublicRestrictedAdmin")
        if ($WriteAccessLevels -contains $WriteAccess) {
            ForEach ($AccessLevel in $WriteAccessLevels) {
                if ($WriteAccess -like $AccessLevel) {
                    # Set WriteAccess to stored definition
                    $WriteAccess = $AccessLevel
                }
            }
        }
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $null
            Type                  =   $null
            Note                  =   $null
            ListGuid              =   $Guid
            ListName              =   $Name
            FieldType             =   $ListType
            Raw                   =   $null
        }
        #$ExpDate = (Get-Date).AddDays(7).ToString("yyyy-MM-dd")

        if ($Owner) {
            $_owner = $Owner
        } else {
            $_owner = Get-LrApiTokenInfo | Select-Object -ExpandProperty UserId
        }

        # Request Body
        $BodyContents = [PSCustomObject]@{
            listType = $ListType
            status = "Active"
            name = $Name
            guid = $Guid
            shortDescription = $ShortDescription
            longDescription = $LongDescription
            autoImportOption = [PSCustomObject]@{
                enabled = $AutoImport
                usePatterns = $AutoImportPatterns
                replaceExisting = $AutoImportReplaceExisting
            }
            importFileName = $AutoImportFileName
            readAccess = $ReadAccess
            writeAccess = $WriteAccess
            restrictedRead = $RestrictedRead
            entityName = $EntityName
            needToNotify = $NeedToNotify
            doesExpire = $DoesExpire
            owner = $_owner
        }

        if ($ListType -eq "GeneralValue") {
            $BodyContents | Add-Member -MemberType NoteProperty -Name 'useContext' -Value @($FinalContext)
        }

        if ($DoesExpire -and !$TimeToLiveSeconds) {
            $ErrorObject.Error = $True
            $ErrorObject.Value = $Name
            $ErrorObject.Type = "Input.Validation"
            $ErrorObject.Note = "Does expire is set to true, requires input parameter TimeToLiveSeconds to be provided."
            $ErrorObject.FieldType = $ListType
        } elseif ($DoesExpire) {
            $BodyContents | Add-Member -MemberType NoteProperty -Name 'timeToLiveSeconds' -Value $TimeToLiveSeconds
        }
 

        $Body = $BodyContents | ConvertTo-Json -Depth 5 -Compress
        
        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"


        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
        
        if ($PassThru) {
            return $Response
        }
    }
    
    End { }
}