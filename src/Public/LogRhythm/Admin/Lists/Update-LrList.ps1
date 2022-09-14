using namespace System
using namespace System.IO
using namespace System.Net
using namespace System.Collections.Generic
Function Update-LrList {
    <#
    .SYNOPSIS
        Update an existing List in the LogRhythm SIEM.
    .DESCRIPTION
        Update-LrList creates a new list based on the paramaters provided.
    .PARAMETER Guid
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER Name
        The value to be added to the specified LogRhythm List Identity.
    .PARAMETER ItemType
        For use with Lists that support multiple item types.  Add-LrListItem will attempt to auto-define
        this value.  This parameter enables setting the ItemType.
    .PARAMETER LoadListItems
        LoadListItems adds the Items property to the return of the PSCustomObject representing the 
        specified LogRhythm List when an item is successfully added.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
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
        [Parameter(Mandatory = $False, valuefrompipelinebypropertyname = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Name,


        [Parameter(Mandatory = $True, valuefrompipelinebypropertyname = $true, Position = 1)]
        [ValidateNotNull()]
        [String] $Guid,


        [Parameter(Mandatory = $False, valuefrompipelinebypropertyname = $true, Position = 2)]
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
            ignorecase=$true)]
        [string] $ListType,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 3)]
        [string] $ShortDescription,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 4)]
        [string] $LongDescription,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 5)]
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
            ignorecase=$true)]
        [string[]] $UseContext,


        [Parameter(Mandatory=$false, valuefrompipelinebypropertyname = $true, Position=6)]
        [ValidateSet('active', 'retired', ignorecase=$true)]
        [string] $Status,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 7)]
        [bool] $AutoImport,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 8)]
        [bool] $AutoImportPatterns,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 9)]
        [bool] $AutoImportReplaceExisting,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 10)]
        [string] $AutoImportFileName,

        [Parameter(Mandatory=$false, valuefrompipelinebypropertyname = $true, Position=11)]
        [ValidateSet('private', 'publicall', 'publicglobaladmin', 'publicglobalanalyst', 'publicrestrictedadmin', 'publicrestrictedanalyst', ignorecase=$true)]
        [string] $ReadAccess,


        [Parameter(Mandatory=$false, valuefrompipelinebypropertyname = $true, Position=12)]
        [ValidateSet('private', 'publicall', 'publicglobaladmin', 'publicglobalanalyst', 'publicrestrictedadmin', 'publicrestrictedanalyst', ignorecase=$true)]
        [string] $WriteAccess,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 13)]
        [bool] $RestrictedRead,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 14)]
        [ValidateLength(3,200)]
        [string] $EntityName,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 15)]
        [int] $TimeToLiveSeconds,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 16)]
        [bool] $NeedToNotify,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 17)]
        [bool] $DoesExpire,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 18)]
        [int64] $Owner,

                                
        [Parameter(Mandatory = $false, Position = 19)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 20)]
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
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $Name
            Code                  =   $null
            Type                  =   $null
            Note                  =   $null
            ListGuid              =   $Guid
            ListName              =   $Name
            FieldType             =   $ListType
            Raw                   =   $null
        }
        
        # Process Identity Object
        if (($Guid -as [System.Guid])) {
            Write-Verbose "Variable: GUID Processed as System.Guid"
            $ExistingList = Get-LrList -Name $Guid
            if (!$ExistingList) {
                $ErrorObject.Error = $True
                $ErrorObject.Code = 404
                $ErrorObject.Type = "List not found."
                $ErrorObject.Note = "List not found."
                return $ErrorObject
            } elseif ($ExistingList.Error -eq $True) {
                Return $ExistingList
            }
        } else {
            Write-Verbose "Variable: GUID Processed as String"
            $ExistingList = Get-LRLists -Name $Guid.ToString() -Exact
            if (!$ExistingList) {
                $ErrorObject.Error = $True
                $ErrorObject.Code = 404
                $ErrorObject.Type = "List not found."
                $ErrorObject.Note = "List not found."
                return $ErrorObject
            } elseif ($ExistingList.Error -eq $True) {
                Return $ExistingList
            }
            
            $Guid = $ExistingList.Guid
        }

        if ($ListType) {
            # Validate List Type
            $ListTypes = @("Application", "Classification", "CommonEvent", "Host", "Location", "MsgSource", "MsgSourceType", "MPERule", "Network", "User", "GeneralValue", "Entity", "RootEntity", "IP", "IPRange", "Identity")
            if ($ListTypes -contains $ListType) {
                ForEach ($Type in $ListTypes) {
                    if ($ListType -like $Type) {
                        # Set ListType to stored definition
                        $_listType = $Type
                    }
                }
            }
        } else {
            $_listType = $ExistingList.listType
        }

        if ($UseContext) {
            $ValidContexts = @("None", "Address", "DomainImpacted", "Group", "HostName", "Message", "MACAddress", "Object", "Process", "Session", "Subject", "URL", "User", "VendorMsgID", "DomainOrigin", "Hash", "Policy", "VendorInfo", "Result", "ObjectType", "CVE", "UserAgent", "ParentProcessId", "ParentProcessName", "ParentProcessPath", "SerialNumber", "Reason", "Status", "ThreatId", "ThreatName", "SessionType", "Action", "ResponseCode", "ObjectName", "UserAgent", "Command")
            [string[]] $_finalContext = @()
            
            ForEach ($Context in $UseContext) {
                ForEach ($ValidContext in $ValidContexts) {
                    if ($Context -like $ValidContext) {
                        $_finalContext += $ValidContext
                    }
                }
            }
        } else {
            $_finalContext = $ExistingList.useContext
        }

        if ($ReadAccess) {
            $ReadAccessLevels = @("Private", "PublicAll", "PublicGlobalAdmin", "PublicGlobalAnalyst", "PublicRestrictedAnalyst", "PublicRestrictedAdmin")
            if ($ReadAccessLevels -contains $ReadAccess) {
                ForEach ($AccessLevel in $ReadAccessLevels) {
                    if ($ReadAccess -like $AccessLevel) {
                        # Set ReadAccess to stored definition
                        $_readAccess = $AccessLevel
                    }
                }
            }
        } else {
            $_readAccess = $ExistingList.readAccess
        }

        if ($WriteAccess) {
            $WriteAccessLevels = @("Private", "PublicAll", "PublicGlobalAdmin", "PublicGlobalAnalyst", "PublicRestrictedAnalyst", "PublicRestrictedAdmin")
            if ($WriteAccessLevels -contains $WriteAccess) {
                ForEach ($AccessLevel in $WriteAccessLevels) {
                    if ($WriteAccess -like $AccessLevel) {
                        # Set WriteAccess to stored definition
                        $_writeAccess = $AccessLevel
                    }
                }
            }
        } else {
            $_writeAccess = $ExistingList.writeAccess
        }
                
        if ($RestrictedRead) {
            $_restrictedRead = $RestrictedRead
        } else {
            $_restrictedRead = $ExistingList.restrictedRead
        }

        if ($Status) {
            $_status = $Status
        } else {
            $_status = $ExistingList.status
        }

        if ($Name) {
            $_name = $Name
        } else {
            $_name = $ExistingList.name
        }

        if ($ShortDescription) {
            $_shortDescription = $ShortDescription
        } else {
            $_shortDescription = $ExistingList.shortDescription
        }

        if ($LongDescription) {
            $_longDescription = $LongDescription
        } else {
            $_longDescription = $ExistingList.longDescription
        }

        if ($AutoImport) {
            $_autoImport = $AutoImport
        } else {
            $_autoImport = $ExistingList.autoImportOption.enabled
        }

        if ($AutoImportPatterns) {
            $_AutoImportPatterns = $AutoImportPatterns
        } else {
            $_AutoImportPatterns = $ExistingList.autoImportOption.usePatterns
        }

        if ($AutoImportReplaceExisting) {
            $_AutoImportReplaceExisting = $AutoImportReplaceExisting
        } else {
            $_AutoImportReplaceExisting = $ExistingList.autoImportOption.replaceExisting
        }

        if ($AutoImportFileName) {
            $_autoImportFileName = $AutoImportFileName
        } else {
            $_autoImportFileName = $ExistingList.importFileName
        }

        if ($EntityName) {
            $_entityName = $EntityName
        } else {
            $_entityName = $ExistingList.entityName
        }

        if ($NeedToNotify) {
            $_needToNotify = $NeedToNotify
        } else {
            $_needToNotify = $ExistingList.needToNotify
        }

        if ($null -ne $DoesExpire) {
            $_doesExpire = $DoesExpire
        } else {
            $_doesExpire = $ExistingList.doesExpire
        }

        if ($Owner) {
            $_owner = $Owner
        } else {
            $_owner = $ExistingList.owner
        }
      
        #$ExpDate = (Get-Date).AddDays(7).ToString("yyyy-MM-dd")


        # Request Body
        $BodyContents = [PSCustomObject]@{
            listType = $_listType
            status = $_Status
            name = $_Name
            guid = $Guid
            shortDescription = $_shortDescription
            longDescription = $_longDescription
            useContext = @($_finalContext)
            autoImportOption = [PSCustomObject]@{
                enabled = $_AutoImport
                usePatterns = $_AutoImportPatterns
                replaceExisting = $_AutoImportReplaceExisting
            }
            importFileName = $_AutoImportFileName
            readAccess = $_readAccess
            writeAccess = $_writeAccess
            restrictedRead = $_restrictedRead
            entityName = $_EntityName
            needToNotify = $_NeedToNotify
            doesExpire = $_DoesExpire
            owner = $_Owner
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