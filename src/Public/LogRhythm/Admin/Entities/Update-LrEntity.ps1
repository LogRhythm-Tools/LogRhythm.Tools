using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrEntity {
    <#
    .SYNOPSIS
        Update an existing Entity entry for the LogRhythm Entity structure.
    .DESCRIPTION
        Update-LrEntity returns a full LogRhythm Entity object, including details and list items if provided the passthru flag.
    .PARAMETER Id
        Integer or String for existing Entity.  If a string is provided an exact lookup will be performed to identify the Integer Id.
    .PARAMETER Name
        [System.String] Parameter for specifying a new Entity name.  
        
        Max length: 200 characters
    .PARAMETER ParentEntityName
        Parameter for specifying the existing LogRhythm Entity for the new Entity record to be set to if the record is a child entity.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Entity object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Segment Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Abbreviation
        Nullable value that is an abbreviation for the entity record.

        Max length: 20 characters
    .PARAMETER ShortDescription
        A brief description of the entity.

        Max length: 255 characters
    .PARAMETER LongDescription
        An extended description of the entity.

        Max length: 2000 characters
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        PSCustomObject representing the new LogRhythm Host and its contents.
    .EXAMPLE
        PS C:\> Update-LrEntity -id "LRT-ChildEntity-021" -Name "LRT-ChildEntity-02" -ParentEntityName "lrt-testentity" -Abbreviation "Lrt-C-02" -ShortDesc "This child entity is for API automation testing." -LongDesc "Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation." -PassThru
        ---
        id               : 4
        parentEntityName : LRT-TestEntity
        name             : LRT-ChildEntity-02
        fullName         : LRT-TestEntity/LRT-ChildEntity-02
        abbreviation     : Lrt-C-02
        recordStatusName : Active
        longDesc         : Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation.
        shortDesc        : This child entity is for API automation testing.
        dateUpdated      : 2020-11-05T00:20:30.11Z
    .EXAMPLE
        PS C:\> Update-LrEntity -id "LRT-ChildEntity-021" -Name "LRT-ChildEntity-02" -ParentEntityName "lrt-testentity" -Abbreviation "Lrt-C-02" -ShortDesc "This child entity is for API automation testing." -LongDesc "Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation." -PassThru
        ---
        Code  : 404
        Error : True
        Type  : NoRecordFound
        Note  : Unable to locate exact Entity: LRT-ChildEntity-021
        Value : LRT-ChildEntity-02
    .EXAMPLE
        PS C:\> New-LrEntity -Name "LRT-ChildEntity-01" -ParentEntityName "lrt-testentity" -Abbreviation "Lrt-C-01" -ShortDesc "This child entity is for API automation testing." -LongDesc "Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation."
        ---
        Code  : 409
        Error : True
        Type  : System.Net.WebException
        Note  : An Entity already exists with this full name
        Value : LRT-ChildEntity-01
    .EXAMPLE
        PS C:\> New-LrEntity -Name "LRT-ChildEntity-021" -ParentEntityName "lrt-testentity" -Abbreviation "Lrt-C-02" -ShortDesc "This child entity is for API automation testing." -LongDesc "Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation."
        ---

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Id,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $ParentEntityName,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Name,

        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [string] $Abbreviation,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true,  Position = 4)]
        [string] $ShortDesc,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [string] $LongDesc,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [ValidateSet('retired','active', ignorecase=$true)]
        [string] $RecordStatus = "Active",

        
        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 8)]
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
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Integer Reference
        [int32] $_int = 1
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

        # Lookup Entity By ID or Name
        if ($ParentEntityName) {
            if ([int]::TryParse($ParentEntityName, [ref]$_int)) {
                Write-Verbose "[$Me]: Entity parses as integer."
                $_parentEntity = Get-LrEntityDetails -Id $ParentEntityName
            } else {
                Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                $EntityLookup = Get-LrEntities -Name $ParentEntityName -Exact
                if ($EntityLookup.Error -eq $true) {
                    $ErrorObject.Error = $EntityLookup.Error
                    $ErrorObject.Type = $EntityLookup.Type
                    $ErrorObject.Code = $EntityLookup.Code
                    $ErrorObject.Note = $EntityLookup.Note
                    return $ErrorObject
                } else {
                    $_parentEntity = $EntityLookup
                }
            }
        }
        Write-Verbose "ParentEntity: $_parentEntity"

        # Lookup Entity
        if ($Id) {
            if ([int]::TryParse($Id, [ref]$_int)) {
                Write-Verbose "[$Me]: Entity parses as integer."
                $_entity = Get-LrEntityDetails -Id $Id
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
                    $_entity = $EntityLookup
                }
            }
        }
        Write-Verbose "Entity: $_entity"

        # Check for RecordStatus Update
        if ($RecordStatus) {
            # Update RecordStatus for 7.5 API
            if ($LrtConfig.LogRhythm.Version -match '7\.[5-9]\.\d+') {
                if ($RecordStatus -eq "new") {
                    $RecordStatus = "active"
                }
            }
            $_recordStatus = (Get-Culture).TextInfo.ToTitleCase($RecordStatus)
        } else {
            $_recordStatus = $_entity.recordStatusName
        }

        # Check for Name Update, otherwise retain the same value
        if ($Name) {
            $_name = $Name
        } else {
            $_name = $_entity.Name
        }
        
        # Check for ShortDesc Update, otherwise retain the same value
        if ($ShortDesc) {
            $_shortDesc = $ShortDesc
        } else {
            if ($_entity.shortDesc) {
                $_shortDesc = $_entity.shortDesc
            }
        }

        # Check for ShortDesc Update, otherwise retain the same value
        if ($LongDesc) {
            $_longDesc = $LongDesc
        } else {
            if ($_entity.longDesc) {
                $_longDesc = $_entity.longDesc
            }
        }

        # Check for Abbreviation Update, otherwise retain the same value
        if ($Abbreviation) {
            $_abbreviation = $Abbreviation
        } else {
            if ($_entity.abbreviation) {
                $_abbreviation = $_entity.abbreviation
            }
        }

        if ($_parentEntity) {
            $_fullName = $($_parentEntity.name)+"/"+$($_entity.name)
        } else {
            $_fullName = ""
        }
        


        #>
        $Body  = [PSCustomObject]@{
            id = $($_entity.id)
            parentEntityName = $($_parentEntity.Name)
            name =  $_name
            fullName = $_fullName
            abbreviation = $_abbreviation
            shortDesc = $_shortDesc
            longDesc = $_longDesc
            recordStatusName = $_recordStatus
        } | ConvertTo-Json -Depth 3

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/entities/"

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