using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrEntity {
    <#
    .SYNOPSIS
        Create a new Entity entry for the LogRhythm Entity structure.
    .DESCRIPTION
        New-LrEntity returns a full LogRhythm Entity object, including details and list items if provided the passthru flag.
    .PARAMETER ParentEntityName
        Parameter for specifying the existing LogRhythm Entity for the new Entity record to be set to if the record is a child entity.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        [System.String] (Name) or [System.Int32]
        Specifies a LogRhythm Entity object by providing one of the following property values:
          + Entity Name (as System.String), e.g. "Segment Bravo"
          + Entity Id (as System.String or System.Int32), e.g. 202
    .PARAMETER Name
        [System.String] Parameter for specifying a new Entity name.  
        
        Max length: 200 characters
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
        PS C:\> New-LrEntity -Name "LRT-TestEntity" -ShortDesc "This entity is for API automation testing." -LongDesc "Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation." -PassThru
        ---
        id               : 2
        name             : LRT-TestEntity
        fullName         : LRT-TestEntity
        abbreviation     :
        recordStatusName : Active
        longDesc         : Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation.
        shortDesc        : This entity is for API automation testing.
        dateUpdated      : 2020-11-04T23:43:09.16Z
    .EXAMPLE
        PS C:\> New-LrEntity -Name "LRT-ChildEntity-01" -ParentEntityName "lrt-testentity" -Abbreviation "Lrt-C-01" -ShortDesc "This child entity is for API automation testing." -LongDesc "Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation." -PassThru
        ---
        id               : 3
        parentEntityName : LRT-TestEntity
        name             : LRT-ChildEntity-01
        fullName         : LRT-TestEntity/LRT-ChildEntity-01
        abbreviation     : Lrt-C-01
        recordStatusName : Active
        longDesc         : Objects represented under this entity should be treated as in-development and not leveraged for any type of analysis or investigation.
        shortDesc        : This child entity is for API automation testing.
        dateUpdated      : 2020-11-04T23:49:31.913Z
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
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $ParentEntityName,


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Name,

        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [string] $Abbreviation,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true,  Position = 4)]
        [string] $ShortDesc,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [string] $LongDesc,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [ValidateSet('new', 'retired','active', ignorecase=$true)]
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
                    $ErrorObject.Raw = $_
                    return $ErrorObject
                } else {
                    $_parentEntity = $EntityLookup
                }
            }
        }
        Write-Verbose "Entity: $_parentEntity"

        # Ensure proper syntax
        if ($RecordStatus) {
            # Update RecordStatus for 7.5 API
            if ($LrtConfig.LogRhythm.Version -match '7\.[0-4]\.\d+') {
                if ($RecordStatus -eq "active") {
                    $RecordStatus = "new"
                }
            }
            $_recordStatus = (Get-Culture).TextInfo.ToTitleCase($RecordStatus)
        }


        #>
        $BodyContents = [PSCustomObject]@{
            id = -1
            parentEntityName = $($_parentEntity.Name)
            name =  $Name
            abbreviation = $Abbreviation
            shortDesc = $shortDesc
            longDesc = $longDesc
            recordStatusName = $_recordStatus
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json -Depth 3

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/entities/"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }
        
        if ($PassThru) {
            return $Response
        }
    }

    End { }
}