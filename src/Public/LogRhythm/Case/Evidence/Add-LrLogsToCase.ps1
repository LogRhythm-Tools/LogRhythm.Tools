using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrLogsToCase {
    <#
    .SYNOPSIS
        Add logs as evidence on an existing case.
    .DESCRIPTION
        Add-LrLogsToCase will take the search result output from a successful LogRhythm search
        task and add the corresponding log results to an existing case.
    .PARAMETER Id
        The Id of the case for which logs will be added to as evidence.
    .PARAMETER IndexId
        The IndexId paramater input aligns to the output paramater from the output of cmdlet
        New-LrSearch's TaskId.  
        
        The IndexId paramater value should be the GUID assigned to the invoked search task.
    .PARAMETER Query
        Default value of '*:*' will reference all of the results from the search criteria of the 
        IndexId will be returned.  
    .PARAMETER Note
        String value as a note attribute associated with the logs added to the case.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        Type -> Parameter
    .OUTPUTS
        PSCustomObject representing the (new|modified) LogRhythm object.
    .EXAMPLE
        PS C:\> Add-LrLogsToCase -Id 1780 -IndexId D9E59CA1-F87E-43DA-9BD2-479BB8F6DFDD -Note "Test of adding logs to case." -PassThru
        ---

        dateCreated   : 2021-01-30T15:22:56.3085247Z
        dateUpdated   : 2021-01-30T15:22:56.3085247Z
        createdBy     : @{number=-100; name=LogRhythm Administrator; disabled=False}
        lastUpdatedBy : @{number=-100; name=LogRhythm Administrator; disabled=False}
        type          : log
        status        : pending
        statusMessage :
        text          : Test of adding logs to case.
        pinned        : False
        datePinned    :
        logs          : @{logCount=0; query=*:*; searchIndexId=D9E59CA1-F87E-43DA-9BD2-479BB8F6DFDD}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $IndexId,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Query = '*:*',


        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $Note,


        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 5)]
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
        $Headers.Add("Content-Type","application/json")

        # Request URI   
        $Method = $HttpMethod.Post
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

        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }

        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/evidence/log/"


        # Request Body
        $Body = [PSCustomObject]@{ 
            indexId = $IndexId
            query = $Query
            note = $Note
        } | ConvertTo-Json
        Write-Verbose "[$Me] Request Body:`n$Body"

        # REQUEST
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Error = $true
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        # Return
        if ($PassThru) {
            return $Response    
        }        
    }


    End { }
}