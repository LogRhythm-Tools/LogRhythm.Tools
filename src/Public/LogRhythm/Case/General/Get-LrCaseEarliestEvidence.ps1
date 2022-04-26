using namespace System
using namespace System.IO
using namespace System.Collections.Generic

function Get-LrCaseEarliestEvidence {
    <#
    .SYNOPSIS
        Retrieves the earliest evidence timestamp of an existing case
    .DESCRIPTION
        The Get-LrCaseEarliestEvidence cmdlet collects an existing case's earliest evidence and returns timestamp
        representing the earliest point in the cases evidence origination.

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .INPUTS
        [System.Object]   ->  Id
    .OUTPUTS
        Returns the date/time in LR Case Api format.
        YYYY-MM-DDTHH:MM:SSZ

        Returns $null if no timestamp is found.
    .EXAMPLE
        PS C:\> Get-LrCaseEarliestEvidence -Id 8700
        ---
        2019-12-19T08:58:40Z
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
	param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 0
        )]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
	)
    
    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        $ProcessedCount = 0

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
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Case                  =   $Id
            Raw                   =   $null
        }  
        
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }   

        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/metrics/"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }
        $ProcessedCount++

        
        if ($Response -and $Response.earliestEvidence) { 
            if ($null -ne $Response.earliestEvidence.customDate) 
            {
                # Custom Date is defined
                [datetime] $EarliestDate = $Response.earliestEvidence.customDate
            } elseif ($null -ne $Response.earliestEvidence.date) 
            {
                # Normal evidence date (if it hasn't been over-written)
                [datetime] $EarliestDate = $Response.earliestEvidence.date
            } elseif ($null -ne $Response.earliestEvidence.originalDate)
            {
                # Neither Custom or Normal Evidence date defined; use original
                [datetime] $EarliestDate = $Response.earliestEvidence.originalDate
            }
            return $EarliestDate
        } 


	# No date could be found
	return $null
	
    }
}