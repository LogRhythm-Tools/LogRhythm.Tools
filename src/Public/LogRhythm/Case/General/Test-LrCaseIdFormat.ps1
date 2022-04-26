using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrCaseIdFormat {
    <#
    .SYNOPSIS
        Displays formatting information for a given LogRhythm Case ID.
    .DESCRIPTION
        The Test-CaseId cmdlet displays information about a given LogRhythm Unique 
        Case Identifier.
        LogRhythm Case IDs can be represented as an RFC 4122 formatted string (Guid), 
        or by an integer (as seen in the LogRhythm Web Console).
    .PARAMETER Id
        The LogRhythm Case Id to be tested.
    .INPUTS
        [System.Object] -> Id
    .OUTPUTS
        System.Object containing properties about the case to be tested, including
        an object representing the case itself, if one was found.
    .EXAMPLE
        C:\PS> Test-CaseIdFormat "5831f290-4798-4148-8165-01317d49afea"
        IsGuid IsValid Value
        ------ ------- -----
         False    True 181
    .EXAMPLE
        C:\PS> Test-LrCaseIdFormat -Id "mock case"

        LookupType : CaseName
        IsValid    : False
        Value      : mock case
        CaseNumber :
        CaseName   :
        CaseGuid   :
        Note       : Case Name value references more than one case.
        Case       : [System.Object]
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Id
    )

    begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # https://docs.microsoft.com/en-us/dotnet/api/system.int32.tryparse
        $_int = 0

        # Collection of all the properties of an LR Case object.
        $CaseProperties = @(
            "id",
            "number",
            "externalId",
            "dateCreated",
            "dateUpdated",
            "dateClosed",
            "owner",
            "lastUpdatedBy",
            "name",
            "status",
            "priority",
            "dueDate",
            "resolution",
            "resolutionDateUpdated",
            "resolutionLastUpdatedBy",
            "summary",
            "entity",
            "collaborators",
            "tags"
        )
    }

    process {
        $OutObject = [PSCustomObject]@{
            LookupType  =   $null
            IsValid     =   $false
            Value       =   $Id
            CaseNumber  =   $null
            CaseName    =   $null
            CaseGuid    =   $null
            Note        =   $null
            Case        =   $null
        }

        
        # We may have received a full case object. Validate it has all the proper properties
        # to be considered a valid case, and we can then avoid having to hit the API with
        # Get-LrCaseById, and pass back the case itself in $OutObject.
        $IdProperties = $Id.PSObject.Properties.Name
        if (! ($CaseProperties | Where-Object { $IdProperties -notcontains $_ })) {
            Write-Verbose "[Test-LrCaseIdFormat]: Received valid case object."
            $_case = $Id
            $OutObject.LookupType = "CaseObject"
            $OutObject.IsValid = $true
            $OutObject.Value = $_case.Id
            $OutObject.CaseNumber = $_case.Number
            $OutObject.CaseName = $_case.Name
            $OutObject.CaseGuid = $_case.Id
            $OutObject.Note = "Test-LrCaseIdFormat received a valid case."
            $OutObject.Case = $_case
            
            # We can return this now, we have everything needed to validate this case.
            return $OutObject
        }


        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $OutObject.Value = $Id.ToString()
            $OutObject.LookupType = "CaseNumber"

            # Lookup case by Number
            try {
                $Case = Get-LrCaseById -Id $Id
                $OutObject.Note = "Case lookup performed by Case Number."
            } catch {
                $OutObject.IsValid = $false
                $OutObject.Note = "Unable to retrieve results for Case Number lookup.  Number: $Id"
            }

            # Check result from Get-LrCaseById for presence of error object
            if ($Case.error -eq $true) {
                $OutObject.IsValid = $false
                $OutObject.Note = $Case.Note
            } else {
                # Set output object results
                $OutObject.IsValid = $true
                $OutObject.CaseNumber = $Case.number
                $OutObject.CaseGuid = $Case.id 
                $OutObject.CaseName = $Case.name
                $OutObject.Case = $Case
            }

            # Check if ID value is a Guid
        } elseif (($Id -Is [System.Guid]) -Or (Test-Guid $Id)) {
            $OutObject.Value = $Id.ToString()
            $OutObject.LookupType = "CaseGuid"
            # Lookup case by GUID
            try {
                $Case = Get-LrCaseById -Id $Id
                $OutObject.Note = "Case lookup performed by Case GUID."
            } catch {
                $OutObject.IsValid = $false
                $OutObject.Note = "Unable to retrieve results for Case GUID lookup.  ID: $Id"
            }
            # Check result from Get-LrCaseById for presence of error object
            if ($Case.error -eq $true) {
                $OutObject.IsValid = $false
                $OutObject.Note = $Case.Note
            } else {
                # Set output object results
                $OutObject.IsValid = $true
                $OutObject.CaseNumber = $Case.number
                $OutObject.CaseGuid = $Case.id 
                $OutObject.CaseName = $Case.name
                $OutObject.Case = $Case
            }
            
            # Check if ID value represents a unique case name
        } else {
            # Lookup case by Name
            $OutObject.LookupType = "CaseName"
            try {
                $Case = Get-LrCases -Name $Id -Exact
            } catch {
                $OutObject.IsValid = $false
                $OutObject.Note = "Unable to retrieve results for Case Name lookup.  Name: $Id"
            }

            # Determine if results represent a unique case
            if ($null -ne $Case.number) {
                if ($Case.count -lt 2) {
                    $OutObject.IsValid = $true
                    $OutObject.CaseNumber = $Case.number
                    $OutObject.CaseGuid = $Case.id 
                    $OutObject.CaseName = $Case.name
                    $OutObject.Case = $Case
                    $OutObject.Note = "Case lookup performed by unique case name value."
                } else {
                    $OutObject.IsValid = $false
                    $OutObject.Note = "Case Name value references more than one case."
                }
            }
        }


        return $OutObject
    }

    end {

    }
}