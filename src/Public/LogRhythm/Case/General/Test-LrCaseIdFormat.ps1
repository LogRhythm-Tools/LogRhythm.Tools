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
        System.Object with IsGuid, IsValid, Value
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
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Id
    )

    begin {
        $_int = 0
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
        }


        #region: Integer Lookup                                                                    
        if ([int]::TryParse($Id, [ref]$_int)) {
            $OutObject.LookupType = "CaseNumber"

            # Lookup case by Number
            try {
                $Case = Get-LrCaseById -Id $Id
            } catch {
                $OutObject.Note = $PSItem.Exception.Message
            }

            # Case Found if Id exists
            if ($Case.Id) {
                $OutObject.IsValid = $true
                $OutObject.CaseNumber = $Case.Number
                $OutObject.CaseGuid = $Case.Id
                $OutObject.CaseName = $Case.Name
            } else {
                # If no case, add the ErrorObject Note
                $OutObject.Note = $Case.Note
            }

            # Return Case - we know this isn't a GUID or Name
            return $OutObject
        }
        #endregion



        #region: GUID Lookup                                                                       
        if (($Id -Is [System.Guid]) -Or (Test-Guid $Id)) {
            $OutObject.LookupType = "CaseGuid"

            # Lookup case by GUID
            try {
                $Case = Get-LrCaseById -Id $Id
            } catch {
                $OutObject.Note = $PSItem.Exception.Message
            }

            # Case Found:
            if ($Case.Id) {
                $OutObject.IsValid = $true
                $OutObject.CaseNumber = $Case.number
                $OutObject.CaseGuid = $Case.id 
                $OutObject.CaseName = $Case.name
            } else {
                # If no case, add the ErrorObject Note
                $OutObject.Note = $Case.Note
            }

            # Return Case - we know this isn't a GUID or Name
            return $OutObject
        }
        #endregion



        #region: Name Lookup                                                                       
        $OutObject.LookupType = "CaseName"
        try {
            $Case = Get-LrCases -Name $Id -Exact
        } catch {
            $OutObject.Note = $PSItem.Exception.Message
        }

        # Validate only a single case is returned!
        # Note: a non-existant object always has a .count value of 0
        if ($Case.Count -eq 0) {
            $OutObject.Note = "Case lookup by Name returned no results."
            return $OutObject
        }
        if ($Case.Count -gt 1) {
            $OutObject.Note = "Case lookup by Name returned more than one result."
            return $OutObject
        }

        if ($Case.Id) {
            $OutObject.IsValid = $true
            $OutObject.CaseNumber = $Case.Number
            $OutObject.CaseGuid = $Case.Id
            $OutObject.CaseName = $Case.Name
        }

        return $OutObject
        #endregion
    }

    end { }
}