using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Format-LrIdentityPsObject {
    <#
    .SYNOPSIS
        Format TrueIdentity object(s) to a flat hierchy PS Object.
    .DESCRIPTION
        Used to support data export/import operations for TrueIdentity records.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER TrueIdentity
        PSObject containing all appropriate data points for TrueIdentity record.
    .OUTPUTS
        PSCustomObject formatted to support Export-Csv.
    .EXAMPLE
        Get-LrIdentityById -IdentityId 10 | Format-LrIdentityPsObject
        ----
        identityID               : 10
        nameFirst                : Beth
        nameMiddle               :
        nameLast                 : Nickels
        displayIdentifier        : beth.nickels@contoso.com
        company                  : Contoso
        department               : Finance
        title                    : Financial Analyst
        manager                  : Mark Robinson
        addressCity              :
        domainName               :
        EntityId                 : 1
        rootEntityId             : 0
        EntityPath               : Primary Site
        EntityName               : Primary Site
        dateUpdated              : 2020-03-10T21:02:53.917Z
        recordStatus             : Active
        identifier1_ID           : 36
        identifier1_Type         : Login
        identifier1_Value        : 2648382
        identifier1_recordStatus : Active
        identifier1_AccountName  : Source 10
        identifier1_IAMName      : Cont0so
        identifier2_ID           : 37
        identifier2_Type         : Login
        identifier2_Value        : beth.nickels
        identifier2_recordStatus : Active
        identifier2_AccountName  : Source 10
        identifier2_IAMName      : Cont0so
        identifier3_ID           : 38
        identifier3_Type         : Login
        identifier3_Value        : beth.nickels@contoso.com
        identifier3_recordStatus : Active
        identifier3_AccountName  : Source 10
        identifier3_IAMName      : Cont0so
        identifier4_ID           : 39
        identifier4_Type         : Email
        identifier4_Value        : beth.nickels@contoso.com
        identifier4_recordStatus : Active
        identifier4_AccountName  : Source 10
        identifier4_IAMName      : Cont0so
        group1_Name              : Domain Admins
    .EXAMPLE
        #Export all Identities to CSV
        Get-LrIdentities | Format-LrIdentityPsObject | Export-Csv -Path ./TrueIdentity.csv -NoTypeInformation

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true, Position = 0)]
        [object]$TrueIdentity,

        [switch]$ActiveOnly,

        [switch]$RetiredOnly
    )

    Begin {
        # Count Maximum number of Identifiers
        [int]$IdentifierMax = 0
        # Count Maximum number of Groups
        [int]$GroupsMax = 0
        # Count number of Entries
        [int]$Entry = 0

        $CsvValues = [PSCustomObject]@{}

        $CsvObject = @()
        
    }

    Process {
        # Set dynamic field counters
        [int]$IdentifierCount = 0
        [int]$GroupCount = 0

        # Create new CSV Entry
        $CsvEntry = [list[string]]::new()

        # Establish objects for iteration
        $IdentityNotes = $TrueIdentity.psobject.Members | where-object membertype -like 'noteproperty'
        $Identifiers = $TrueIdentity.identifiers
        $Groups = $TrueIdentity.groups
        ForEach ($IdNote in $IdentityNotes) {
            if ($IdNote.Name -eq "entity") {
                $CsvEntry.Add($IdNote.Value.entityId.ToString())
                $CsvEntry.Add($IdNote.Value.rootEntityId.ToString())
                $CsvEntry.Add($IdNote.Value.path)
                $CsvEntry.Add($IdNote.Value.name)
            } elseif ($IdNote.Name -eq "identifiers") {
                ForEach ($Identifier in $Identifiers) {
                    $IdentifierCount += 1
                    $CsvEntry.Add($Identifier.identifierID.ToString())
                    $CsvEntry.Add($Identifier.identifierType)
                    $CsvEntry.Add($Identifier.value)
                    $CsvEntry.Add($Identifier.recordStatus)
                    if ($null -eq $Identifier.source) {
                        $CsvEntry.Add("")
                        $CsvEntry.Add("")
                    } else {
                        $CsvEntry.Add($Identifier.source.AccountName)
                        $CsvEntry.Add($Identifier.source.IAMName)
                    }
                }
                $CsvEntry.Add("mark1,$IdentifierCount")
                if ($IdentifierCount -ge $IdentifierMax) { $IdentifierMax = $IdentifierCount}
            } elseif ($IdNote.Name -eq "groups") {
                ForEach ($Group in $Groups) {
                    $GroupCount += 1
                    $CsvEntry.Add($Group.name)
                }
                $CsvEntry.Add("mark2,$GroupCount")
                if ($GroupCount -ge $GroupMax) { $GroupMax = $GroupCount}
            } else {
                $CsvEntry.Add($IdNote.Value.ToString())
            }
        }
        $CsvValues | Add-Member -MemberType NoteProperty -Name $Entry -Value $CsvEntry
        #Write-Host $CsvEntry
        $Entry = $Entry+1
    }

    End {
        # Build CSV Header
        $CsvHeader = @("identityID","nameFirst","nameMiddle","nameLast","displayIdentifier","company","department","title","manager",`
        "addressCity","domainName","EntityId","rootEntityId","EntityPath","EntityName","dateUpdated","recordStatus")
        for ($i = 1; $i -le $IdentifierMax; $i++) {
            $CsvHeader += "identifier"+$i+"_ID"
            $CsvHeader += "identifier"+$i+"_Type"
            $CsvHeader += "identifier"+$i+"_Value"
            $CsvHeader += "identifier"+$i+"_recordStatus"
            $CsvHeader += "identifier"+$i+"_AccountName"
            $CsvHeader += "identifier"+$i+"_IAMName"
        }
        for ($i = 1; $i -le $GroupMax; $i++) {
            $CsvHeader += "group"+$i+"_Name"
        }
        # thumbnailPhoto not currently supported
        $CsvHeader += "thumbnailPhoto"


        # 17 is the starting position for identifiers  22 is the end of identifier 1
        # 17 -22  - 6 values
        # 23 - 28 - 6 values
        # 17 + # of identifiers * 6
        # Lookup actual number of entries
        $CsvEntries =  $CsvValues.psobject.Members | where-object membertype -like 'noteproperty' | measure-object | Select-Object -ExpandProperty Count
        
        # Set regex record stop patterns
        [regex]$IdentifierPattern = '^(mark1,(\d*))$'
        [regex]$GroupPattern = '^(mark2,(\d*))$'

        # Build PSObject of Identities
        For ($x = 0; $x -lt $CsvEntries; $x++) {
            # Pull Values for Entry
            $Values = $($CsvValues.$x)
            # Reset Line Entry
            $Line = new-object PSObject
            # Reset Column position for New Entry
            $ColumnPosition = 0

            # For each Value, add in an Entry to Line
            ForEach ($Value in $Values) {
                # If the Value is the marker for End of Identifiers
                if ($Value -match $IdentifierPattern) {
                    $ReplaceStr = [regex]::match($Value, $IdentifierPattern).Groups[1].Value
                    $IdentifierCount = [regex]::match($Value, $IdentifierPattern).Groups[2].Value
                    $FieldAdd = ($IdentifierMax - $IdentifierCount) * 6
                    # Create empty identifier entries
                    For ($i = 0; $i -lt $FieldAdd; $i++) {
                        $Value = $null
                        $Line | add-member -membertype NoteProperty -name $CsvHeader[$ColumnPosition] -value $Value
                        Write-Verbose "Header: $($CsvHeader[$ColumnPosition]) Value: $Value"
                        $ColumnPosition = $ColumnPosition + 1
                    }
                # If the Value is the marker for End of Groups
                } elseif ($Value -match $GroupPattern) {
                    $ReplaceStr2 = [regex]::match($Value, $GroupPattern).Groups[1].Value
                    $GroupCount = [regex]::match($Value, $GroupPattern).Groups[2].Value
                    $FieldAdd2 = ($GroupMax - $GroupCount)
                    # Create empty identifier entries
                    For ($i = 0; $i -lt $FieldAdd2; $i++) {
                        $Line | add-member -membertype NoteProperty -name $CsvHeader[$ColumnPosition] -value $Value
                        Write-Verbose "Header: $($CsvHeader[$ColumnPosition]) Value: $Value"
                        $ColumnPosition = $ColumnPosition + 1
                    }
                # Add Value to the Line
                } else {
                    $Line | add-member -membertype NoteProperty -name $CsvHeader[$ColumnPosition] -value $Value
                    Write-Verbose "Header: $($CsvHeader[$ColumnPosition]) Value: $Value"
                    $ColumnPosition = $ColumnPosition + 1
                }

            }
            # Add line to PSObject
            $CsvObject += $Line
        }
        # Return PSObject
        return $CsvObject
    }
}